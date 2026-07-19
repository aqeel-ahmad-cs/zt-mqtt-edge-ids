"""
Live packet capture entry point. Attaches to a network interface using
Scapy's sniff() and hands reconstructed TCP payloads off to the MQTT
parser and flow tracker. Kept deliberately thin - this module's only job
is capture plumbing, not protocol logic or feature math.
"""

import logging
import socket
import sys
import time

import yaml
from scapy.all import IP, TCP, sniff, conf as scapy_conf
from scapy.error import Scapy_Exception

from .flow_tracker import FlowTracker
from .packet_parser import MalformedPacketError, parse_mqtt_packet

logger = logging.getLogger(__name__)

# real MQTT frames rarely exceed a few hundred bytes on this kind of
# sensor/telemetry traffic; 8 KB gives generous headroom for a single
# legitimate frame while still capping how much junk a flooding client
# can force us to hold in memory before we give up on it
MAX_SEGMENT_BUFFER_BYTES = 8192

# how long we'll hold onto a partial (unparsed) segment before assuming
# the rest of it is never coming and discarding it - prevents buffers
# from a dead/gone client lingering forever
SEGMENT_BUFFER_MAX_AGE_SECONDS = 30


class MQTTSniffer:
    def __init__(self, config_path: str = "config/network_config.yaml"):
        self.config = self._load_config(config_path)
        self.flow_tracker = FlowTracker(
            window_size=self.config["flow_tracking"]["window_size"],
            max_tracked_clients=self.config["flow_tracking"]["max_tracked_clients"],
            idle_timeout_seconds=self.config["flow_tracking"]["idle_timeout_seconds"],
        )
        # buffers partial TCP segments per (src, sport) since MQTT frames
        # can span more than one TCP segment on slow links or with large
        # publish payloads - scapy hands us segments, not reassembled streams
        self._segment_buffers = {}
        # tracks when each buffer was last touched, so we can evict ones
        # that never complete (see _evict_stale_buffers)
        self._buffer_last_touched = {}
        self._on_feature_callback = None

    def _load_config(self, config_path: str) -> dict:
        try:
            with open(config_path, "r") as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.error("config file not found at %s", config_path)
            raise
        except yaml.YAMLError as exc:
            logger.error("failed to parse config file %s: %s", config_path, exc)
            raise

    def register_feature_callback(self, callback):
        """callback(feature_dict) gets invoked whenever a flow window fills."""
        self._on_feature_callback = callback

    def _evict_stale_buffers(self):
        """
        Drop any partial-frame buffers that have been sitting around too
        long without completing. Without this, a client that starts a
        frame and never finishes it (dropped connection, deliberate
        stall) leaves its buffer allocated forever.
        """
        now = time.time()
        stale_keys = [
            key for key, last_touched in self._buffer_last_touched.items()
            if (now - last_touched) > SEGMENT_BUFFER_MAX_AGE_SECONDS
        ]
        for key in stale_keys:
            self._segment_buffers.pop(key, None)
            self._buffer_last_touched.pop(key, None)

        if stale_keys:
            logger.debug("evicted %d stale reassembly buffer(s)", len(stale_keys))

    def _handle_packet(self, packet):
        if IP not in packet or TCP not in packet:
            return

        if not packet.haslayer(TCP) or len(bytes(packet[TCP].payload)) == 0:
            return

        source_ip = packet[IP].src
        source_port = packet[TCP].sport
        buffer_key = (source_ip, source_port)

        # periodic housekeeping - cheap to call every packet since it's
        # just a dict scan over however many partial buffers exist right now
        self._evict_stale_buffers()

        raw_bytes = bytes(packet[TCP].payload)
        # simple reassembly: append to any pending buffer for this flow,
        # since a single scapy-captured segment might be a partial MQTT frame
        combined = self._segment_buffers.pop(buffer_key, b"") + raw_bytes
        self._buffer_last_touched.pop(buffer_key, None)

        if len(combined) > MAX_SEGMENT_BUFFER_BYTES:
            # a legitimate MQTT frame from these device profiles never
            # gets close to this size, so if we're still accumulating
            # past it, either the parser is stuck on garbage or a client
            # is deliberately flooding us with fragments - either way,
            # holding onto it further just risks OOM, so we bail out
            logger.warning(
                "reassembly buffer for %s:%d exceeded %d bytes, dropping as malformed",
                source_ip, source_port, MAX_SEGMENT_BUFFER_BYTES,
            )
            client_id = f"unknown@{source_ip}"
            features = self.flow_tracker.ingest(source_ip, client_id, None, is_malformed=True)
            if features and self._on_feature_callback:
                self._on_feature_callback(features)
            return

        try:
            parsed = parse_mqtt_packet(combined)
        except MalformedPacketError as exc:
            # could genuinely be a malformed/malicious frame, or just a
            # segment boundary we haven't fully reassembled yet - since we
            # can't tell which, we keep the partial data around (bounded by
            # the size/age limits above) in case the rest arrives next packet,
            # and also record this as a malformed observation for the flow
            logger.debug("malformed MQTT frame from %s:%d - %s", source_ip, source_port, exc)
            self._segment_buffers[buffer_key] = combined
            self._buffer_last_touched[buffer_key] = time.time()

            client_id = f"unknown@{source_ip}"
            features = self.flow_tracker.ingest(source_ip, client_id, None, is_malformed=True)
            if features and self._on_feature_callback:
                self._on_feature_callback(features)
            return
        except Exception as exc:  # noqa: BLE001 - last-resort guard around 3rd party parse logic
            logger.warning("unexpected error parsing packet from %s:%d: %s", source_ip, source_port, exc)
            return

        client_id = parsed.client_id or f"anon@{source_ip}"

        try:
            features = self.flow_tracker.ingest(source_ip, client_id, parsed)
        except Exception as exc:  # noqa: BLE001
            logger.error("flow tracker failed to ingest packet: %s", exc)
            return

        if features and self._on_feature_callback:
            try:
                self._on_feature_callback(features)
            except Exception as exc:  # noqa: BLE001
                logger.error("feature callback raised an exception: %s", exc)

    def start(self):
        capture_cfg = self.config["capture"]
        interface = capture_cfg["interface"]
        bpf_filter = capture_cfg["bpf_filter"]

        logger.info(
            "starting capture on interface=%s filter='%s' promisc=%s",
            interface, bpf_filter, capture_cfg["promiscuous"],
        )

        try:
            scapy_conf.iface = interface
        except (OSError, ValueError) as exc:
            logger.error("could not bind to interface %s: %s", interface, exc)
            sys.exit(1)

        try:
            # timeout=None used to mean sniff() could block forever if no
            # matching traffic showed up - that leaves no way to notice a
            # dead/hung capture from the outside. a periodic timeout makes
            # sniff() return every 60s so the loop below can re-enter it;
            # scapy doesn't expose a "still alive" signal any other way
            while True:
                sniff(
                    iface=interface,
                    filter=bpf_filter,
                    prn=self._handle_packet,
                    store=False,
                    promisc=capture_cfg["promiscuous"],
                    timeout=60,
                )
        except PermissionError:
            logger.error(
                "permission denied opening raw socket on %s - "
                "this process needs root or CAP_NET_RAW", interface,
            )
            sys.exit(1)
        except Scapy_Exception as exc:
            logger.error("scapy capture failure on %s: %s", interface, exc)
            sys.exit(1)
        except socket.error as exc:
            logger.error("socket error during capture: %s", exc)
            sys.exit(1)
        except KeyboardInterrupt:
            logger.info("capture stopped by user")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    sniffer = MQTTSniffer()
    sniffer.register_feature_callback(lambda f: logger.info("flow window ready: %s", f))
    sniffer.start()
