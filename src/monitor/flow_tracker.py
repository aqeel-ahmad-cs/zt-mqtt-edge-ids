"""
Tracks per-client MQTT flows and computes rolling statistical features.

A "flow" here is keyed by (source_ip, client_id) rather than the usual
5-tuple, because the same physical device can reconnect from a new source
port constantly (Mosquitto clients do this on every reconnect) and we'd
otherwise fragment one device's history into dozens of short-lived flows.
Client ID is the more stable identity signal at the application layer.
"""

import logging
import time
from collections import deque

logger = logging.getLogger(__name__)


class FlowState:
    """
    Bounded rolling window of packet-level observations for a single client.
    Deques with maxlen keep memory flat regardless of how long a client has
    been connected - important since this runs continuously on constrained
    edge hardware, not as a one-shot batch job.
    """

    def __init__(self, client_id: str, source_ip: str, window_size: int):
        self.client_id = client_id
        self.source_ip = source_ip
        self.window_size = window_size

        self.timestamps = deque(maxlen=window_size)
        self.payload_lengths = deque(maxlen=window_size)
        self.packet_types = deque(maxlen=window_size)
        self.topics_seen = set()
        self.keep_alive_values = deque(maxlen=window_size)

        self.connect_count = 0
        self.publish_count = 0
        self.subscribe_count = 0
        self.malformed_count = 0

        self.first_seen = time.time()
        self.last_seen = time.time()

    def record(self, parsed_packet, is_malformed: bool = False):
        now = time.time()
        self.timestamps.append(now)
        self.last_seen = now

        if is_malformed:
            self.malformed_count += 1
            return

        self.payload_lengths.append(parsed_packet.payload_length)
        self.packet_types.append(parsed_packet.packet_type)

        if parsed_packet.topic:
            self.topics_seen.add(parsed_packet.topic)

        if parsed_packet.keep_alive is not None:
            self.keep_alive_values.append(parsed_packet.keep_alive)

        if parsed_packet.packet_type_name == "CONNECT":
            self.connect_count += 1
        elif parsed_packet.packet_type_name == "PUBLISH":
            self.publish_count += 1
        elif parsed_packet.packet_type_name == "SUBSCRIBE":
            self.subscribe_count += 1

    def is_window_full(self) -> bool:
        return len(self.timestamps) >= self.window_size

    def is_idle(self, idle_timeout_seconds: int) -> bool:
        return (time.time() - self.last_seen) > idle_timeout_seconds


class FlowTracker:
    """
    Owns the full set of active flows and produces feature vectors once a
    given client's window fills up. Also periodically evicts idle flows so
    a fleet of thousands of devices doesn't grow the tracked-client table
    without bound - relevant since this is meant to run unattended on a
    gateway with limited RAM.
    """

    def __init__(self, window_size: int = 20, max_tracked_clients: int = 500,
                 idle_timeout_seconds: int = 300):
        self.window_size = window_size
        self.max_tracked_clients = max_tracked_clients
        self.idle_timeout_seconds = idle_timeout_seconds
        self._flows = {}

    def _flow_key(self, source_ip: str, client_id: str):
        return f"{source_ip}::{client_id}"

    def ingest(self, source_ip: str, client_id: str, parsed_packet, is_malformed: bool = False):
        """
        Records one observed packet for a client, evicting stale entries
        first if we're at capacity. Returns a feature dict if the client's
        window just filled, otherwise None.
        """
        if len(self._flows) >= self.max_tracked_clients:
            self._evict_idle_flows()

        key = self._flow_key(source_ip, client_id)

        if key not in self._flows:
            if len(self._flows) >= self.max_tracked_clients:
                logger.warning(
                    "flow table at capacity (%d clients), dropping new flow for %s",
                    self.max_tracked_clients, key,
                )
                return None
            self._flows[key] = FlowState(client_id, source_ip, self.window_size)

        flow = self._flows[key]
        flow.record(parsed_packet, is_malformed=is_malformed)

        if flow.is_window_full():
            return self._extract_features(flow)

        return None

    def _evict_idle_flows(self):
        stale_keys = [
            key for key, flow in self._flows.items()
            if flow.is_idle(self.idle_timeout_seconds)
        ]
        for key in stale_keys:
            del self._flows[key]

        if stale_keys:
            logger.debug("evicted %d idle flows", len(stale_keys))

    def _extract_features(self, flow: FlowState) -> dict:
        """
        Computes the fixed-schema feature vector consumed by the ML engine.
        Keep this schema in sync with src/engine/preprocessing.py - training
        and inference must agree on exactly what these numbers mean.
        """
        timestamps = list(flow.timestamps)
        intervals = [
            timestamps[i] - timestamps[i - 1]
            for i in range(1, len(timestamps))
        ]

        payload_lengths = list(flow.payload_lengths) or [0]
        keep_alives = list(flow.keep_alive_values) or [0]

        mean_interval = sum(intervals) / len(intervals) if intervals else 0.0
        variance = (
            sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            if intervals else 0.0
        )

        total_packets = flow.connect_count + flow.publish_count + flow.subscribe_count
        connect_ratio = flow.connect_count / total_packets if total_packets else 0.0

        features = {
            "client_id": flow.client_id,
            "source_ip": flow.source_ip,
            "mean_inter_arrival": round(mean_interval, 6),
            "inter_arrival_variance": round(variance, 6),
            "mean_payload_length": round(sum(payload_lengths) / len(payload_lengths), 2),
            "max_payload_length": max(payload_lengths),
            "payload_length_std": round(_std(payload_lengths), 2),
            "topic_cardinality": len(flow.topics_seen),
            "connect_to_publish_ratio": round(connect_ratio, 4),
            "malformed_packet_count": flow.malformed_count,
            "mean_keep_alive": round(sum(keep_alives) / len(keep_alives), 2),
            "packets_in_window": len(flow.timestamps),
        }
        return features

    def active_flow_count(self) -> int:
        return len(self._flows)


def _std(values):
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    return variance ** 0.5
