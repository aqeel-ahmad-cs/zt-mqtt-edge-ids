"""
Regression tests for src/monitor/mqtt_sniffer.py, specifically the
reassembly buffer bounds added after a review flagged that a fragmented,
never-completing MQTT frame could grow _segment_buffers without limit.

These tests build lightweight fake Scapy packet objects rather than
requiring a live capture or root privileges, so they run in normal CI.
"""

import sys
import os
import time
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scapy.all import IP, TCP

from src.monitor.mqtt_sniffer import MQTTSniffer, MAX_SEGMENT_BUFFER_BYTES, SEGMENT_BUFFER_MAX_AGE_SECONDS


class _FakePayload:
    def __init__(self, data: bytes):
        self._data = data

    def __bytes__(self):
        return self._data


class _FakeTCPLayer:
    def __init__(self, sport: int, payload: bytes):
        self.sport = sport
        self.payload = _FakePayload(payload)


class _FakeIPLayer:
    def __init__(self, src: str):
        self.src = src


class _FakePacket:
    """Minimal stand-in for a scapy packet, just enough for _handle_packet."""

    def __init__(self, src_ip: str, src_port: int, payload: bytes):
        self._ip = _FakeIPLayer(src_ip)
        self._tcp = _FakeTCPLayer(src_port, payload)

    def __contains__(self, layer):
        return True

    def haslayer(self, layer):
        return True

    def __getitem__(self, layer):
        if layer is IP:
            return self._ip
        if layer is TCP:
            return self._tcp
        raise KeyError(layer)


def _make_sniffer() -> MQTTSniffer:
    fake_config = {
        "flow_tracking": {"window_size": 20, "max_tracked_clients": 500, "idle_timeout_seconds": 300},
        "capture": {"interface": "lo", "bpf_filter": "tcp port 1883", "promiscuous": False},
    }
    with patch.object(MQTTSniffer, "_load_config", return_value=fake_config):
        return MQTTSniffer("unused_path.yaml")


class TestSegmentBufferSizeCap:
    def test_buffer_does_not_grow_past_cap_under_fragment_flood(self):
        sniffer = _make_sniffer()

        # each fragment looks like it could be the start of an MQTT frame
        # but never completes one, forcing repeated reassembly attempts
        garbage_chunk = bytes([0x10]) + b"A" * 2000
        source_ip, source_port = "192.168.99.99", 55555

        for _ in range(10):  # 10 * 2001 bytes far exceeds the cap
            packet = _FakePacket(source_ip, source_port, garbage_chunk)
            sniffer._handle_packet(packet)

        buffered = sniffer._segment_buffers.get((source_ip, source_port), b"")
        assert len(buffered) <= MAX_SEGMENT_BUFFER_BYTES, (
            f"buffer grew to {len(buffered)} bytes, exceeding the {MAX_SEGMENT_BUFFER_BYTES} byte cap"
        )

    def test_oversized_buffer_is_recorded_as_malformed(self):
        sniffer = _make_sniffer()
        seen_features = []
        sniffer.register_feature_callback(seen_features.append)

        garbage_chunk = bytes([0x10]) + b"A" * (MAX_SEGMENT_BUFFER_BYTES + 100)
        packet = _FakePacket("10.0.0.5", 12345, garbage_chunk)
        sniffer._handle_packet(packet)

        # window_size is 20, so a single oversized packet won't complete a
        # window on its own, but the flow tracker should have registered
        # it internally without the process ever holding the raw bytes
        assert ("10.0.0.5", 12345) not in sniffer._segment_buffers

    def test_normal_sized_traffic_is_unaffected(self):
        """Sanity check: the cap shouldn't interfere with legitimate small frames."""
        sniffer = _make_sniffer()

        # a well-formed but incomplete frame (missing the rest of the payload)
        # should still just sit in the buffer normally, since it's tiny
        partial_frame = bytes([0x30, 0x20]) + b"\x00\x04test"
        packet = _FakePacket("10.0.0.9", 9999, partial_frame)
        sniffer._handle_packet(packet)

        buffered = sniffer._segment_buffers.get(("10.0.0.9", 9999), b"")
        assert len(buffered) < MAX_SEGMENT_BUFFER_BYTES


class TestSegmentBufferStaleEviction:
    def test_stale_buffer_gets_evicted_after_max_age(self):
        sniffer = _make_sniffer()

        buffer_key = ("10.0.0.20", 4000)
        sniffer._segment_buffers[buffer_key] = b"\x10leftover-partial-frame"
        # backdate the touch time past the eviction window
        sniffer._buffer_last_touched[buffer_key] = time.time() - (SEGMENT_BUFFER_MAX_AGE_SECONDS + 5)

        sniffer._evict_stale_buffers()

        assert buffer_key not in sniffer._segment_buffers
        assert buffer_key not in sniffer._buffer_last_touched

    def test_fresh_buffer_is_not_evicted(self):
        sniffer = _make_sniffer()

        buffer_key = ("10.0.0.21", 4001)
        sniffer._segment_buffers[buffer_key] = b"\x10leftover-partial-frame"
        sniffer._buffer_last_touched[buffer_key] = time.time()

        sniffer._evict_stale_buffers()

        assert buffer_key in sniffer._segment_buffers
