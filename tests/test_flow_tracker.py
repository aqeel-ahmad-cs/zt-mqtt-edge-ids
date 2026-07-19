import sys
import os
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.monitor.flow_tracker import FlowTracker
from src.monitor.packet_parser import ParsedMQTTPacket


def make_publish_packet(topic="telemetry/dev-01", payload_length=20, keep_alive=None):
    packet = ParsedMQTTPacket()
    packet.packet_type = 3
    packet.packet_type_name = "PUBLISH"
    packet.topic = topic
    packet.payload_length = payload_length
    packet.keep_alive = keep_alive
    packet.qos = 0
    return packet


class TestFlowTrackerWindowing:
    def test_returns_none_before_window_fills(self):
        tracker = FlowTracker(window_size=5)
        result = None
        for _ in range(3):
            result = tracker.ingest("10.0.0.5", "dev-01", make_publish_packet())
        assert result is None

    def test_returns_features_once_window_full(self):
        tracker = FlowTracker(window_size=5)
        result = None
        for _ in range(5):
            result = tracker.ingest("10.0.0.5", "dev-01", make_publish_packet())
        assert result is not None
        assert result["client_id"] == "dev-01"
        assert result["source_ip"] == "10.0.0.5"
        assert result["packets_in_window"] == 5

    def test_window_resets_after_extraction(self):
        tracker = FlowTracker(window_size=3)
        for _ in range(3):
            tracker.ingest("10.0.0.5", "dev-01", make_publish_packet())

        # the deque is bounded, not cleared - next full window comes after
        # 3 more packets since maxlen just keeps rolling
        second_result = None
        for _ in range(3):
            second_result = tracker.ingest("10.0.0.5", "dev-01", make_publish_packet())
        assert second_result is not None


class TestFlowIsolationBetweenClients:
    def test_devices_do_not_share_windows(self):
        tracker = FlowTracker(window_size=5)
        for _ in range(4):
            tracker.ingest("10.0.0.5", "dev-a", make_publish_packet())

        result_b = tracker.ingest("10.0.0.6", "dev-b", make_publish_packet())
        assert result_b is None  # dev-b's own window only has 1 packet so far

    def test_same_ip_different_client_ids_tracked_separately(self):
        # relevant when multiple containerized clients share a host IP,
        # which is exactly the lab docker-compose topology
        tracker = FlowTracker(window_size=3)
        for _ in range(3):
            tracker.ingest("172.28.0.20", "client-a", make_publish_packet())

        result_b = tracker.ingest("172.28.0.20", "client-b", make_publish_packet())
        assert result_b is None


class TestMalformedPacketTracking:
    def test_malformed_packets_increment_counter_without_crashing(self):
        tracker = FlowTracker(window_size=5)
        result = None
        for _ in range(5):
            result = tracker.ingest("10.0.0.7", "unknown@10.0.0.7", None, is_malformed=True)

        assert result is not None
        assert result["malformed_packet_count"] == 5


class TestCapacityLimits:
    def test_evicts_idle_flows_when_at_capacity(self):
        tracker = FlowTracker(window_size=5, max_tracked_clients=2, idle_timeout_seconds=0)
        tracker.ingest("10.0.0.1", "dev-1", make_publish_packet())
        tracker.ingest("10.0.0.2", "dev-2", make_publish_packet())

        # idle_timeout_seconds=0 means both existing flows are immediately
        # eligible for eviction, so this third client should get admitted
        time.sleep(0.01)
        tracker.ingest("10.0.0.3", "dev-3", make_publish_packet())

        assert tracker.active_flow_count() <= 2
