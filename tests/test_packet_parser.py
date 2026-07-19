"""
Unit tests for src/monitor/packet_parser.py using hand-built byte strings
that mimic real MQTT wire frames. Building these by hand (rather than
capturing real pcaps) keeps the test suite runnable without root or a
live broker, which matters for CI.
"""

import struct
import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.monitor.packet_parser import (
    MalformedPacketError,
    MQTT_CONNECT,
    MQTT_PUBLISH,
    MQTT_SUBSCRIBE,
    parse_mqtt_packet,
)


def build_connect_packet(client_id: str, keep_alive: int = 60) -> bytes:
    protocol_name = "MQTT"
    protocol_level = 4  # MQTT 3.1.1
    connect_flags = 0x02  # clean session

    variable_header = struct.pack(">H", len(protocol_name)) + protocol_name.encode("utf-8")
    variable_header += bytes([protocol_level, connect_flags])
    variable_header += struct.pack(">H", keep_alive)

    payload = struct.pack(">H", len(client_id)) + client_id.encode("utf-8")

    body = variable_header + payload
    remaining_length = len(body)

    fixed_header = bytes([MQTT_CONNECT << 4]) + bytes([remaining_length])
    return fixed_header + body


def build_publish_packet(topic: str, payload_data: bytes, qos: int = 0) -> bytes:
    variable_header = struct.pack(">H", len(topic)) + topic.encode("utf-8")
    if qos > 0:
        variable_header += struct.pack(">H", 1)  # packet identifier

    body = variable_header + payload_data
    remaining_length = len(body)

    first_byte = (MQTT_PUBLISH << 4) | (qos << 1)
    fixed_header = bytes([first_byte]) + bytes([remaining_length])
    return fixed_header + body


def build_subscribe_packet(topic: str) -> bytes:
    variable_header = struct.pack(">H", 1)  # packet identifier
    payload = struct.pack(">H", len(topic)) + topic.encode("utf-8") + bytes([0])  # requested QoS 0

    body = variable_header + payload
    remaining_length = len(body)

    fixed_header = bytes([MQTT_SUBSCRIBE << 4 | 0x02]) + bytes([remaining_length])
    return fixed_header + body


class TestConnectParsing:
    def test_parses_client_id_correctly(self):
        packet_bytes = build_connect_packet("sensor-temp-01", keep_alive=60)
        parsed = parse_mqtt_packet(packet_bytes)

        assert parsed.packet_type_name == "CONNECT"
        assert parsed.client_id == "sensor-temp-01"
        assert parsed.keep_alive == 60

    def test_empty_client_id_gets_placeholder(self):
        packet_bytes = build_connect_packet("", keep_alive=30)
        parsed = parse_mqtt_packet(packet_bytes)

        assert parsed.client_id == "<empty-client-id>"

    def test_truncated_connect_raises_malformed(self):
        packet_bytes = build_connect_packet("device-01")
        truncated = packet_bytes[:-5]

        with pytest.raises(MalformedPacketError):
            parse_mqtt_packet(truncated)


class TestPublishParsing:
    def test_parses_topic_and_payload_length(self):
        payload_data = b"22.5"
        packet_bytes = build_publish_packet("telemetry/temp-sensor-01", payload_data, qos=0)
        parsed = parse_mqtt_packet(packet_bytes)

        assert parsed.packet_type_name == "PUBLISH"
        assert parsed.topic == "telemetry/temp-sensor-01"
        assert parsed.payload_length == len(payload_data)

    def test_qos1_publish_accounts_for_packet_identifier(self):
        payload_data = b"hello-world"
        packet_bytes = build_publish_packet("telemetry/plug-01", payload_data, qos=1)
        parsed = parse_mqtt_packet(packet_bytes)

        assert parsed.qos == 1
        assert parsed.payload_length == len(payload_data)


class TestSubscribeParsing:
    def test_parses_topic_filter(self):
        packet_bytes = build_subscribe_packet("cmd/smart-plug-01")
        parsed = parse_mqtt_packet(packet_bytes)

        assert parsed.packet_type_name == "SUBSCRIBE"
        assert parsed.topic == "cmd/smart-plug-01"


class TestMalformedInputs:
    def test_empty_bytes_raises(self):
        with pytest.raises(MalformedPacketError):
            parse_mqtt_packet(b"")

    def test_single_byte_raises(self):
        with pytest.raises(MalformedPacketError):
            parse_mqtt_packet(b"\x10")

    def test_unrecognized_packet_type_raises(self):
        # nibble 0 (reserved, unused in MQTT 3.1.1) followed by remaining length 0
        garbage = bytes([0x00, 0x00])
        with pytest.raises(MalformedPacketError):
            parse_mqtt_packet(garbage)

    def test_remaining_length_exceeding_buffer_raises(self):
        # claims 100 bytes of remaining length but supplies none
        garbage = bytes([MQTT_CONNECT << 4, 100])
        with pytest.raises(MalformedPacketError):
            parse_mqtt_packet(garbage)

    def test_non_utf8_client_id_raises(self):
        bad_bytes = bytes([MQTT_CONNECT << 4, 20])
        bad_bytes += struct.pack(">H", 4) + b"MQTT"
        bad_bytes += bytes([4, 0x02])
        bad_bytes += struct.pack(">H", 60)
        bad_bytes += struct.pack(">H", 2) + b"\xff\xfe"  # invalid utf-8 sequence

        with pytest.raises(MalformedPacketError):
            parse_mqtt_packet(bad_bytes)
