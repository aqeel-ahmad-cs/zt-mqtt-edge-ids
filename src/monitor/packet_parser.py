"""
Low-level MQTT 3.1.1 control packet parser.

Scapy gives us the raw TCP payload bytes; the broker itself does not expose
per-packet metadata to us since we're sniffing off the wire rather than
hooking into Mosquitto's own logging. So this module re-implements just
enough of the MQTT fixed-header spec to pull out the fields the flow
tracker actually cares about (packet type, client id, topic, payload size,
keep-alive). It intentionally does NOT attempt a full RFC-complete parse -
things like will messages, retain flags, and QoS 2 ack chains are not
needed for anomaly detection and would just add surface area for bugs.
"""

import logging
import struct

logger = logging.getLogger(__name__)

# MQTT control packet type identifiers (upper nibble of the first byte)
MQTT_CONNECT = 1
MQTT_CONNACK = 2
MQTT_PUBLISH = 3
MQTT_PUBACK = 4
MQTT_SUBSCRIBE = 8
MQTT_SUBACK = 9
MQTT_UNSUBSCRIBE = 10
MQTT_PINGREQ = 12
MQTT_PINGRESP = 13
MQTT_DISCONNECT = 14

PACKET_TYPE_NAMES = {
    MQTT_CONNECT: "CONNECT",
    MQTT_CONNACK: "CONNACK",
    MQTT_PUBLISH: "PUBLISH",
    MQTT_PUBACK: "PUBACK",
    MQTT_SUBSCRIBE: "SUBSCRIBE",
    MQTT_SUBACK: "SUBACK",
    MQTT_UNSUBSCRIBE: "UNSUBSCRIBE",
    MQTT_PINGREQ: "PINGREQ",
    MQTT_PINGRESP: "PINGRESP",
    MQTT_DISCONNECT: "DISCONNECT",
}


class MalformedPacketError(Exception):
    """Raised when a payload doesn't decode as a well-formed MQTT frame."""
    pass


class ParsedMQTTPacket:
    """Plain data holder for whatever fields we managed to extract."""

    __slots__ = (
        "packet_type", "packet_type_name", "remaining_length",
        "client_id", "topic", "payload_length", "keep_alive",
        "qos", "raw_length",
    )

    def __init__(self):
        self.packet_type = None
        self.packet_type_name = None
        self.remaining_length = 0
        self.client_id = None
        self.topic = None
        self.payload_length = 0
        self.keep_alive = None
        self.qos = 0
        self.raw_length = 0

    def __repr__(self):
        return (
            f"<ParsedMQTTPacket type={self.packet_type_name} "
            f"client_id={self.client_id} topic={self.topic} "
            f"payload_len={self.payload_length}>"
        )


def _decode_remaining_length(data: bytes, offset: int):
    """
    MQTT encodes remaining length as a variable-length integer using
    7 bits per byte with the top bit as a continuation flag. Max 4 bytes.
    Returns (value, bytes_consumed).
    """
    multiplier = 1
    value = 0
    bytes_consumed = 0

    for _ in range(4):
        if offset + bytes_consumed >= len(data):
            raise MalformedPacketError("truncated remaining-length field")

        encoded_byte = data[offset + bytes_consumed]
        bytes_consumed += 1
        value += (encoded_byte & 0x7F) * multiplier

        if (encoded_byte & 0x80) == 0:
            return value, bytes_consumed

        multiplier *= 128

    # if we get here, the continuation bit never cleared within 4 bytes -
    # that's a spec violation and a decent signal something's off
    raise MalformedPacketError("remaining-length field exceeds 4 bytes")


def _read_utf8_string(data: bytes, offset: int):
    """MQTT strings are length-prefixed with a 2-byte big-endian int."""
    if offset + 2 > len(data):
        raise MalformedPacketError("truncated string length prefix")

    (str_len,) = struct.unpack_from(">H", data, offset)
    start = offset + 2
    end = start + str_len

    if end > len(data):
        raise MalformedPacketError("string length prefix exceeds buffer")

    try:
        value = data[start:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MalformedPacketError(f"non-utf8 string field: {exc}") from exc

    return value, end


def parse_mqtt_packet(payload: bytes) -> ParsedMQTTPacket:
    """
    Attempts to decode a single MQTT control packet from raw bytes.
    Raises MalformedPacketError on anything that doesn't fit the spec -
    callers should treat that as a signal worth feeding to the flow
    tracker rather than silently dropping it, since malformed-packet
    floods are one of the attack patterns this whole project targets.
    """
    if len(payload) < 2:
        raise MalformedPacketError("payload too short to contain a fixed header")

    first_byte = payload[0]
    packet_type = (first_byte >> 4) & 0x0F
    qos = (first_byte >> 1) & 0x03

    if packet_type not in PACKET_TYPE_NAMES:
        raise MalformedPacketError(f"unrecognized packet type nibble: {packet_type}")

    try:
        remaining_length, header_bytes_used = _decode_remaining_length(payload, 1)
    except MalformedPacketError:
        raise

    body_start = 1 + header_bytes_used
    body_end = body_start + remaining_length

    if body_end > len(payload):
        raise MalformedPacketError(
            f"declared remaining_length {remaining_length} exceeds actual payload"
        )

    parsed = ParsedMQTTPacket()
    parsed.packet_type = packet_type
    parsed.packet_type_name = PACKET_TYPE_NAMES[packet_type]
    parsed.remaining_length = remaining_length
    parsed.qos = qos
    parsed.raw_length = len(payload)

    try:
        if packet_type == MQTT_CONNECT:
            _parse_connect_body(payload, body_start, body_end, parsed)
        elif packet_type == MQTT_PUBLISH:
            _parse_publish_body(payload, body_start, body_end, parsed, first_byte)
        elif packet_type == MQTT_SUBSCRIBE:
            _parse_subscribe_body(payload, body_start, body_end, parsed)
        # PINGREQ/DISCONNECT/etc have no useful variable header for us
    except MalformedPacketError:
        # re-raise with type context so upstream logs are actually useful
        raise
    except (struct.error, IndexError) as exc:
        raise MalformedPacketError(f"unexpected decode failure in {parsed.packet_type_name}: {exc}") from exc

    return parsed


def _parse_connect_body(payload, start, end, parsed):
    # protocol name (2-byte len + string), protocol level (1 byte),
    # connect flags (1 byte), keep-alive (2 bytes big-endian), then client id
    protocol_name, offset = _read_utf8_string(payload, start)

    if offset + 2 > end:
        raise MalformedPacketError("CONNECT body truncated before protocol level/flags")

    protocol_level = payload[offset]
    connect_flags = payload[offset + 1]
    offset += 2

    if offset + 2 > end:
        raise MalformedPacketError("CONNECT body truncated before keep-alive field")

    (keep_alive,) = struct.unpack_from(">H", payload, offset)
    offset += 2

    client_id, offset = _read_utf8_string(payload, offset)

    parsed.keep_alive = keep_alive
    parsed.client_id = client_id if client_id else "<empty-client-id>"


def _parse_publish_body(payload, start, end, parsed, first_byte):
    topic, offset = _read_utf8_string(payload, start)
    parsed.topic = topic

    # QoS > 0 packets carry a 2-byte packet identifier before the payload
    qos = (first_byte >> 1) & 0x03
    if qos > 0:
        offset += 2

    parsed.payload_length = max(end - offset, 0)


def _parse_subscribe_body(payload, start, end, parsed):
    # packet identifier (2 bytes), then one or more topic filter + qos pairs.
    # we only care about the first topic filter for feature purposes.
    if start + 2 > end:
        raise MalformedPacketError("SUBSCRIBE body truncated before packet id")

    offset = start + 2
    topic, offset = _read_utf8_string(payload, offset)
    parsed.topic = topic
