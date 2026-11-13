from asyncua import ua
from asyncua.common.connection import MessageChunk
from asyncua.common.utils import Buffer
from asyncua.crypto.security_policies import SecurityPolicyNone
from asyncua.ua.ua_binary import (
    header_from_binary,
    nodeid_from_binary,
    struct_from_binary,
)


POLICY = SecurityPolicyNone()

READ_TYPE = ua.NodeId(
    ua.ObjectIds.ReadRequest_Encoding_DefaultBinary
)

WRITE_TYPE = ua.NodeId(
    ua.ObjectIds.WriteRequest_Encoding_DefaultBinary
)


def split_uatcp_frames(raw):
    """
    Split a TCP payload into OPC UA TCP frames using MessageSize.

    OPC UA TCP stores MessageSize as a 4-byte little-endian integer
    beginning at byte offset 4.
    """
    frames = []
    pos = 0

    while pos + 8 <= len(raw):
        size = int.from_bytes(raw[pos + 4:pos + 8], "little")

        if size < 8:
            break

        end = pos + size

        if end > len(raw):
            # TCP segmentation/reassembly would be needed here.
            break

        frames.append(raw[pos:end])
        pos = end

    return frames


def _node_name(nodeid):
    try:
        return nodeid.to_string()
    except Exception:
        return str(nodeid)


def _datavalue_value(datavalue):
    if datavalue is None:
        return None

    variant = getattr(datavalue, "Value", None)

    if variant is None:
        return None

    return getattr(variant, "Value", None)


def decode_request_frame(frame):
    """
    Decode one unencrypted OPC UA TCP request frame.

    Returns:
        None for non-MSG messages or unsupported services.

        For Read:
        {
            "kind": "read",
            "nodes": [...]
        }

        For Write:
        {
            "kind": "write",
            "writes": [
                {"node": "...", "value": ...}
            ]
        }
    """
    buf = Buffer(frame)
    header = header_from_binary(buf)

    if header.MessageType != ua.MessageType.SecureMessage:
        return None

    chunk = MessageChunk.from_header_and_body(
        POLICY,
        header,
        buf
    )

    body = Buffer(chunk.Body)

    service_type = nodeid_from_binary(body)

    # Every service request starts with RequestHeader.
    struct_from_binary(ua.RequestHeader, body)

    if service_type == READ_TYPE:
        params = struct_from_binary(
            ua.ReadParameters,
            body
        )

        nodes = [
            _node_name(item.NodeId)
            for item in params.NodesToRead
        ]

        return {
            "kind": "read",
            "service": "ReadRequest",
            "nodes": nodes,
        }

    if service_type == WRITE_TYPE:
        params = struct_from_binary(
            ua.WriteParameters,
            body
        )

        writes = []

        for item in params.NodesToWrite:
            writes.append({
                "node": _node_name(item.NodeId),
                "value": _datavalue_value(item.Value),
            })

        return {
            "kind": "write",
            "service": "WriteRequest",
            "writes": writes,
        }

    return None


def decode_payload(raw, ts=None):
    """
    Decode all supported OPC UA request frames contained inside
    one TCP payload.
    """
    events = []

    for frame in split_uatcp_frames(raw):
        try:
            event = decode_request_frame(frame)
        except Exception:
            # Unsupported/irrelevant OPC service for this detector.
            continue

        if event is not None:
            event["ts"] = ts
            events.append(event)

    return events


def decode_messages(messages):
    """
    Convert pcap_loader message dictionaries into
    """
    events = []

    for message in messages:
        events.extend(
            decode_payload(
                message["raw"],
                message.get("ts")
            )
        )

    return sorted(
        events,
        key=lambda e: e["ts"] if e["ts"] is not None else 0
    )
