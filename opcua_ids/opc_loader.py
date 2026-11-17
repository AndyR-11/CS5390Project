"""
Loads an OPC UA capture into the same kind of message list the Modbus pipeline uses:

    {"raw": bytes, "ts": float, "label": "normal"|"attack:<type>",
     "src_port": int, "conn_id": int, "dec": <opc_decode.decode() dict>}

Unlike pcap_loader_generic.py (one TCP payload = one message), this reassembles each
client->server TCP stream and splits it on the UA-TCP size field, so two messages in one
segment, or one message split across segments, are handled. Retransmitted bytes (TCP
sequence numbers we have already consumed) are dropped so they don't become duplicate
messages. Requests only (dport == port).

Limitation: segments are consumed in capture order. Out-of-order delivery is not
re-sequenced, which is fine for loopback/veth lab captures but not for lossy links.
"""
import struct
from scapy.all import PcapReader, TCP, IP, IPv6

from opc_decode import decode

_SEQ_MASK = 0xFFFFFFFF


def _new_conn(serial, next_seq=None):
    return {"buf": bytearray(), "t0": None, "id": serial, "next_seq": next_seq}


def _seq_diff(a, b):
    """Signed distance a - b between two 32-bit TCP sequence numbers (handles wraparound)."""
    d = (a - b) & _SEQ_MASK
    return d - (1 << 32) if d >= 1 << 31 else d


def load_opc_pcap(path, server_port=4840, label="normal"):
    messages = []
    conns = {}      # sport -> {"buf", "t0" (ts of first byte in buf), "id", "next_seq"}
    serial = 0
    with PcapReader(str(path)) as packets:
        for pkt in packets:
            if TCP not in pkt or not (IP in pkt or IPv6 in pkt):
                continue
            tcp = pkt[TCP]
            if int(tcp.dport) != server_port:
                continue
            sport, ts = int(tcp.sport), float(pkt.time)
            flags = int(tcp.flags)
            if flags & 0x02 and not flags & 0x10:       # SYN: a new connection on this port
                serial += 1
                conns[sport] = _new_conn(serial, (int(tcp.seq) + 1) & _SEQ_MASK)
                continue
            payload = bytes(tcp.payload)
            if not payload:
                continue
            st = conns.get(sport)
            if st is None:                              # capture started mid-connection
                serial += 1
                st = conns[sport] = _new_conn(serial)
            seq = int(tcp.seq)
            if st["next_seq"] is not None:
                behind = -_seq_diff(seq, st["next_seq"])     # >0: these bytes were already consumed
                if behind >= len(payload):
                    continue                                 # pure retransmission
                if behind > 0:
                    payload = payload[behind:]               # partial overlap: keep only the new tail
                    seq = st["next_seq"]
            st["next_seq"] = (seq + len(payload)) & _SEQ_MASK
            if not st["buf"]:
                st["t0"] = ts
            st["buf"].extend(payload)
            while len(st["buf"]) >= 8:
                size = struct.unpack("<I", bytes(st["buf"][4:8]))[0]
                plausible = bytes(st["buf"][:3]).isalpha() and bytes(st["buf"][:3]).isupper()
                if not plausible or size < 8 or size > 1 << 20:
                    size = len(st["buf"])               # garbage: consume the rest as one bad message
                if len(st["buf"]) < size:
                    break                                # wait for more segments
                raw = bytes(st["buf"][:size])
                del st["buf"][:size]
                messages.append({"raw": raw, "ts": st["t0"], "label": label,
                                 "src_port": sport, "conn_id": st["id"],
                                 "dec": decode(raw)})
                st["t0"] = ts                            # remainder (if any) started in this packet
    messages.sort(key=lambda m: m["ts"])
    return messages
