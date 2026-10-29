"""
Loads a real Wireshark/tcpdump .pcap or .pcapng capture into the same
message format run_demo.py expects:

    {"raw": <bytes>, "ts": <float>, "label": "normal" or "attack:<type>",
     "src_port": <int>, "trans_id": <int>}

Replaces traffic_sim.py's generate_normal()/inject_attacks() once you
have real captures. Everything downstream (profile.py, both
detectors, evaluate.py) is unchanged.

Handles two things real captures hit that synthetic traffic never did:
  1. Loopback captures (localhost) carry a 4-byte "Null/Loopback"
     header before the IP header -- scapy's rdpcap/sniff already
     strips this for you via the DLT, so this script doesn't need to
     special-case it. It's mentioned here only so you know why a raw
     read of the file wouldn't line up with what Wireshark shows.
  2. Modbus/TCP responses look almost identical to requests on the
     wire. By default this loader keeps REQUESTS ONLY (packets whose
     destination port is the Modbus port), since that's what your
     detectors are designed to check. Pass keep_responses=True if you
     want both.
"""

from scapy.all import rdpcap, TCP, IP
from scapy.layers.inet import TCP as TCPLayer


def load_pcap(path, modbus_port=502, label="normal", keep_responses=False):
    """
    Returns a list of message dicts, in the format run_demo.py expects.

    path:            .pcap or .pcapng file
    modbus_port:     the port you ran everything on (502 in your setup)
    label:           label to assign every message in this file, e.g.
                      "normal" or "attack:illegal_func". For a capture
                      that mixes normal + several attack types, use
                      label_messages_by_log() afterward instead (see
                      bottom of this file).
    keep_responses:  False (default) keeps only client->server
                      requests; True keeps both directions.
    """
    packets = rdpcap(path)
    messages = []

    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            continue

        tcp = pkt[TCP]
        payload = bytes(tcp.payload)
        if len(payload) < 8:        # shorter than a bare MBAP header -- not a Modbus message
            continue

        is_request = (tcp.dport == modbus_port)
        is_response = (tcp.sport == modbus_port)
        if not (is_request or (keep_responses and is_response)):
            continue

        trans_id = int.from_bytes(payload[0:2], "big")
        messages.append({
            "raw": payload,
            "ts": float(pkt.time),
            "label": label,
            "src_port": tcp.sport if is_request else tcp.dport,
            "trans_id": trans_id,
        })

    messages.sort(key=lambda m: m["ts"])
    return messages


def label_messages_by_log(messages, attack_windows):
    """
    Use this when one pcap mixes normal + attack traffic (e.g. you ran
    the client and attacker.py at the same time, as suggested).

    attack_windows: list of (start_ts, end_ts, label) tuples, e.g.
        [(1730000010.0, 1730000011.5, "attack:illegal_func"), ...]
    You can build these from the attacker's own printed output --
    note roughly when each attack ran, or add timestamps to
    attacker.py's print statements if you want exact boundaries.

    Mutates and returns the same list, relabeling any message whose
    timestamp falls inside a window.
    """
    for m in messages:
        for start, end, label in attack_windows:
            if start <= m["ts"] <= end:
                m["label"] = label
                break
    return messages


def load_mixed_pcap(path, attack_label, modbus_port=502, keep_responses=False):
    """
    For a capture where the client (normal traffic) was running
    WHILE attacker.py ran -- auto-splits messages into "normal" vs
    the given attack label, instead of blanket-labeling the whole
    file (which was the "attack:mixed" problem from before).

    How the split works: modbus_client.py holds ONE long-lived TCP
    connection and polls repeatedly on it, so its source port appears
    on many messages. attacker.py opens a NEW connection (and gets a
    NEW ephemeral port) for every attack it sends, so each attack
    message's source port appears only once or twice. This function
    picks the source port with the MOST messages and calls that one
    "normal" -- everything else gets attack_label.

    This works even for read_flood, which opens 50 separate
    connections: each flood connection still only sends 1 message, so
    none of them individually outnumbers the client's long-running
    connection (as long as the client was actually polling during the
    capture).

    Caveat: if you capture an attack with NO client running at all
    (attack-only capture), there's no dominant "normal" port to find,
    so this function may mislabel one of the attack's own connections
    as normal. For an attack-only capture, use load_pcap() directly
    with label=attack_label instead -- every message in the file
    really is that attack.
    """
    from collections import Counter

    messages = load_pcap(path, modbus_port=modbus_port, label="normal", keep_responses=keep_responses)
    if not messages:
        return messages

    port_counts = Counter(m["src_port"] for m in messages)
    dominant_port, _ = port_counts.most_common(1)[0]

    for m in messages:
        if m["src_port"] != dominant_port:
            m["label"] = attack_label

    return messages


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Quick sanity check: load a pcap and print counts")
    parser.add_argument("pcap")
    parser.add_argument("--port", type=int, default=502)
    parser.add_argument("--label", default="normal")
    args = parser.parse_args()

    msgs = load_pcap(args.pcap, modbus_port=args.port, label=args.label)
    print(f"Loaded {len(msgs)} Modbus request messages from {args.pcap}")
    if msgs:
        print(f"First ts: {msgs[0]['ts']}, last ts: {msgs[-1]['ts']}")
        print(f"Example message: {msgs[0]}")