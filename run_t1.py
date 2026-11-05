import argparse
from collections import Counter
import json
from pathlib import Path

from .clustering import MessageTypeClusterer


def load_payloads(path, port):
    from scapy.all import PcapReader, TCP, IP, IPv6
    messages = []
    with PcapReader(str(path)) as packets:
        for index, packet in enumerate(packets):
            if TCP not in packet or not (IP in packet or IPv6 in packet):
                continue
            tcp = packet[TCP]
            raw = bytes(tcp.payload)
            if int(tcp.dport) != port or not raw:
                continue
            messages.append({"raw": raw, "ts": float(packet.time), "packet_index": index})
    return sorted(messages, key=lambda m: (m["ts"], m["packet_index"]))


def summarize(assignments):
    counts = Counter(assignments)
    return {"count": len(assignments), "cluster_counts": dict(sorted(counts.items())),
            "unknown_fraction": counts[-1] / len(assignments) if assignments else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("normal_pcap", type=Path)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--test-pcap", type=Path, action="append", default=[])
    parser.add_argument("--max-entropy", type=float, default=1.5)
    parser.add_argument("--min-samples", type=int, default=8)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    messages = load_payloads(args.normal_pcap, args.port)
    split = int(len(messages) * .7)
    if split < args.min_samples or split == len(messages):
        parser.error("Not enough payloads for a chronological 70/30 split")
    model = MessageTypeClusterer(max_entropy=args.max_entropy, min_samples=args.min_samples).fit(messages[:split])
    train = model.predict(messages[:split])
    held_out = model.predict(messages[split:])
    result = {"source": str(args.normal_pcap), "port": args.port, "unit": "client-to-server TCP payload (no stream reassembly)",
              "warning": "Cluster novelty is not proof of an attack or a semantic type.",
              "model": model.describe(), "train": summarize(train),
              "held_out": summarize(held_out),
              "assignments": [{"packet_index": m["packet_index"], "cluster_id": c, "split": "train" if i < split else "held_out"}
                              for i, (m, c) in enumerate(zip(messages, train + held_out))], "additional_captures": []}
    for path in args.test_pcap:
        assignments = model.predict(load_payloads(path, args.port))
        result["additional_captures"].append({"source": str(path), **summarize(assignments)})
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("train", "held_out")}, indent=2))


if __name__ == "__main__":
    main()
