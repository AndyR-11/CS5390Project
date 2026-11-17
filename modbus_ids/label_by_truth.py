"""
Label a multi-client capture using the ground-truth JSON written by
modbus_lab/multi_client_lab.py.

Rule: a request is ATTACK if it was sent inside the attack's time window on a
connection that is NOT one of the long-lived client connections. Everything else
(including the attacker client's own normal polling) is normal.

    python3 label_by_truth.py run1.pcap run1_truth.json
"""
import json
import sys
from collections import Counter

from pcap_loader import load_pcap


def load_labeled(pcap_path, truth_path, slack=0.25):
    truth = json.load(open(truth_path))
    atk = truth["attack"]
    client_ports = {c["local_port"] for c in truth["clients"] if c["local_port"]}
    label = "attack:" + atk["name"]
    msgs = load_pcap(pcap_path, modbus_port=truth["target_port"], label="normal")
    for m in msgs:
        in_window = atk["start_ts"] - slack <= m["ts"] <= atk["end_ts"] + slack
        if in_window and m["src_port"] not in client_ports:
            m["label"] = label
    return msgs, truth


if __name__ == "__main__":
    msgs, truth = load_labeled(sys.argv[1], sys.argv[2])
    c = Counter(m["label"] for m in msgs)
    print(f"{truth['n_clients']} clients, attacker={truth['attack']['attacker_client']}, "
          f"attack={truth['attack']['name']}")
    print("labels:", dict(c))
    per_port = Counter((m["src_port"], m["label"]) for m in msgs)
    clients = {c["local_port"]: c for c in truth["clients"]}
    for (p, l), k in sorted(per_port.items()):
        if p in clients:
            print(f"  client port {p} ({clients[p]['name']}, {clients[p]['role']}): {k} {l}")
