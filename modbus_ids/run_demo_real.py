"""
SUPERSEDED by run_demo_real_multi.py -- use that instead if you
captured one pcap per attack type (the recommended workflow). This
script is kept only for the single-combined-attack-file case; it still
has the "attack:mixed" labeling limitation described below, which
run_demo_real_multi.py's load_mixed_pcap() solves properly.

Same pipeline as run_demo.py, but loads REAL pcaps instead of
synthetic traffic.

Usage:
    python3 run_demo_real.py normal_traffic.pcapng attack_traffic.pcapng

Assumes:
  - normal_traffic.pcapng has ONLY clean traffic (client, no attacker)
  - attack_traffic.pcapng has normal + attacker.py traffic mixed in,
    captured while you ran attacker.py --attack all

If your attack pcap mixes multiple attack types with no per-type
timestamps, every attack message gets the generic label "attack:mixed"
below -- and worse, any NORMAL client traffic also captured in that
same file gets mislabeled "attack:mixed" too, since this script has no
way to separate them. Use run_demo_real_multi.py instead, which
auto-splits normal vs. attack traffic within a mixed capture by
connection (see pcap_loader.load_mixed_pcap).

This script's statistics-baseline false positive rate is also still
unreliable: combining test_normal and attack_capture into one
timeline, when the two pcaps were captured minutes/hours apart, turns
the dead time between them into thousands of empty windows that look
like a rate anomaly. run_demo_real_multi.py fixes this by windowing
each capture file on its own local timeline. Use that script's results
for your report, not this one's stats numbers.
"""

import sys

from pcap_loader import load_pcap
from profile import build_struct_profile, build_stats_profile
from detector_struct import struct_detect
from detector_stats import windows_from_messages, stats_detect
from evaluate import evaluate_struct, evaluate_windows, print_report

WINDOW_SEC = 5.0
MODBUS_PORT = 502   # match whatever port you actually ran the lab on


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 run_demo_real.py normal_traffic.pcapng attack_traffic.pcapng")
        sys.exit(1)

    normal_path, attack_path = sys.argv[1], sys.argv[2]

    all_normal = load_pcap(normal_path, modbus_port=MODBUS_PORT, label="normal")
    attack_capture = load_pcap(attack_path, modbus_port=MODBUS_PORT, label="attack:mixed")

    if not all_normal:
        print(f"No Modbus request messages found in {normal_path}. "
              f"Check MODBUS_PORT matches what you captured on.")
        sys.exit(1)

    # split clean traffic by TIME (first 70% trains, last 30% tests),
    # not a random per-message shuffle -- shuffling scatters the
    # held-out messages apart in time, which makes the stats
    # detector's rate/gap features look artificially sparse in the
    # test set and causes false positives unrelated to real detector
    # quality.
    all_normal_sorted = sorted(all_normal, key=lambda m: m["ts"])
    split = int(len(all_normal_sorted) * 0.7)
    train_normal = all_normal_sorted[:split]
    test_normal = all_normal_sorted[split:]

    print(f"Training on {len(train_normal)} normal messages, "
          f"testing false positives on {len(test_normal)} held-out normal messages, "
          f"evaluating detection on {len(attack_capture)} messages from the attack capture.")

    struct_profile = build_struct_profile(train_normal)
    stats_profile = build_stats_profile(train_normal, WINDOW_SEC)
    print("Learned structure profile:", struct_profile)

    # --- structure detector ---
    all_struct_msgs = test_normal + attack_capture
    struct_alerts = [
        struct_detect(m["raw"], struct_profile) is not None
        for m in all_struct_msgs
    ]
    per_type, fpr = evaluate_struct(all_struct_msgs, struct_alerts)
    print_report("Structure-based detector", per_type, fpr)

    # --- stats detector ---
    all_stats_msgs = sorted(test_normal + attack_capture, key=lambda m: m["ts"])
    windows = windows_from_messages(all_stats_msgs, WINDOW_SEC)
    stats_alerts = [stats_detect(w, stats_profile) for w in windows]
    per_type, fpr = evaluate_windows(windows, stats_alerts)
    print_report("Statistics-only baseline", per_type, fpr)


if __name__ == "__main__":
    main()