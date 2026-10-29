"""
Runs ALL THREE detectors (structure, stats, behavioral) against your
real lab captures -- one pcap per attack type, as recommended, plus a
clean normal-only pcap.

Each attack pcap can be either:
  - "mixed" (client was running during the attack) -- auto-splits
    normal vs attack traffic by connection (see pcap_loader's
    load_mixed_pcap for how/why this works)
  - "pure" (client was NOT running -- only attacker.py's traffic) --
    every message in the file is labeled as that attack

Usage:
    python3 run_demo_real_multi.py normal_traffic.pcapng \\
        illegal_func.pcapng \\
        bad_length.pcapng \\
        out_of_range.pcapng \\
        replay.pcapng \\
        read_flood.pcapng \\
        write_no_read.pcapng \\
        value_jump.pcapng

Each attack filename (without extension) becomes its label, e.g.
illegal_func.pcapng -> "attack:illegal_func". Rename your files to
match the attack if you used different names.
"""

import sys
import os

from pcap_loader import load_pcap, load_mixed_pcap
from profile import build_struct_profile, build_stats_profile
from detector_struct import struct_detect
from detector_stats import windows_from_messages, stats_detect
from detector_behavioral import build_behavioral_profile, behavioral_detect
from evaluate import (
    evaluate_struct, evaluate_windows_counts, print_report,
    merge_per_type, merge_counts,
)

WINDOW_SEC = 5.0
MODBUS_PORT = 502


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    normal_path = sys.argv[1]
    attack_paths = sys.argv[2:]

    all_normal = load_pcap(normal_path, modbus_port=MODBUS_PORT, label="normal")
    if not all_normal:
        print(f"No Modbus request messages found in {normal_path}. "
              f"Check MODBUS_PORT matches what you captured on.")
        sys.exit(1)

    attack_files = []   # list of (path, msgs) -- kept separate per file for windowing
    attack_msgs = []    # flattened -- safe to use for per-message detectors (struct, behavioral)
    for path in attack_paths:
        label = "attack:" + os.path.splitext(os.path.basename(path))[0]
        msgs = load_mixed_pcap(path, attack_label=label, modbus_port=MODBUS_PORT)
        n_attack = sum(1 for m in msgs if m["label"] == label)
        print(f"{path}: {len(msgs)} messages, {n_attack} labeled {label}, "
              f"{len(msgs) - n_attack} labeled normal")
        attack_files.append((path, msgs))
        attack_msgs.extend(msgs)

    # held-out split: train on the FIRST 70% of the capture by TIME,
    # test false positives on the trailing 30% -- both pieces stay
    # internally continuous this way. A random per-message shuffle
    # (tried first, see git history / earlier version) scatters the
    # held-out messages apart in time, which makes the stats
    # detector's rate/gap features look artificially sparse in the
    # test set and causes false positives that have nothing to do
    # with real detector quality.
    all_normal_sorted = sorted(all_normal, key=lambda m: m["ts"])
    split = int(len(all_normal_sorted) * 0.7)
    train_normal = all_normal_sorted[:split]
    test_normal = all_normal_sorted[split:]

    print(f"\nTraining on {len(train_normal)} normal messages, "
          f"testing false positives on {len(test_normal)} held-out normal messages, "
          f"evaluating detection on {len(attack_msgs)} messages from attack captures.\n")

    struct_profile = build_struct_profile(train_normal)
    stats_profile = build_stats_profile(train_normal, WINDOW_SEC)
    behavioral_profile = build_behavioral_profile(train_normal)
    print("Structure profile:", struct_profile)
    print("Behavioral profile:", behavioral_profile)

    # --- structure detector ---
    all_struct_msgs = test_normal + attack_msgs
    struct_alerts = [
        struct_detect(m["raw"], struct_profile) is not None
        for m in all_struct_msgs
    ]
    per_type, fpr = evaluate_struct(all_struct_msgs, struct_alerts)
    print_report("Structure-based detector", per_type, fpr)

    # --- stats detector ---
    # Windowed per FILE, not across the whole combined timeline: your
    # normal capture and each attack capture happen at very different
    # real wall-clock times, so merging them into one timeline first
    # creates a huge dead gap that windows_from_messages would slice
    # into thousands of empty windows -- each one looking like a rate
    # anomaly and wrecking the false positive rate. Windowing each
    # file on its own local timeline avoids that, and merge_per_type/
    # merge_counts combine the per-file results afterward.
    per_type_pieces = []
    fp_tn_pieces = []

    test_normal_windows = windows_from_messages(test_normal, WINDOW_SEC)
    test_normal_alerts = [stats_detect(w, stats_profile) for w in test_normal_windows]
    pt, fp, tn = evaluate_windows_counts(test_normal_windows, test_normal_alerts)
    per_type_pieces.append(pt)
    fp_tn_pieces.append((fp, tn))

    for path, msgs in attack_files:
        file_windows = windows_from_messages(sorted(msgs, key=lambda m: m["ts"]), WINDOW_SEC)
        file_alerts = [stats_detect(w, stats_profile) for w in file_windows]
        pt, fp, tn = evaluate_windows_counts(file_windows, file_alerts)
        per_type_pieces.append(pt)
        fp_tn_pieces.append((fp, tn))

    per_type = merge_per_type(per_type_pieces)
    fpr = merge_counts(fp_tn_pieces)
    print_report("Statistics-only baseline", per_type, fpr)

    # --- behavioral detector (needs the full chronological stream) ---
    all_behavioral_msgs = sorted(test_normal + attack_msgs, key=lambda m: m["ts"])
    reasons = behavioral_detect(all_behavioral_msgs, behavioral_profile)
    behavioral_alerts = [r is not None for r in reasons]
    per_type, fpr = evaluate_struct(all_behavioral_msgs, behavioral_alerts)
    print_report("Behavioral detector", per_type, fpr)


if __name__ == "__main__":
    main()