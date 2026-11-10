"""
Runs the GENERIC (inferred-schema) struct + behavioral detectors
against the same real captures and same train/held-out split as
run_demo_real_multi.py, scored with the SAME evaluate.py functions --
so these numbers are directly comparable, attack-type by attack-type,
to the existing hand-written-schema baseline in
paola_t1/results/existing_detectors.txt.
"""

import os
import sys

from pcap_loader import load_pcap, load_mixed_pcap
from evaluate import evaluate_struct, evaluate_struct_counts, print_report, merge_per_type, merge_counts
from generic_pipeline import build_generic_profile, struct_detect_generic, behavioral_detect_generic

MODBUS_PORT = 502


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} normal.pcapng attack1.pcapng [attack2.pcapng ...]")
        sys.exit(1)

    normal_path = sys.argv[1]
    attack_paths = sys.argv[2:]

    all_normal = load_pcap(normal_path, modbus_port=MODBUS_PORT, label="normal")
    attack_files = []   # (path, msgs) kept SEPARATE per file -- see behavioral section below
    attack_msgs = []    # flattened, fine for the per-message struct detector
    for path in attack_paths:
        label = "attack:" + os.path.splitext(os.path.basename(path))[0]
        msgs = load_mixed_pcap(path, attack_label=label, modbus_port=MODBUS_PORT)
        attack_files.append((path, msgs))
        attack_msgs.extend(msgs)

    all_normal_sorted = sorted(all_normal, key=lambda m: m["ts"])
    split = int(len(all_normal_sorted) * 0.7)
    train_normal = all_normal_sorted[:split]
    test_normal = all_normal_sorted[split:]

    print(f"Training on {len(train_normal)} normal messages (same split as the hand-written baseline), "
          f"testing on {len(test_normal)} held-out normal + {len(attack_msgs)} attack messages.\n")

    profile = build_generic_profile(train_normal)
    print(f"Inferred {len(profile.schemas)} known clusters from training data "
          f"(write-like: {profile.write_like_clusters})\n")

    # --- generic structural detector ---
    all_struct_msgs = test_normal + attack_msgs
    struct_alerts = [struct_detect_generic(m["raw"], profile) is not None for m in all_struct_msgs]
    per_type, fpr = evaluate_struct(all_struct_msgs, struct_alerts)
    print_report("GENERIC structural detector (inferred schema)", per_type, fpr)

    # --- generic behavioral detector ---
    # IMPORTANT: evaluated PER FILE, not merged-then-sorted across files.
    # test_normal and each attack pcap are SEPARATE real captures with
    # unrelated wall-clock timestamps -- sorting them together risks an
    # unrelated file's message looking like it "just happened" right
    # before an attack purely by timestamp coincidence, which would
    # silently erase a real write_no_read signal. The ORIGINAL hand-
    # written evaluation (run_demo_real_multi.py) does this same merge-
    # then-sort for its behavioral detector -- this per-file version
    # avoids that risk instead of inheriting it.
    per_type_pieces = []
    fp_tn_pieces = []

    test_normal_sorted = sorted(test_normal, key=lambda m: m["ts"])
    reasons = behavioral_detect_generic(test_normal_sorted, profile)
    alerts = [r is not None for r in reasons]
    pt, fp, tn = evaluate_struct_counts(test_normal_sorted, alerts)
    per_type_pieces.append(pt)
    fp_tn_pieces.append((fp, tn))

    for path, msgs in attack_files:
        file_sorted = sorted(msgs, key=lambda m: m["ts"])
        reasons = behavioral_detect_generic(file_sorted, profile)
        alerts = [r is not None for r in reasons]
        pt, fp, tn = evaluate_struct_counts(file_sorted, alerts)
        per_type_pieces.append(pt)
        fp_tn_pieces.append((fp, tn))

    per_type = merge_per_type(per_type_pieces)
    fpr = merge_counts(fp_tn_pieces)
    print_report("GENERIC behavioral detector (inferred schema, per-file)", per_type, fpr)


if __name__ == "__main__":
    main()