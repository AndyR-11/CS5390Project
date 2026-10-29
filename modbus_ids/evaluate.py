"""
Scores detector output against ground-truth labels. Works per-message
for the structure detector, per-window for the stats detector.
"""

from collections import defaultdict


def evaluate_struct_counts(messages, alerts):
    """Same as evaluate_struct, but returns raw (per_type, fp, tn)
    counts -- use when merging results across several files/pieces."""
    per_type = defaultdict(lambda: {"tp": 0, "fn": 0})
    fp = tn = 0

    for m, alert in zip(messages, alerts):
        if m["label"] == "normal":
            if alert:
                fp += 1
            else:
                tn += 1
        else:
            attack_type = m["label"].split(":", 1)[1]
            if alert:
                per_type[attack_type]["tp"] += 1
            else:
                per_type[attack_type]["fn"] += 1

    return per_type, fp, tn


def evaluate_struct(messages, alerts):
    """
    messages: list of dicts with 'label' ("normal" or "attack:<type>")
    alerts:   list of same length, True/False per message

    Per-message, not windowed, so (unlike evaluate_windows) it's safe
    to combine messages from different capture files/times here.
    """
    per_type, fp, tn = evaluate_struct_counts(messages, alerts)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return per_type, fpr


def evaluate_windows_counts(windows, alerts):
    """
    Same logic as evaluate_windows, but returns raw (per_type, fp, tn)
    counts instead of a collapsed false-positive rate -- use this when
    you need to combine results from several separately-windowed
    pieces (see merge_per_type/merge_counts below) before computing a
    single overall fpr. evaluate_windows() is a thin wrapper around
    this for the common single-piece case.
    """
    per_type = defaultdict(lambda: {"tp": 0, "fn": 0})
    fp = tn = 0

    for window, alert in zip(windows, alerts):
        labels = [m["label"] for m in window]
        attack_labels = [l for l in labels if l != "normal"]

        if not attack_labels:
            if alert:
                fp += 1
            else:
                tn += 1
        else:
            # count the window once per distinct attack type present
            for t in set(l.split(":", 1)[1] for l in attack_labels):
                if alert:
                    per_type[t]["tp"] += 1
                else:
                    per_type[t]["fn"] += 1

    return per_type, fp, tn


def evaluate_windows(windows, alerts):
    """
    windows: list of message-lists (see detector_stats.windows_from_messages)
    alerts:  True/False per window
    A window counts as "attack" if any message inside it is an attack.

    IMPORTANT: only pass windows built from messages that are close in
    time (e.g. all from one capture file). If you combine messages from
    several captures taken at very different real times (common with
    real pcaps -- your normal capture and each attack capture happen
    minutes or hours apart), the dead time between them turns into
    thousands of empty windows that look like a statistical anomaly
    and wreck your false positive rate. Window each capture file
    separately and merge with merge_per_type/merge_counts instead --
    see run_demo_real_multi.py for the pattern.
    """
    per_type, fp, tn = evaluate_windows_counts(windows, alerts)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return per_type, fpr


def merge_per_type(per_type_dicts):
    """Sums several per_type count dicts (as returned by evaluate_struct
    or evaluate_windows_counts) into one."""
    merged = defaultdict(lambda: {"tp": 0, "fn": 0})
    for per_type in per_type_dicts:
        for attack_type, counts in per_type.items():
            merged[attack_type]["tp"] += counts["tp"]
            merged[attack_type]["fn"] += counts["fn"]
    return merged


def merge_counts(fp_tn_pairs):
    """Sums several (fp, tn) pairs and returns the combined false
    positive rate."""
    total_fp = sum(fp for fp, tn in fp_tn_pairs)
    total_tn = sum(tn for fp, tn in fp_tn_pairs)
    return total_fp / (total_fp + total_tn) if (total_fp + total_tn) else 0.0


def print_report(name, per_type, fpr):
    print(f"\n--- {name} ---")
    print(f"{'attack type':<20} {'detected':<10} {'missed':<10} {'recall':<8}")
    for attack_type, counts in sorted(per_type.items()):
        tp, fn = counts["tp"], counts["fn"]
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        print(f"{attack_type:<20} {tp:<10} {fn:<10} {recall:<8.2f}")
    print(f"false positive rate (on clean traffic): {fpr:.3f}")