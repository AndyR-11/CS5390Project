"""
Scores detector output against ground-truth labels.

This intentionally matches the Modbus evaluation format so results
from both protocols can be compared directly.
"""

from collections import defaultdict


def evaluate_struct_counts(
    messages,
    alerts
):
    per_type = defaultdict(
        lambda: {
            "tp": 0,
            "fn": 0
        }
    )

    fp = 0
    tn = 0

    for m, alert in zip(
        messages,
        alerts
    ):
        if m["label"] == "normal":

            if alert:
                fp += 1
            else:
                tn += 1

        else:
            attack_type = (
                m["label"]
                .split(":", 1)[1]
            )

            if alert:
                per_type[
                    attack_type
                ]["tp"] += 1
            else:
                per_type[
                    attack_type
                ]["fn"] += 1

    return per_type, fp, tn


def evaluate_struct(
    messages,
    alerts
):
    per_type, fp, tn = (
        evaluate_struct_counts(
            messages,
            alerts
        )
    )

    fpr = (
        fp / (fp + tn)
        if (fp + tn)
        else 0.0
    )

    return per_type, fpr


def evaluate_windows_counts(
    windows,
    alerts
):
    per_type = defaultdict(
        lambda: {
            "tp": 0,
            "fn": 0
        }
    )

    fp = 0
    tn = 0

    for window, alert in zip(
        windows,
        alerts
    ):
        labels = [
            m["label"]
            for m in window
        ]

        attack_labels = [
            label
            for label in labels
            if label != "normal"
        ]

        if not attack_labels:

            if alert:
                fp += 1
            else:
                tn += 1

        else:
            attack_types = set(
                label.split(
                    ":",
                    1
                )[1]
                for label
                in attack_labels
            )

            for attack_type in (
                attack_types
            ):
                if alert:
                    per_type[
                        attack_type
                    ]["tp"] += 1
                else:
                    per_type[
                        attack_type
                    ]["fn"] += 1

    return per_type, fp, tn


def merge_per_type(
    per_type_dicts
):
    merged = defaultdict(
        lambda: {
            "tp": 0,
            "fn": 0
        }
    )

    for per_type in (
        per_type_dicts
    ):
        for attack_type, counts in (
            per_type.items()
        ):
            merged[
                attack_type
            ]["tp"] += counts["tp"]

            merged[
                attack_type
            ]["fn"] += counts["fn"]

    return merged


def merge_counts(
    fp_tn_pairs
):
    total_fp = sum(
        fp
        for fp, tn
        in fp_tn_pairs
    )

    total_tn = sum(
        tn
        for fp, tn
        in fp_tn_pairs
    )

    return (
        total_fp
        / (total_fp + total_tn)
        if (total_fp + total_tn)
        else 0.0
    )


def print_report(
    name,
    per_type,
    fpr
):
    print(
        f"\n--- {name} ---"
    )

    print(
        f"{'attack type':<20} "
        f"{'detected':<10} "
        f"{'missed':<10} "
        f"{'recall':<8}"
    )

    for attack_type, counts in sorted(
        per_type.items()
    ):
        tp = counts["tp"]
        fn = counts["fn"]

        recall = (
            tp / (tp + fn)
            if (tp + fn)
            else 0.0
        )

        print(
            f"{attack_type:<20} "
            f"{tp:<10} "
            f"{fn:<10} "
            f"{recall:<8.2f}"
        )

    print(
        "false positive rate "
        f"(on clean traffic): "
        f"{fpr:.3f}"
    )
