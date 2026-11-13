"""
Runs all three OPC UA detectors against real capture files:

  1. Structure-based detector
  2. Statistics-only baseline
  3. Behavioral detector

Normal traffic is split chronologically:
  first 70% = training
  final 30% = held-out false-positive test

Each attack capture represents one attack experiment. This differs
slightly from the Modbus per-message evaluation because an OPC UA
attack capture also contains normal connection/session setup traffic
such as HEL, OPN, and CLO.

Output formatting intentionally matches the Modbus evaluator.

Usage:

python3 run_demo_real_multi.py \
    ../pcaps/opcua/opc_normal_only.pcapng \
    ../pcaps/opcua/opc_invalid_node_only.pcapng \
    ../pcaps/opcua/opc_write_no_read_only.pcapng \
    ../pcaps/opcua/opc_value_jump_only.pcapng \
    ../pcaps/opcua/opc_read_flood_only.pcapng \
    ../pcaps/opcua/opc_session_flood_only.pcapng
"""

import os
import sys
from collections import defaultdict

from pcap_loader import load_tcp_payloads

from profile import (
    build_struct_profile,
    build_stats_profile,
)

from detector_struct import struct_detect
from detector_stats import stats_detect

from detector_behavioral import (
    build_behavioral_profile,
    behavioral_detect,
)

from evaluate import print_report


OPC_PORT = 4840


def attack_name(path):
    name = os.path.splitext(
        os.path.basename(path)
    )[0]

    if name.startswith("opc_"):
        name = name[4:]

    if name.endswith("_only"):
        name = name[:-5]

    return name


def empty_results():
    return defaultdict(
        lambda: {
            "tp": 0,
            "fn": 0
        }
    )


def false_positive_rate(
    alert_flags
):
    if not alert_flags:
        return 0.0

    return (
        sum(alert_flags)
        / len(alert_flags)
    )


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    normal_path = sys.argv[1]
    attack_paths = sys.argv[2:]

    all_normal = load_tcp_payloads(
        normal_path,
        server_port=OPC_PORT,
        label="normal",
    )

    if not all_normal:
        print(
            "No OPC UA request messages "
            f"found in {normal_path}."
        )
        sys.exit(1)

    attack_files = []

    for path in attack_paths:
        name = attack_name(path)

        msgs = load_tcp_payloads(
            path,
            server_port=OPC_PORT,
            label="attack:" + name,
        )

        print(
            f"{path}: "
            f"{len(msgs)} messages, "
            f"attack={name}"
        )

        attack_files.append(
            (name, msgs)
        )

    # ---------------------------------------------
    # 70/30 chronological normal split
    # ---------------------------------------------

    all_normal = sorted(
        all_normal,
        key=lambda m: m["ts"]
    )

    split = int(
        len(all_normal) * 0.7
    )

    train_normal = all_normal[:split]
    test_normal = all_normal[split:]

    total_attack_messages = sum(
        len(msgs)
        for _, msgs
        in attack_files
    )

    print(
        f"\nTraining on "
        f"{len(train_normal)} "
        "normal messages, "
        "testing false positives on "
        f"{len(test_normal)} "
        "held-out normal messages, "
        "evaluating "
        f"{len(attack_files)} "
        "attack captures containing "
        f"{total_attack_messages} "
        "request messages.\n"
    )

    # ---------------------------------------------
    # Build profiles
    # ---------------------------------------------

    struct_profile = (
        build_struct_profile(
            train_normal
        )
    )

    stats_profile = (
        build_stats_profile(
            train_normal
        )
    )

    behavioral_profile = (
        build_behavioral_profile(
            train_normal
        )
    )

    print(
        "Structure profile:",
        struct_profile
    )

    print(
        "Statistics profile:",
        stats_profile
    )

    print(
        "Behavioral profile:",
        behavioral_profile
    )

    # =============================================
    # STRUCTURE DETECTOR
    # =============================================

    structure_normal_alerts = [
        struct_detect(
            m["raw"],
            struct_profile
        ) is not None
        for m in test_normal
    ]

    structure_fpr = (
        false_positive_rate(
            structure_normal_alerts
        )
    )

    structure_results = (
        empty_results()
    )

    for name, msgs in attack_files:

        # OPC attack captures contain normal session/setup
        # messages. Only application MSG traffic is considered
        # when asking whether the attack itself produced a
        # structural anomaly.
        attack_msgs = [
            m for m in msgs
            if (
                len(m["raw"]) >= 3
                and m["raw"][:3] == b"MSG"
            )
        ]

        hit = any(
            struct_detect(
                m["raw"],
                struct_profile
            ) is not None
            for m in attack_msgs
        )

        if hit:
            structure_results[
                name
            ]["tp"] += 1
        else:
            structure_results[
                name
            ]["fn"] += 1

    print_report(
        "Structure-based detector",
        structure_results,
        structure_fpr
    )

    # =============================================
    # STATISTICS DETECTOR
    # =============================================

    stats_normal_hit = (
        stats_detect(
            test_normal,
            stats_profile
        )
    )

    stats_fpr = (
        1.0
        if stats_normal_hit
        else 0.0
    )

    stats_results = empty_results()

    for name, msgs in attack_files:

        hit = stats_detect(
            msgs,
            stats_profile
        )

        if hit:
            stats_results[
                name
            ]["tp"] += 1
        else:
            stats_results[
                name
            ]["fn"] += 1

    print_report(
        "Statistics-only baseline",
        stats_results,
        stats_fpr
    )

    # =============================================
    # BEHAVIORAL DETECTOR
    # =============================================

    normal_behavioral = (
        behavioral_detect(
            test_normal,
            behavioral_profile
        )
    )

    behavioral_fpr = (
        1.0
        if normal_behavioral
        else 0.0
    )

    behavioral_results = (
        empty_results()
    )

    for name, msgs in attack_files:

        alerts = behavioral_detect(
            msgs,
            behavioral_profile
        )

        hit = bool(alerts)

        if hit:
            behavioral_results[
                name
            ]["tp"] += 1
        else:
            behavioral_results[
                name
            ]["fn"] += 1

    print_report(
        "Behavioral detector",
        behavioral_results,
        behavioral_fpr
    )


if __name__ == "__main__":
    main()
