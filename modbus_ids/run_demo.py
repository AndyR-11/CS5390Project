"""
Runs the full pipeline end to end on SYNTHETIC traffic, so you can see
the detectors working before the real lab exists.

Once you have real pcaps (normal_traffic.pcapng, attack_traffic.pcapng
from your lab), use pcap_loader.py instead -- see run_demo_real.py for
an example. Everything downstream (profile.py, detector_struct.py,
detector_stats.py, evaluate.py) stays the same either way.
"""

from traffic_sim import generate_normal, inject_attacks
from profile import build_struct_profile, build_stats_profile
from detector_struct import struct_detect
from detector_stats import windows_from_messages, stats_detect
from evaluate import evaluate_struct, evaluate_windows, print_report

WINDOW_SEC = 5.0


def main():
    # --- data ---
    train_normal = generate_normal(n=300, start_ts=0.0)

    train_end = train_normal[-1]["ts"]
    test_normal = generate_normal(n=150, start_ts=train_end + 5.0)

    test_normal_end = test_normal[-1]["ts"]
    test_mixed = inject_attacks(generate_normal(n=150, start_ts=test_normal_end + 5.0))

    # --- build profiles from TRAINING data only ---
    struct_profile = build_struct_profile(train_normal)
    stats_profile = build_stats_profile(train_normal, WINDOW_SEC)
    print("Learned structure profile:", struct_profile)

    # --- structure detector: run on clean test + mixed test, per message ---
    all_struct_msgs = test_normal + test_mixed
    struct_alerts = [
        struct_detect(m["raw"], struct_profile) is not None
        for m in all_struct_msgs
    ]
    per_type, fpr = evaluate_struct(all_struct_msgs, struct_alerts)
    print_report("Structure-based detector", per_type, fpr)

    # --- stats detector: run on clean test + mixed test, per window ---
    all_stats_msgs = sorted(test_normal + test_mixed, key=lambda m: m["ts"])
    windows = windows_from_messages(all_stats_msgs, WINDOW_SEC)
    stats_alerts = [stats_detect(w, stats_profile) for w in windows]
    per_type, fpr = evaluate_windows(windows, stats_alerts)
    print_report("Statistics-only baseline", per_type, fpr)


if __name__ == "__main__":
    main()
