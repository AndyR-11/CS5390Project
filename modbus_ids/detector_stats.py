"""
Statistics-only baseline detector. Never looks inside the message --
only rate, size, and timing within a sliding window. This is the
"dumb" detector your structure-based detector is compared against.
"""

Z_THRESHOLD = 3.0  # flag if a feature is more than this many std devs from normal


def windows_from_messages(messages, window_sec=5.0):
    """Buckets messages into fixed time windows."""
    if not messages:
        return []
    start = messages[0]["ts"]
    end = messages[-1]["ts"]
    n_windows = int((end - start) // window_sec) + 1

    buckets = [[] for _ in range(n_windows)]
    for m in messages:
        idx = int((m["ts"] - start) // window_sec)
        idx = min(idx, n_windows - 1)
        buckets[idx].append(m)
    return buckets


def window_features(window, window_sec=5.0):
    """
    window_sec must match whatever you passed to windows_from_messages()
    -- rate is messages per the window's fixed duration, not per the
    spread of timestamps actually inside it. (An earlier version used
    the message spread as the denominator; for a window with only one
    message that spread is ~0, producing an absurd ~1,000,000 msg/sec
    "rate" that poisoned both the learned profile and detection. Real
    captures hit this constantly -- a quiet window with 1 message is
    common -- so this isn't an edge case, it's the normal case.)
    """
    if not window:
        return {"rate": 0.0, "avg_size": 0.0, "avg_gap": 0.0}
    sizes = [len(m["raw"]) for m in window]
    ts = sorted(m["ts"] for m in window)
    gaps = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)] or [0.0]
    return {
        "rate": len(window) / window_sec,
        "avg_size": sum(sizes) / len(sizes),
        "avg_gap": sum(gaps) / len(gaps),
    }


def stats_detect(window, profile, window_sec=5.0):
    """Returns True (alert) if this window's features look abnormal.
    window_sec must match what was used to build the window and the
    profile -- see window_features() for why."""
    feats = window_features(window, window_sec)
    checks = [
        (feats["rate"], profile.rate_mean, profile.rate_std),
        (feats["avg_size"], profile.size_mean, profile.size_std),
        (feats["avg_gap"], profile.gap_mean, profile.gap_std),
    ]
    for value, mean, std in checks:
        if abs(value - mean) > Z_THRESHOLD * std:
            return True
    return False