"""
Statistics-only OPC UA baseline.

Uses only message timing/rate and does not decode OPC UA semantics.
The detector learns a normal peak MSG request rate and alerts when
traffic exceeds three times that normal rate.
"""


def is_opc_msg(message):
    raw = message["raw"]
    return len(raw) >= 3 and raw[:3] == b"MSG"


def peak_msg_rate(messages, window_sec=1.0):
    msg_times = sorted(
        m["ts"]
        for m in messages
        if is_opc_msg(m)
    )

    if not msg_times:
        return 0.0

    left = 0
    peak = 0

    for right in range(len(msg_times)):
        while (
            msg_times[right]
            - msg_times[left]
            > window_sec
        ):
            left += 1

        count = right - left + 1
        peak = max(peak, count)

    return peak / window_sec


def stats_detect(messages, profile):
    rate = peak_msg_rate(
        messages,
        profile.window_sec
    )

    return rate > profile.rate_threshold
