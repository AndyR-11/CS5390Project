"""
Builds normal-behavior profiles for OPC UA structure and
statistics detection.
"""

from infer_structure import infer
from detector_stats import peak_msg_rate


class StructProfile:
    def __init__(self):
        self.prefix_width = 3
        self.clusters = []
        self.cluster_map = {}

    def __repr__(self):
        return (
            "StructProfile("
            f"prefix_width={self.prefix_width}, "
            f"clusters={len(self.clusters)})"
        )


def build_struct_profile(
    normal_messages,
    prefix_width=3
):
    schema = infer(
        normal_messages,
        prefix_width=prefix_width,
        min_cluster_size=1,
    )

    p = StructProfile()

    p.prefix_width = schema["prefix_width"]
    p.clusters = schema["clusters"]

    p.cluster_map = {
        c["cluster_key_hex"]: c
        for c in p.clusters
    }

    return p


class StatsProfile:
    def __init__(self):
        self.normal_peak_rate = 0.0
        self.rate_threshold = 0.0
        self.window_sec = 1.0
        self.multiplier = 3.0

    def __repr__(self):
        return (
            "StatsProfile("
            f"normal_peak_rate="
            f"{self.normal_peak_rate:.2f}, "
            f"rate_threshold="
            f"{self.rate_threshold:.2f}, "
            f"window_sec="
            f"{self.window_sec:.1f})"
        )


def build_stats_profile(
    normal_messages,
    window_sec=1.0,
    multiplier=3.0
):
    p = StatsProfile()

    p.window_sec = window_sec
    p.multiplier = multiplier

    p.normal_peak_rate = (
        peak_msg_rate(
            normal_messages,
            window_sec
        )
    )

    p.rate_threshold = (
        p.normal_peak_rate
        * multiplier
    )

    return p
