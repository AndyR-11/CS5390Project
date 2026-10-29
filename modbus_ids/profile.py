"""
Builds a "what does normal look like" profile from clean training
traffic. Both detectors use a profile; this file only builds the one
the structure-based detector needs.
"""

from parser import parse
from schema import DEFAULT_SCHEMA


class StructProfile:
    def __init__(self):
        self.proto_id = None
        self.allowed_func_codes = set()
        self.addr_range = {}   # func_code -> (min, max)
        self.qty_range = {}    # func_code -> (min, max)

    def __repr__(self):
        return (f"StructProfile(proto_id={self.proto_id}, "
                f"funcs={self.allowed_func_codes}, "
                f"addr_range={self.addr_range}, qty_range={self.qty_range})")


def build_struct_profile(normal_messages, schema=DEFAULT_SCHEMA) -> StructProfile:
    p = StructProfile()
    addr_vals, qty_vals = {}, {}

    for m in normal_messages:
        f = parse(m["raw"], schema)
        p.proto_id = f["proto_id"]           # should be constant; last write wins, fine for now
        p.allowed_func_codes.add(f["func_code"])

        func = f["func_code"]
        if "start_addr" in f:
            addr_vals.setdefault(func, []).append(f["start_addr"])
        if "quantity" in f:
            qty_vals.setdefault(func, []).append(f["quantity"])

    for func, vals in addr_vals.items():
        p.addr_range[func] = (min(vals), max(vals))
    for func, vals in qty_vals.items():
        p.qty_range[func] = (min(vals), max(vals))

    return p


class StatsProfile:
    def __init__(self):
        self.rate_mean = self.rate_std = 0.0
        self.size_mean = self.size_std = 0.0
        self.gap_mean = self.gap_std = 0.0


def build_stats_profile(normal_messages, window_sec=5.0) -> StatsProfile:
    from detector_stats import windows_from_messages, window_features
    p = StatsProfile()
    windows = windows_from_messages(normal_messages, window_sec)
    feats = [window_features(w, window_sec) for w in windows if w]

    rates = [f["rate"] for f in feats]
    sizes = [f["avg_size"] for f in feats]
    gaps = [f["avg_gap"] for f in feats]

    p.rate_mean, p.rate_std = _mean_std(rates)
    p.size_mean, p.size_std = _mean_std(sizes)
    p.gap_mean, p.gap_std = _mean_std(gaps)
    return p


def _mean_std(vals):
    if not vals:
        return 0.0, 1.0
    mean = sum(vals) / len(vals)
    var = sum((v - mean) ** 2 for v in vals) / len(vals)
    std = var ** 0.5
    return mean, max(std, 1e-6)   # avoid divide-by-zero