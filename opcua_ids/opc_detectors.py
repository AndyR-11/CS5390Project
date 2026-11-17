"""
Profiles + the three detectors for OPC UA, mirroring the Modbus pipeline
(detector_struct / detector_stats / detector_behavioral) but working on decoded
OPC UA messages (see opc_decode.py).

  structure   - stateless, one message at a time, vs. what normal traffic contained
  statistics  - per time window: request rate, avg size, gap, new-connection rate
  behavioral  - stateful: write_no_read (per connection) and value_jump
"""
from collections import defaultdict

WINDOW_SEC = 5.0
Z_THRESHOLD = 3.0


# --------------------------------------------------------------------------- structure
class StructProfile:
    def __init__(self):
        self.msg_types = set()
        self.services = set()                    # (msg_type, service)
        self.nodes = defaultdict(set)            # service -> set of node ids
        self.attrs = defaultdict(set)            # service -> attribute ids
        self.n_items = {}                        # service -> (min, max)
        self.length = {}                         # (msg_type, service) -> (min, max)

    def __repr__(self):
        return (f"StructProfile(services={sorted(self.services, key=str)}, "
                f"read_nodes={sorted(self.nodes['Read'], key=str)}, "
                f"write_nodes={sorted(self.nodes['Write'], key=str)})")


def build_struct_profile(messages):
    p = StructProfile()
    for m in messages:
        d = m["dec"]
        if not d["parse_ok"]:
            continue
        key = (d["msg_type"], d["service"])
        p.msg_types.add(d["msg_type"])
        p.services.add(key)
        lo, hi = p.length.get(key, (len(m["raw"]), len(m["raw"])))
        p.length[key] = (min(lo, len(m["raw"])), max(hi, len(m["raw"])))
        svc = d["service"]
        if svc in ("Read", "Write"):
            p.nodes[svc].update(d["nodes"])
            if d["attr"] is not None:
                p.attrs[svc].add(d["attr"])
            lo, hi = p.n_items.get(svc, (d["n_items"], d["n_items"]))
            p.n_items[svc] = (min(lo, d["n_items"]), max(hi, d["n_items"]))
    return p


def struct_detect(m, p):
    """Returns a reason string, or None if the message looks normal."""
    d = m["dec"]
    if d["problem"] == "unknown_msg_type":
        return "unknown_msg_type"
    if d["problem"] == "size_mismatch":
        return "size_mismatch"
    if not d["parse_ok"]:
        return "parse_error"
    if d["msg_type"] not in p.msg_types:
        return "unseen_msg_type"
    key = (d["msg_type"], d["service"])
    if key not in p.services:
        return "unseen_service"
    lo, hi = p.length[key]
    if not lo <= len(m["raw"]) <= hi:
        return "unexpected_length"
    svc = d["service"]
    if svc in ("Read", "Write"):
        if any(n not in p.nodes[svc] for n in d["nodes"]):
            return "unseen_node"
        if d["attr"] not in p.attrs[svc]:
            return "unseen_attribute"
        lo, hi = p.n_items[svc]
        if not lo <= d["n_items"] <= hi:
            return "bad_item_count"
    return None


# --------------------------------------------------------------------------- statistics
# Per-feature minimum std. Windows from a single short normal capture can have a
# near-zero spread (e.g. every request the same size), which would make any tiny
# deviation a "3 sigma" event. The floors keep z-scores meaningful.
STD_FLOOR = {"rate": 0.2, "avg_size": 3.0, "avg_gap": 0.05, "new_conns": 0.5}
FEATURES = ["rate", "avg_size", "avg_gap", "new_conns"]


class StatsProfile:
    def __init__(self):
        self.mean = {f: 0.0 for f in FEATURES}
        self.std = {f: 1.0 for f in FEATURES}


def windows_from_messages(messages, window_sec=WINDOW_SEC, drop_partial_tail=False):
    """Split a chronological message list into consecutive windows of window_sec.

    The last window only covers part of window_sec (the capture just ends), so its request
    rate is artificially low. Pass drop_partial_tail=True for CLEAN-traffic windows (training
    and false-positive scoring) so a capture ending can never look like an anomaly. Keep the
    default for windows that may contain an attack.
    """
    if not messages:
        return []
    start, end = messages[0]["ts"], messages[-1]["ts"]
    n = int((end - start) // window_sec) + 1
    buckets = [[] for _ in range(n)]
    for m in messages:
        buckets[min(int((m["ts"] - start) // window_sec), n - 1)].append(m)
    if drop_partial_tail and n > 1:
        buckets.pop()
    return buckets


def window_features(window, window_sec=WINDOW_SEC):
    if not window:
        return {"rate": 0.0, "avg_size": 0.0, "avg_gap": 0.0, "new_conns": 0.0}
    ts = sorted(m["ts"] for m in window)
    gaps = [b - a for a, b in zip(ts, ts[1:])] or [0.0]
    return {"rate": len(window) / window_sec,
            "avg_size": sum(len(m["raw"]) for m in window) / len(window),
            "avg_gap": sum(gaps) / len(gaps),
            "new_conns": float(sum(m["dec"]["msg_type"] == "HEL" for m in window))}


def build_stats_profile(messages, window_sec=WINDOW_SEC):
    p = StatsProfile()
    feats = [window_features(w, window_sec)
             for w in windows_from_messages(messages, window_sec, drop_partial_tail=True) if w]
    for f in FEATURES:
        vals = [x[f] for x in feats]
        mean = sum(vals) / len(vals)
        std = (sum((v - mean) ** 2 for v in vals) / len(vals)) ** 0.5
        p.mean[f], p.std[f] = mean, max(std, STD_FLOOR[f], 0.1 * abs(mean))
    return p


def stats_detect(window, p, window_sec=WINDOW_SEC):
    """True if any feature is more than Z_THRESHOLD std devs from normal. Returns (alert, which)."""
    feats = window_features(window, window_sec)
    hit = [f for f in FEATURES if abs(feats[f] - p.mean[f]) > Z_THRESHOLD * p.std[f]]
    return bool(hit), hit


# --------------------------------------------------------------------------- behavioral
class BehavioralProfile:
    def __init__(self):
        self.max_write_step = 50
        self.write_lo = None
        self.write_hi = None
        self.read_before_write_sec = 5.0

    def __repr__(self):
        return (f"BehavioralProfile(max_write_step={self.max_write_step}, "
                f"write_range=({self.write_lo},{self.write_hi}), "
                f"read_before_write_sec={self.read_before_write_sec})")


def build_behavioral_profile(messages, read_window_sec=5.0):
    p = BehavioralProfile()
    p.read_before_write_sec = read_window_sec
    last, steps, vals = {}, [], []
    for m in messages:
        d = m["dec"]
        if d["service"] == "Write" and d["value"] is not None:
            for node in d["nodes"]:
                if node in last:
                    steps.append(abs(d["value"] - last[node]))
                last[node] = d["value"]
            vals.append(d["value"])
    if steps:
        p.max_write_step = max(10, int(max(steps) * 1.5))
    if vals:
        p.write_lo, p.write_hi = min(vals) - p.max_write_step, max(vals) + p.max_write_step
    return p


def behavioral_detect(messages, p):
    """messages: FULL chronological list. Returns one reason-or-None per message.

    write_no_read is tracked PER CONNECTION: a write is only legitimate if the same
    connection read that node recently. (Tracking it globally lets any other client's
    read mask an attacker's write.) value_jump is tracked per node across connections,
    plus an absolute range from normal writes, so it still fires when the attacker's
    session is the first writer.

    An out-of-range value is NOT remembered as the node's "last value": otherwise one attack
    write (e.g. 999) would make the next legitimate write (e.g. 495) look like a jump too.
    In-range values always update it, so a legitimate level shift raises one alert, not many.
    """
    out = [None] * len(messages)
    last_read = {}     # (conn_id, node) -> ts
    last_value = {}    # node -> value of most recent write
    for i, m in enumerate(messages):
        d = m["dec"]
        if d["service"] == "Read":
            for node in d["nodes"]:
                last_read[(m["conn_id"], node)] = m["ts"]
        elif d["service"] == "Write" and d["value"] is not None:
            for node in d["nodes"]:
                t = last_read.get((m["conn_id"], node))
                too_big = node in last_value and abs(d["value"] - last_value[node]) > p.max_write_step
                out_of_range = p.write_lo is not None and not p.write_lo <= d["value"] <= p.write_hi
                if t is None or m["ts"] - t > p.read_before_write_sec:
                    out[i] = "write_no_read"
                elif too_big or out_of_range:
                    out[i] = "value_jump"
                if not out_of_range:
                    last_value[node] = d["value"]
    return out
