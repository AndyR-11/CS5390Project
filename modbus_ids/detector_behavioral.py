"""
Behavioral detector. Unlike detector_struct.py and detector_stats.py,
this one is STATEFUL -- it needs the recent message history, not just
the current message, because sequence and rate-of-change are
properties of a *stream* of messages, not any single one.

Two rules, matching the two new attacks in traffic_sim.py:
  1. read_before_write: a write to a given address should be preceded
     by a read of that same address within a short time window.
  2. value_jump: a write's value shouldn't change by more than the
     largest step ever seen in normal training traffic.

Both checks are deliberately simple (a time window and a max-delta),
matching the project's "keep it simple, evaluate it honestly" scope --
see README for why this is a separate detector rather than folded
into detector_struct.py.
"""

from parser import parse
from schema import DEFAULT_SCHEMA


class BehavioralProfile:
    def __init__(self):
        self.max_write_step = 0          # largest |delta| seen between consecutive writes, per address
        self.read_before_write_sec = 5.0  # how far back to look for a preceding read

    def __repr__(self):
        return (f"BehavioralProfile(max_write_step={self.max_write_step}, "
                f"read_before_write_sec={self.read_before_write_sec})")


def build_behavioral_profile(normal_messages, schema=DEFAULT_SCHEMA, read_window_sec=5.0) -> BehavioralProfile:
    """Learns the normal write step size from training traffic. The
    read-before-write window is left as a fixed parameter (5 sec) --
    you could also learn it from the data's typical read-to-write gap
    if you want to go further."""
    p = BehavioralProfile()
    p.read_before_write_sec = read_window_sec

    last_value_by_addr = {}
    max_step = 0
    for m in normal_messages:
        f = parse(m["raw"], schema)
        if f["func_code"] == 6 and "value" in f:
            addr, value = f["start_addr"], f["value"]
            if addr in last_value_by_addr:
                step = abs(value - last_value_by_addr[addr])
                max_step = max(max_step, step)
            last_value_by_addr[addr] = value

    # small safety margin so legitimate traffic right at the boundary
    # of what training saw doesn't immediately false-positive
    p.max_write_step = int(max_step * 1.5) if max_step else 50
    return p


def behavioral_detect(messages, profile, schema=DEFAULT_SCHEMA):
    """
    messages: the FULL chronological message list (both normal and
              attack, as evaluate.py expects) -- this detector needs
              to see history, so it processes the whole stream at once
              rather than one message at a time.

    Returns a list of (reason_or_None) the same length as `messages`,
    one entry per message, in the same order.
    """
    results = [None] * len(messages)
    last_read_ts_by_addr = {}       # addr -> timestamp of the most recent read
    last_value_by_addr = {}         # addr -> value of the most recent write

    for i, m in enumerate(messages):
        f = parse(m["raw"], schema)
        func = f["func_code"]

        if func in (1, 2, 3, 4) and "start_addr" in f:
            last_read_ts_by_addr[f["start_addr"]] = m["ts"]

        elif func == 6 and "value" in f:
            addr, value = f["start_addr"], f["value"]

            last_read_ts = last_read_ts_by_addr.get(addr)
            if last_read_ts is None or (m["ts"] - last_read_ts) > profile.read_before_write_sec:
                results[i] = "write_no_read"
            elif addr in last_value_by_addr:
                step = abs(value - last_value_by_addr[addr])
                if step > profile.max_write_step:
                    results[i] = "value_jump"

            last_value_by_addr[addr] = value

    return results