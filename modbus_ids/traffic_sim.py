"""
Generates synthetic Modbus/TCP-like traffic: normal read requests plus
labeled attack messages. This is NOT a substitute for your real lab
captures -- it exists so you can build and test the detector logic
before the lab is finished. Swap this out for a real pcap loader
(pcap_loader.py) once you have real captures.
"""

import random
import struct

NORMAL_FUNC_CODES = [3, 4]          # read holding / input registers
NORMAL_ADDR_RANGE = (0, 200)
NORMAL_QTY_RANGE = (1, 10)
PROTO_ID = 0


def _build_message(trans_id, func_code, addr, qty, unit_id=1, bad_length=None):
    pdu = struct.pack(">BHH", func_code, addr, qty)       # func(1) + addr(2) + qty(2)
    body = struct.pack(">B", unit_id) + pdu                # unit_id(1) + pdu
    real_length = len(body)
    length_field = bad_length if bad_length is not None else real_length
    header = struct.pack(">HHH", trans_id, PROTO_ID, length_field)
    return header + body


WRITE_ADDR = 1              # the one register normal traffic ever writes to
WRITE_VALUE_RANGE = (490, 510)
NORMAL_WRITE_STEP = 20       # max |value - last_value| seen in normal writes


def generate_normal(n, start_ts=0.0, gap=1.0, src_port=50000, jitter=0.15, write_prob=0.1):
    """n normal messages, evenly spaced with small random jitter (real
    polling traffic is never perfectly regular -- without jitter the
    stats baseline's learned std is ~0 and it flags everything).

    Mostly reads, with an occasional write to WRITE_ADDR -- and every
    write is preceded by a read of that same address a moment earlier,
    mimicking a real HMI's read/verify-before-write pattern. This
    read-before-write pattern is what the behavioral detector learns
    as "normal sequence."
    """
    msgs = []
    ts = start_ts
    trans_id = 0
    last_write_value = random.randint(*WRITE_VALUE_RANGE)

    def next_trans():
        nonlocal trans_id
        trans_id = (trans_id + 1) % 65536
        return trans_id

    i = 0
    while i < n:
        # read poll (always happens)
        addr = random.randint(*NORMAL_ADDR_RANGE)
        qty = random.randint(*NORMAL_QTY_RANGE)
        raw = _build_message(next_trans(), random.choice(NORMAL_FUNC_CODES), addr, qty)
        msgs.append({"raw": raw, "ts": ts, "label": "normal", "src_port": src_port, "trans_id": trans_id})
        ts += gap + random.uniform(-jitter, jitter)
        i += 1

        # occasionally follow up with a read-of-write-address, then a write
        if i < n - 1 and random.random() < write_prob:
            raw = _build_message(next_trans(), 3, WRITE_ADDR, 1)   # read check
            msgs.append({"raw": raw, "ts": ts, "label": "normal", "src_port": src_port, "trans_id": trans_id})
            ts += gap * 0.3 + random.uniform(-jitter, jitter)
            i += 1

            new_value = last_write_value + random.randint(-NORMAL_WRITE_STEP, NORMAL_WRITE_STEP)
            new_value = max(WRITE_VALUE_RANGE[0], min(WRITE_VALUE_RANGE[1], new_value))
            raw = _build_message(next_trans(), 6, WRITE_ADDR, new_value)
            msgs.append({"raw": raw, "ts": ts, "label": "normal", "src_port": src_port, "trans_id": trans_id})
            last_write_value = new_value
            ts += gap + random.uniform(-jitter, jitter)
            i += 1

    return msgs


def inject_attacks(normal_msgs, src_port=59999):
    """Returns a NEW list: normal_msgs with attack messages mixed in."""
    msgs = list(normal_msgs)
    last_ts = max(m["ts"] for m in normal_msgs)
    next_ts = last_ts + 1.0
    next_trans = max(m["trans_id"] for m in normal_msgs) + 1

    def add(raw, label):
        nonlocal next_ts, next_trans
        msgs.append({
            "raw": raw, "ts": next_ts, "label": label,
            "src_port": src_port, "trans_id": next_trans,
        })
        next_ts += 1.0
        next_trans += 1

    # illegal function code (0x2B is not in our normal set)
    add(_build_message(next_trans, 0x2B, 10, 1), "attack:illegal_func")

    # wrong length field (claims body is longer than it really is)
    add(_build_message(next_trans, 3, 10, 1, bad_length=99), "attack:bad_length")

    # out-of-range value (quantity way beyond anything seen in training)
    add(_build_message(next_trans, 3, 10, 9999), "attack:out_of_range")

    # replayed write: send the exact same message twice in a row
    replay_raw = _build_message(next_trans, 3, 50, 5)
    add(replay_raw, "attack:replay")
    add(replay_raw, "attack:replay")

    # read flood: burst of otherwise-valid reads with ~0 time gap
    flood_start = next_ts
    for i in range(50):
        trans_id = next_trans
        raw = _build_message(trans_id, 3, 10, 1)
        msgs.append({
            "raw": raw, "ts": flood_start + i * 0.01, "label": "attack:read_flood",
            "src_port": src_port, "trans_id": trans_id,
        })
        next_trans += 1

    # write with no preceding read -- structurally and statistically
    # normal, but skips the read/verify step normal traffic always does
    add(_build_message(next_trans, 6, WRITE_ADDR, 500), "attack:write_no_read")

    # implausible value jump -- preceded by a normal read (so this
    # tests ONLY the jump-size rule, not the read-before-write rule),
    # but the write value is far outside the step size ever seen in
    # normal writes (structurally valid, size/rate unremarkable)
    add(_build_message(next_trans, 3, WRITE_ADDR, 1), "normal")
    add(_build_message(next_trans, 6, WRITE_ADDR, 999), "attack:value_jump")

    msgs.sort(key=lambda m: m["ts"])
    return msgs