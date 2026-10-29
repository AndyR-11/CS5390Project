"""
Structure-based detector. Checks ONE message at a time against the
normal-behavior profile built from training traffic. Returns a reason
string if something looks wrong, or None if the message looks normal.
"""

from parser import parse
from schema import DEFAULT_SCHEMA


def struct_detect(raw: bytes, profile, schema=DEFAULT_SCHEMA):
    f = parse(raw, schema)

    if f["proto_id"] != profile.proto_id:
        return "bad_proto_id"

    # the length field should equal unit_id + everything after it
    real_body_len = len(raw) - 6   # MBAP header's length field covers bytes after itself
    if f["length"] != real_body_len:
        return "bad_length"

    if f["func_code"] not in profile.allowed_func_codes:
        return "illegal_func"

    func = f["func_code"]
    if func in profile.addr_range and "start_addr" in f:
        lo, hi = profile.addr_range[func]
        if not (lo <= f["start_addr"] <= hi):
            return "out_of_range"

    if func in profile.qty_range and "quantity" in f:
        lo, hi = profile.qty_range[func]
        if not (lo <= f["quantity"] <= hi):
            return "out_of_range"

    return None
