"""
Field schema for a Modbus/TCP message.

IMPORTANT: this is a placeholder. Your T2 (field boundary + role
inference) code should eventually PRODUCE a schema like this from raw
bytes alone, with no knowledge of Modbus. For now it's hardcoded to
the real Modbus layout so the detector/evaluation pipeline has
something to run against while inference is still being built.

Once your inference script works, replace DEFAULT_SCHEMA below with
whatever your script outputs (ideally loaded from a JSON file it writes).
"""

DEFAULT_SCHEMA = [
    {"name": "trans_id",  "offset": 0, "len": 2, "role": "counter"},
    {"name": "proto_id",  "offset": 2, "len": 2, "role": "constant"},
    {"name": "length",    "offset": 4, "len": 2, "role": "length"},
    {"name": "unit_id",   "offset": 6, "len": 1, "role": "id"},
    {"name": "func_code", "offset": 7, "len": 1, "role": "function_code"},
    # everything after byte 8 is function-specific data; handled separately
]

DATA_OFFSET = 8  # where function-specific fields start
