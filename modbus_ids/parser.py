"""
Parse a raw Modbus/TCP message into a dict of field values, using a
schema (see schema.py). Works on any schema with the same shape,
whether it's hand-written or produced by your inference code.
"""

from schema import DEFAULT_SCHEMA, DATA_OFFSET


def parse(raw: bytes, schema=DEFAULT_SCHEMA) -> dict:
    fields = {}
    for f in schema:
        start, end = f["offset"], f["offset"] + f["len"]
        chunk = raw[start:end]
        fields[f["name"]] = int.from_bytes(chunk, "big")

    # function-specific data: for read requests (func 1/2/3/4) this is
    # [start_addr: 2 bytes][quantity: 2 bytes]
    func = fields.get("func_code")
    if func in (1, 2, 3, 4) and len(raw) >= DATA_OFFSET + 4:
        fields["start_addr"] = int.from_bytes(raw[DATA_OFFSET:DATA_OFFSET + 2], "big")
        fields["quantity"] = int.from_bytes(raw[DATA_OFFSET + 2:DATA_OFFSET + 4], "big")

    # write single register (func 6): [addr: 2 bytes][value: 2 bytes]
    if func == 6 and len(raw) >= DATA_OFFSET + 4:
        fields["start_addr"] = int.from_bytes(raw[DATA_OFFSET:DATA_OFFSET + 2], "big")
        fields["value"] = int.from_bytes(raw[DATA_OFFSET + 2:DATA_OFFSET + 4], "big")

    fields["_raw_len"] = len(raw)
    return fields