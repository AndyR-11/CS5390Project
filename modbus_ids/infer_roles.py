"""
Assigns a rough ROLE to each inferred field (from infer_boundaries.py +
infer_merge.py), and exports the result in the same shape as
schema.py's DEFAULT_SCHEMA so it's a drop-in replacement.

Roles assigned here are generic statistical labels, not protocol
knowledge:

  constant        - exactly one value seen across all messages
  counter         - value is monotonic (non-decreasing, with wraps
                    allowed) across message arrival order
  low_variability - few distinct values, no monotonic trend (fits
                    things like a small set of IDs or flags)
  variable        - lots of distinct values, no trend (fits free-form
                    data)

Field NAMES are made up (field_0, field_1, ...) since inference has no
way to know what a field is actually called -- that's expected. If you
want human-readable names for your report, rename them by hand after
looking at the inferred roles; don't hardcode Modbus names into this
file.
"""

import json

from infer_merge import _is_monotonic_merge


def _distinct_count(values):
    return len(set(values))


def assign_roles(raw_messages, fields):
    """
    raw_messages: list of raw byte strings (same messages used for
                  inference).
    fields: list of (offset, length) from infer_boundaries +
            infer_merge.
    Returns a schema list: [{"name", "offset", "len", "role"}, ...],
    in the same shape as schema.py's DEFAULT_SCHEMA.
    """
    n = len(raw_messages)
    schema = []
    for i, (offset, length) in enumerate(fields):
        values = [int.from_bytes(m[offset:offset + length], "big") for m in raw_messages]
        distinct = _distinct_count(values)

        if distinct == 1:
            role = "constant"
        elif _is_monotonic_merge(values):
            role = "counter"
        elif distinct <= max(4, n * 0.05):
            role = "low_variability"
        else:
            role = "variable"

        schema.append({
            "name": f"field_{i}",
            "offset": offset,
            "len": length,
            "role": role,
        })
    return schema


def save_schema(schema, path):
    with open(path, "w") as f:
        json.dump(schema, f, indent=2)


def load_schema(path):
    """Loads a schema previously saved by save_schema(). Use this in
    place of importing DEFAULT_SCHEMA from schema.py once you trust
    your inferred layout -- same list-of-dicts shape, so parser.py,
    profile.py, and the detectors all work unchanged."""
    with open(path) as f:
        return json.load(f)