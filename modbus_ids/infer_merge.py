"""
Post-processes infer_boundaries.py's output to fix a specific, known
failure mode of plain per-byte variability thresholding: a multi-byte
field whose bytes have very different variability gets incorrectly
split into separate fields. Two concrete cases this causes:

  1. A multi-byte COUNTER (like a transaction ID): the low byte
     changes almost every message (looks "highly variable"), but the
     high byte only changes once every ~256 messages (looks "almost
     constant"). Plain thresholding sees a big jump between them and
     splits what should be one field into two.

  2. A multi-byte VALUE whose actual range is small relative to its
     byte width (e.g. a 2-byte field that only ever holds 0-999): the
     high byte barely varies (often constant or near-constant), the
     low byte varies a lot. Same symptom, same wrong split.

Neither heuristic below references Modbus or any specific protocol --
both are generic statistical tests on adjacent fields.
"""

from collections import Counter


def _field_values(raw_messages, offset, length):
    """Big-endian integer value of a field, per message, in the
    messages' given order (NOT sorted -- caller controls order)."""
    return [int.from_bytes(m[offset:offset + length], "big") for m in raw_messages]


def _is_monotonic_merge(combined_values, min_fraction=0.9):
    """True if combined_values (in message arrival order) is
    non-decreasing often enough to look like a counter. Allows a
    16-bit-style wraparound (value drops back near 0) without
    penalizing it, since counters legitimately wrap."""
    if len(combined_values) < 3:
        return False
    ok = 0
    total = len(combined_values) - 1
    for i in range(total):
        a, b = combined_values[i], combined_values[i + 1]
        if b >= a or (a > b and a > 60000 and b < 5000):  # treat a big-to-small drop near 16-bit max as a wrap
            ok += 1
    return (ok / total) >= min_fraction


def _is_low_info_merge(values_a, values_b, factor=1.5):
    """True if combining two adjacent fields doesn't multiply the
    number of distinct values much beyond the more-variable field
    alone -- a sign the less-variable one is redundant (e.g. a
    slow/near-constant high byte of a small-range value), not an
    independent field."""
    distinct_a = len(set(values_a))
    distinct_b = len(set(values_b))
    distinct_combined = len(set(zip(values_a, values_b)))
    return distinct_combined <= max(distinct_a, distinct_b) * factor


def merge_fields(raw_messages, fields, max_merged_len=4):
    """
    fields: list of (offset, length) as produced by
            infer_boundaries.boundaries_to_fields().
    Returns a new list of (offset, length), with adjacent fields
    merged wherever the counter or low-info-gain test says they're
    likely one field. Repeats until no more merges happen.
    """
    fields = list(fields)
    changed = True
    while changed:
        changed = False
        merged = []
        i = 0
        while i < len(fields):
            if i + 1 < len(fields):
                a_off, a_len = fields[i]
                b_off, b_len = fields[i + 1]
                if a_off + a_len == b_off and (a_len + b_len) <= max_merged_len:
                    values_a = _field_values(raw_messages, a_off, a_len)
                    values_b = _field_values(raw_messages, b_off, b_len)
                    combined = _field_values(raw_messages, a_off, a_len + b_len)

                    if _is_monotonic_merge(combined) or _is_low_info_merge(values_a, values_b):
                        merged.append((a_off, a_len + b_len))
                        i += 2
                        changed = True
                        continue
            merged.append(fields[i])
            i += 1
        fields = merged
    return fields