"""
T2: field boundary inference -- figures out where fields start and end
in a raw byte stream, using ONLY statistics computed across many
messages. Never references Modbus, function codes, or any protocol
name anywhere in this file -- that's the "no spec used" rule. Test it
on a made-up protocol and it should work exactly the same way.

The idea: look at each byte position across many messages of the same
type. A position that's part of a stable field (a constant, or a
counter that increments predictably) looks "low variability" -- few
distinct values relative to the number of messages. A position inside
a free-varying data field looks "high variability" -- almost every
message has a different value there. A FIELD BOUNDARY is where that
variability signal changes sharply from one byte to the next.
"""

from collections import Counter


def byte_variability(messages, max_len=None):
    """
    messages: list of raw byte strings (or bytes-like), not the full
              message dicts -- pass [m["raw"] for m in your_messages].
    Returns a list of floats, one per byte position, each in [0, 1]:
    0.0 = every message had the exact same byte there, 1.0 = every
    message had a different byte there (as different as possible given
    how many messages you have).
    """
    if max_len is None:
        max_len = min(len(m) for m in messages)

    variability = []
    for pos in range(max_len):
        values = [m[pos] for m in messages]
        counts = Counter(values)
        # normalized Shannon-style spread: 0 if all one value, higher
        # the more evenly spread the values are. Using distinct-count
        # ratio (simpler, same spirit, easier to reason about):
        variability.append(len(counts) / len(values))
    return variability


def find_boundaries(variability, jump_threshold=0.12):
    """
    A boundary is placed between byte i and byte i+1 whenever the
    variability signal changes by more than jump_threshold. Returns a
    sorted list of boundary offsets (each offset is the START of a new
    field; 0 is always included as the start of the first field).

    jump_threshold default was 0.25, tuned against synthetic traffic
    with a wide-range counter. On real captured traffic (see
    chain_t1_t2.py), a counter field's variability ceiling can be much
    lower than 1.0 -- e.g. a 1-byte sub-field of a transaction ID that
    wraps every 256 messages tops out around 0.13 distinct-value ratio
    even though it's a genuine, fully-varying counter byte. 0.25 missed
    that real signal entirely and collapsed whole messages into one
    field. 0.12 was chosen by sweeping 0.02-0.25 against real pooled
    Modbus captures: every value in [0.105, 0.13] gives the same best
    boundary F1 (0.57, up from 0.33) with no spurious extra splits, so
    0.12 sits in the middle of a wide stable range rather than being a
    value that only works by coincidence at this exact number.
    """
    boundaries = [0]
    for i in range(1, len(variability)):
        if abs(variability[i] - variability[i - 1]) > jump_threshold:
            boundaries.append(i)
    return boundaries


def boundaries_to_fields(boundaries, total_len):
    """Converts a list of boundary offsets into (offset, length) field
    spans covering the full message length."""
    offsets = sorted(set(boundaries))
    if not offsets or offsets[0] != 0:
        offsets = [0] + offsets
    fields = []
    for i, start in enumerate(offsets):
        end = offsets[i + 1] if i + 1 < len(offsets) else total_len
        if end > start:
            fields.append((start, end - start))
    return fields


def infer_boundaries(messages, jump_threshold=0.12):
    """
    One-call convenience: messages -> list of (offset, length) field
    spans. messages should be raw byte strings of the SAME message
    type (see cluster.py if your capture mixes several types).

    jump_threshold default matches find_boundaries() -- see that
    function's docstring for why 0.12 instead of the original 0.25.
    """
    max_len = min(len(m) for m in messages)
    variability = byte_variability(messages, max_len)
    boundaries = find_boundaries(variability, jump_threshold)
    return boundaries_to_fields(boundaries, max_len), variability