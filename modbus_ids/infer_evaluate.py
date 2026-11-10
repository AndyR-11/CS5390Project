"""
Scores inferred field boundaries against ground truth -- this is your
week 4 deliverable: "field boundary inference, scored against ground
truth" (see schema.py's DEFAULT_SCHEMA for what "ground truth" means
here: the REAL Modbus layout, used only for scoring, never fed into
the inference algorithm itself).

A "boundary" is a byte offset where one field ends and the next
begins. We score boundary offsets, not whole fields -- this is more
forgiving and more standard: if the true layout has fields at
[0,2,4,6,7,8] and you found [0,2,4,6,8] (missing the 6/7 split), you
still get credit for the 4 boundaries you found correctly.
"""

from schema import DEFAULT_SCHEMA


def true_boundaries_from_schema(schema=DEFAULT_SCHEMA, total_len=12):
    """Extracts the ground-truth boundary offsets from schema.py's
    DEFAULT_SCHEMA. Only used for SCORING -- never pass this into the
    inference algorithm itself."""
    offsets = sorted(f["offset"] for f in schema)
    if 0 not in offsets:
        offsets = [0] + offsets
    return offsets


def score_boundaries(predicted, true, total_len):
    """
    predicted, true: lists of boundary offsets (ints), each < total_len.
    Returns (precision, recall, f1).
    """
    pred_set = set(predicted)
    true_set = set(true)

    tp = len(pred_set & true_set)
    fp = len(pred_set - true_set)
    fn = len(true_set - pred_set)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return precision, recall, f1


def print_boundary_report(predicted, true, total_len):
    precision, recall, f1 = score_boundaries(predicted, true, total_len)
    print(f"Predicted boundaries: {sorted(predicted)}")
    print(f"True boundaries:      {sorted(true)}")
    print(f"Matched:   {sorted(set(predicted) & set(true))}")
    print(f"Missed:    {sorted(set(true) - set(predicted))}   (real boundaries we didn't find)")
    print(f"Spurious:  {sorted(set(predicted) - set(true))}   (boundaries we guessed that aren't real)")
    print(f"Precision: {precision:.2f}   Recall: {recall:.2f}   F1: {f1:.2f}")