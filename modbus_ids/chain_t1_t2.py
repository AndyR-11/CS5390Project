"""
Chains T1 (message-type clustering, Paola's clustering.py) into T2
(field boundary + merge + role inference) -- the integration that was
missing: T1 alone groups messages by type, but doesn't say what's
inside them. T2 alone needs messages pre-split by type or its byte
statistics are meaningless (mixing two message types together looks
like noise). Neither half changes; this script is pure glue.

Pipeline, per captured file:
  1. Load raw messages (protocol-agnostic: just needs {"raw": bytes, ...})
  2. T1: MessageTypeClusterer.fit_predict() -> cluster id per message
  3. group_messages() -> {cluster_id: [messages]}  (T1's own adapter)
  4. For each cluster with enough messages (skip -1 = unassigned, and
     skip clusters too small to get meaningful byte statistics):
       a. infer_boundaries()           -- T2 step 1
       b. merge_fields()                -- T2 step 2 (fixes split counters/values)
       c. assign_roles() -> schema      -- T2 step 3, output shape matches
                                           schema.py's DEFAULT_SCHEMA
  5. Writes one combined schema file: {cluster_id: {"count", "schema"}}

Ground truth (schema.py's DEFAULT_SCHEMA) is used ONLY to score the
result afterward, exactly like infer_evaluate.py already does -- it is
never passed into clustering or inference themselves. This keeps the
whole chain's "no spec used" discipline intact end to end.
"""

import argparse
import json
import os
import sys

# Lets this script find paola_t1/ regardless of which folder you run it
# from (repo root or modbus_ids/ itself) -- paola_t1 is a SIBLING of
# modbus_ids, not something on the Python path by default, which is
# exactly the ModuleNotFoundError you'd otherwise hit running this from
# inside modbus_ids.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_THIS_DIR)
for _p in (_THIS_DIR, _REPO_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from pcap_loader import load_pcap
from paola_t1.clustering import MessageTypeClusterer, group_messages
from infer_boundaries import infer_boundaries
from infer_merge import merge_fields
from infer_roles import assign_roles
from schema import DEFAULT_SCHEMA

MIN_CLUSTER_SIZE_FOR_T2 = 8  # below this, byte statistics are too noisy to trust


def true_boundaries(total_len):
    offsets = sorted(f["offset"] for f in DEFAULT_SCHEMA)
    if 0 not in offsets:
        offsets = [0] + offsets
    return [o for o in offsets if o < total_len]


def score_boundaries(predicted, true):
    pred_set, true_set = set(predicted), set(true)
    tp = len(pred_set & true_set)
    fp = len(pred_set - true_set)
    fn = len(true_set - pred_set)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return precision, recall, f1


def run_chain(messages, clusterer_kwargs=None):
    """messages: list of {"raw": bytes, ...}. Returns dict:
    {cluster_id: {"count": int, "length": int, "schema": [...]}}"""
    clusterer = MessageTypeClusterer(**(clusterer_kwargs or {}))
    assignments = clusterer.fit_predict(messages)
    groups = group_messages(messages, assignments)

    results = {}
    for cluster_id, group in sorted(groups.items()):
        if cluster_id == -1:
            results["unassigned"] = {"count": len(group)}
            continue
        if len(group) < MIN_CLUSTER_SIZE_FOR_T2:
            results[str(cluster_id)] = {"count": len(group), "note": "too small for T2"}
            continue

        raws = [m["raw"] for m in group]
        fields, _variability = infer_boundaries(raws)
        fields = merge_fields(raws, fields)
        schema = assign_roles(raws, fields)

        results[str(cluster_id)] = {
            "count": len(group),
            "min_len": min(len(r) for r in raws),
            "max_len": max(len(r) for r in raws),
            "schema": schema,
        }
    return results, clusterer.describe()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcaps", nargs="+", help="one or more real capture files to pool for T1+T2")
    ap.add_argument("--port", type=int, default=502)
    ap.add_argument("--out", default="chained_schema.json")
    args = ap.parse_args()

    messages = []
    for p in args.pcaps:
        msgs = load_pcap(p, modbus_port=args.port, label="unused")
        print(f"{p}: loaded {len(msgs)} messages")
        messages.extend(msgs)
    print(f"Total pooled messages: {len(messages)}\n")

    results, t1_description = run_chain(messages)

    with open(args.out, "w") as f:
        json.dump({"t1": t1_description, "t2_per_cluster": results}, f, indent=2)

    print("--- T1 clusters -> T2 schemas ---")
    for cluster_id, info in results.items():
        if cluster_id == "unassigned" or "schema" not in info:
            print(f"cluster {cluster_id}: count={info['count']} ({info.get('note', 'unassigned')})")
            continue
        print(f"\ncluster {cluster_id}: count={info['count']} len={info['min_len']}..{info['max_len']}")
        for f in info["schema"]:
            print(f"  offset={f['offset']:<3} len={f['len']:<2} role={f['role']:<16} name={f['name']}")

        predicted = sorted(set(fld["offset"] for fld in info["schema"]) | {0})
        true = true_boundaries(info["min_len"])
        precision, recall, f1 = score_boundaries(predicted, true)
        print(f"  boundary score vs ground truth (SCORING ONLY, not used in inference): "
              f"precision={precision:.2f} recall={recall:.2f} f1={f1:.2f}")

    print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()