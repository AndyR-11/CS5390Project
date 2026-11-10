"""
Generic (schema-agnostic) structural + behavioral detection, built on
top of an INFERRED schema (T1 clusters + T2 fields) instead of a
hand-written one. Same spirit as detector_struct.py/detector_behavioral.py,
rewritten to key off field ROLES (constant/variable/counter) instead of
hardcoded Modbus field NAMES (func_code, start_addr, value) -- because
the inferred schema has no such names, only generic field_0/field_1/...
with roles.

This is what actually answers the project's core question: does
detection still work when the schema comes from blind inference
instead of being handed to you? Train/test split and scoring reuse
evaluate.py unchanged -- only HOW the alert is produced differs, not
how it's scored, so numbers are directly comparable to the hand-written
baseline in paola_t1/results/existing_detectors.txt.
"""

import os
import sys

# Same path-finding as chain_t1_t2.py: paola_t1 is a SIBLING of
# modbus_ids, not on the Python path by default, so this file needs to
# add the repo root itself regardless of which folder it's run from.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_THIS_DIR)
for _p in (_THIS_DIR, _REPO_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from paola_t1.clustering import MessageTypeClusterer, group_messages
from infer_boundaries import infer_boundaries
from infer_merge import merge_fields
from infer_roles import assign_roles

READ_WINDOW_SEC = 5.0


def _field_value(raw, offset, length):
    return int.from_bytes(raw[offset:offset + length], "big")


class GenericProfile:
    def __init__(self):
        self.clusterer = None
        self.schemas = {}            # cluster_id -> schema (list of field dicts)
        self.field_profiles = {}     # cluster_id -> {field_name: {"role","value" or "min"/"max"}}
        self.write_like_clusters = set()   # clusters with a non-constant (variable) field
        self.max_step = {}           # cluster_id -> learned max step for its variable field
        self.last_value_from_training = {}  # cluster_id -> last variable-field value seen in training


def build_generic_profile(train_messages, min_cluster_size=8):
    """Fits T1 (clustering) + T2 (boundary/merge/role inference) + a
    simple value profile per field, ALL from training data only -- the
    inferred schema and the "what's normal" ranges are learned together,
    exactly like build_struct_profile does for the hand-written case."""
    profile = GenericProfile()
    clusterer = MessageTypeClusterer(min_samples=min_cluster_size)
    assignments = clusterer.fit_predict(train_messages)
    profile.clusterer = clusterer
    groups = group_messages(train_messages, assignments)

    for cluster_id, group in groups.items():
        if cluster_id == -1 or len(group) < min_cluster_size:
            continue
        raws = [m["raw"] for m in group]
        fields, _variability = infer_boundaries(raws)
        fields = merge_fields(raws, fields)
        schema = assign_roles(raws, fields)
        profile.schemas[cluster_id] = schema

        field_profile = {}
        variable_field = None
        for f in schema:
            vals = [_field_value(r, f["offset"], f["len"]) for r in raws]
            if f["role"] == "constant":
                field_profile[f["name"]] = {"role": "constant", "value": vals[0]}
            elif f["role"] == "counter":
                field_profile[f["name"]] = {"role": "counter"}
            else:  # "variable" or "low_variability"
                field_profile[f["name"]] = {"role": f["role"], "min": min(vals), "max": max(vals)}
                variable_field = f
        profile.field_profiles[cluster_id] = field_profile

        if variable_field is not None:
            profile.write_like_clusters.add(cluster_id)
            group_sorted = sorted(group, key=lambda m: m["ts"])
            vseq = [_field_value(m["raw"], variable_field["offset"], variable_field["len"])
                    for m in group_sorted]
            steps = [abs(vseq[i + 1] - vseq[i]) for i in range(len(vseq) - 1)]
            profile.max_step[cluster_id] = int(max(steps) * 1.5) if steps else 50
            # Seed value: the LAST value seen in TRAINING for this cluster.
            # Lets value_jump be checked on the very first write-like
            # message in a held-out file, instead of silently skipping it
            # for lack of a prior value to compare against (see
            # behavioral_detect_generic's initial_last_value param).
            profile.last_value_from_training[cluster_id] = vseq[-1]

    return profile


def struct_detect_generic(raw, profile):
    """Per-message structural check, generic version of detector_struct.py's
    struct_detect(). Returns a reason string or None."""
    assignment = profile.clusterer.predict([{"raw": raw}])[0]
    if assignment == -1 or assignment not in profile.schemas:
        return "unknown_message_type"

    schema = profile.schemas[assignment]
    fp = profile.field_profiles[assignment]
    for f in schema:
        info = fp[f["name"]]
        if info["role"] == "constant":
            val = _field_value(raw, f["offset"], f["len"])
            if val != info["value"]:
                return f"constant_violation:{f['name']}"
        elif info["role"] in ("variable", "low_variability"):
            val = _field_value(raw, f["offset"], f["len"])
            if not (info["min"] <= val <= info["max"]):
                return f"range_violation:{f['name']}"
        # "counter" role: no structural check (same as original -- counters
        # aren't range-checked, only ever examined for sequence behavior)
    return None


def behavioral_detect_generic(messages, profile, read_window_sec=READ_WINDOW_SEC, seed_from_training=True):
    """
    Generic version of detector_behavioral.py's behavioral_detect().
    "Read" vs "write" isn't known by name here -- it's inferred as:
    a cluster with NO variable field = read-like (nothing changes, just
    polls); a cluster WITH a variable field = write-like (something is
    being set). This matches your lab's actual two clusters (reads have
    no variable field once address/quantity are fixed; writes do,
    because the value changes) but is a real approximation worth being
    honest about -- it depends on reads never touching a varying field,
    which stops holding once e.g. multiple addresses are read.

    seed_from_training: if True (default), last_value_by_cluster starts
    pre-loaded from profile.last_value_from_training instead of empty.
    Lets value_jump be evaluated on the very first write-like message of
    a short, separately-evaluated file (see run_generic_eval.py's
    per-file behavioral evaluation) instead of silently having nothing
    to compare against. Does NOT help write_no_read -- that gap is a
    separate, address-granularity limitation, not a missing-history one
    (see generic struct/behavioral comparison write-up).
    """
    results = [None] * len(messages)
    read_like_clusters = set(profile.schemas.keys()) - profile.write_like_clusters
    last_read_ts = None
    last_value_by_cluster = dict(profile.last_value_from_training) if seed_from_training else {}

    assignments = [profile.clusterer.predict([{"raw": m["raw"]}])[0] for m in messages]

    for i, (m, assignment) in enumerate(zip(messages, assignments)):
        if assignment == -1 or assignment not in profile.schemas:
            # Doesn't match any known T1 cluster at all -- e.g. a write
            # with a value so extreme it breaks the cluster's own byte
            # signature. struct_detect_generic already flags this case;
            # behavioral must too, or messages like this are silently
            # invisible to it (found by testing against value_jump.pcapng
            # -- its attack messages come back assignment=-1, and were
            # being skipped entirely before this branch existed).
            results[i] = "unknown_message_type"
        elif assignment in read_like_clusters:
            last_read_ts = m["ts"]
        elif assignment in profile.write_like_clusters:
            schema = profile.schemas[assignment]
            variable_field = next(f for f in schema if f["role"] in ("variable", "low_variability"))
            val = _field_value(m["raw"], variable_field["offset"], variable_field["len"])

            if last_read_ts is None or (m["ts"] - last_read_ts) > read_window_sec:
                results[i] = "write_no_read"
            elif assignment in last_value_by_cluster:
                step = abs(val - last_value_by_cluster[assignment])
                if step > profile.max_step.get(assignment, 50):
                    results[i] = "value_jump"
            last_value_by_cluster[assignment] = val

    return results