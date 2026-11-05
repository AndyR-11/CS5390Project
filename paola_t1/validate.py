"""Reproducible offline validation. Modbus knowledge is used ONLY for scoring.

Run from the repository root: python -m paola_t1.validate
"""
from collections import Counter, defaultdict
import json
from pathlib import Path
import random
import subprocess
import sys

from .clustering import MessageTypeClusterer
from .run_t1 import load_payloads


def score(model, messages):
    assignments = model.predict(messages)
    matrix = defaultdict(Counter)
    labels = []
    for m, c in zip(messages, assignments):
        # Ground truth oracle for this Modbus-only diagnostic, AFTER clustering.
        truth = m["raw"][7]
        labels.append(truth)
        matrix[c][truth] += 1
    known = sum(c != -1 for c in assignments)
    majority = sum(max(row.values()) for c, row in matrix.items() if c != -1)
    choose2 = lambda n: n * (n - 1) // 2
    cells = Counter(zip(assignments, labels))
    # Exclude unknowns from pair scoring and report coverage explicitly.
    cells = {k: n for k, n in cells.items() if k[0] != -1}
    rows, cols = Counter(), Counter()
    for (c, truth), n in cells.items():
        rows[c] += n
        cols[truth] += n
    same_both = sum(choose2(n) for n in cells.values())
    same_cluster = sum(choose2(n) for n in rows.values())
    same_truth = sum(choose2(n) for n in cols.values())
    return {"count": len(messages), "known_coverage": known / len(messages),
            "purity_known_only": majority / known if known else None,
            "pair_precision_known_only": same_both / same_cluster if same_cluster else None,
            "pair_recall_known_only": same_both / same_truth if same_truth else None,
            "cluster_vs_function_code": dict(matrix)}


def main():
    root = Path(__file__).resolve().parents[1]
    out = root / "paola_t1/results"
    out.mkdir(exist_ok=True)
    sys.path.insert(0, str(root / "modbus_ids"))
    from traffic_sim import generate_normal
    random.seed(5390)
    synthetic = generate_normal(4000)
    real = load_payloads(root / "modbus_ids/normal_traffic.pcapng", 502)
    results = {"seed": 5390, "note": "Function code oracle is evaluation-only; not attack detection accuracy.",
               "experiments": []}
    for name, messages in [("synthetic", synthetic), ("real_modbus", real)]:
        split = int(.7 * len(messages))
        for entropy in (.75, 1.5, 2.5):
            model = MessageTypeClusterer(max_entropy=entropy).fit(messages[:split])
            results["experiments"].append({"dataset": name, "entropy": entropy,
                "model": model.describe(), "held_out": score(model, messages[split:])})
    results["real_modbus_framing_check"] = {
        "payloads": len(real),
        "mbap_length_mismatch": sum(len(m["raw"]) < 8 or
            int.from_bytes(m["raw"][4:6], "big") + 6 != len(m["raw"]) for m in real),
        "note": "Necessary length check only; does not prove absence of retransmissions."}
    (out / "validation.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    baseline = subprocess.run([sys.executable, "run_demo_real_multi.py", "normal_traffic.pcapng",
        "illegal_func.pcapng", "bad_length.pcapng", "out_of_range.pcapng", "replay.pcapng",
        "read_flood.pcapng", "write_no_read.pcapng", "value_jump.pcapng"],
        cwd=root / "modbus_ids", capture_output=True, text=True, check=True)
    (out / "existing_detectors.txt").write_text(
        "PROVISIONAL: unchanged existing pipeline, heuristic port-based labels, hardcoded schema.\n"
        + baseline.stdout + baseline.stderr, encoding="utf-8")
    for exp in results["experiments"]:
        print(exp["dataset"], exp["entropy"], exp["held_out"])
    print(results["real_modbus_framing_check"])


if __name__ == "__main__":
    main()
