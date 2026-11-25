import json
from pathlib import Path
from integrated_ids.streams import load_capture, attach_labels
from integrated_ids.evaluate import read_events

manifest = json.loads(Path("integration_results/full_test/manifest.json").read_text())
base = Path("integration_results/full_test")

bad = []
for run in manifest["runs"]:
    capture = base / run["pcap"]
    messages, diagnostics = load_capture(capture, run["port"], run["protocol"])
    labels = attach_labels(messages, read_events(base / run["events"]))
    if labels["unmatched_messages"] or labels["unmatched_events"]:
        bad.append((run["id"], run["protocol"], labels["unmatched_messages"], labels["unmatched_events"]))

print(f"{len(bad)} / {len(manifest['runs'])} runs have mismatches\n")
for r in bad:
    print(r)