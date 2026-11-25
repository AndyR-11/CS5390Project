import json
from pathlib import Path
from integrated_ids.streams import load_capture
from integrated_ids.evaluate import read_events

run_dir = Path("integration_results/full_test")
run_id = "opcua_12_test_write_no_read"
manifest = json.loads((run_dir / "manifest.json").read_text())
run = next(r for r in manifest["runs"] if r["id"] == run_id)

messages, diagnostics = load_capture(run_dir / run["pcap"], run["port"], run["protocol"])
events = read_events(run_dir / run["events"])

print("capture_seconds (configured):", run.get("capture_seconds"))
print("event ts range:  ", min(e["ts"] for e in events), "to", max(e["ts"] for e in events))
print("message ts range:", min(m["ts"] for m in messages), "to", max(m["ts"] for m in messages))
print("num events:", len(events), "num messages:", len(messages))

# how many events fall after the last captured message?
last_msg_ts = max(m["ts"] for m in messages)
tail = [e for e in events if e["ts"] > last_msg_ts]
print("events logged after last captured message:", len(tail))
if tail:
    print("earliest such tail event ts - last msg ts =", min(e["ts"] for e in tail) - last_msg_ts)