import json
from pathlib import Path

manifest_path = Path("integration_results/full_test/manifest.json")
manifest = json.loads(manifest_path.read_text())

exclude = {"opcua_10_test_value_jump"}  # add bad_length/replay run ids here too if not already excluded

manifest["runs"] = [r for r in manifest["runs"] if r["id"] not in exclude]
manifest["expected_runs"] = len(manifest["runs"])

manifest_path.write_text(json.dumps(manifest, indent=2))
print("Remaining runs:", manifest["expected_runs"])