"""Runs the blind pipeline on an OPC UA capture: T1 clustering -> T2 field boundaries -> merge -> roles.

Uses the Modbus-side T1/T2/role code unmodified; only this glue script is new.
    python3 run_t1_t2_roles.py ../pcaps/opcua/opc_normal_only.pcapng --out /tmp/opc_normal_t2.json

Needs on PYTHONPATH (they live outside this folder):
  clustering.py                        T1 message-type clustering   (branch main: paola_t1/)
  infer_boundaries.py, infer_merge.py, infer_roles.py   T2 + role inference (blind pipeline)
    PYTHONPATH=../paola_t1:/path/to/t2_scripts python3 run_t1_t2_roles.py ...
"""
import json, argparse
from collections import Counter
from pcap_loader_generic import load_tcp_payloads
from clustering import MessageTypeClusterer, group_messages
from infer_boundaries import infer_boundaries
from infer_merge import merge_fields
from infer_roles import assign_roles

ap = argparse.ArgumentParser()
ap.add_argument("pcaps", nargs="+")
ap.add_argument("--port", type=int, default=4840)
ap.add_argument("--min-samples", type=int, default=8)
ap.add_argument("--out", default=None)
a = ap.parse_args()

msgs = []
for p in a.pcaps:
    msgs += load_tcp_payloads(p, a.port)
msgs.sort(key=lambda m: m["ts"])
print(f"{len(msgs)} client->server payloads from {len(a.pcaps)} file(s)")
print("length histogram:", sorted(Counter(len(m['raw']) for m in msgs).items()))

model = MessageTypeClusterer(min_samples=a.min_samples)
assign = model.fit_predict(msgs)
groups = group_messages(msgs, assign)
print("T1 clusters:", {k: len(v) for k, v in sorted(groups.items())})
print("T1 offsets by length:", model.offsets)

out = {}
for cid, g in sorted(groups.items()):
    if cid == -1 or len(g) < 3:
        continue
    raws = [m["raw"] for m in g]
    lens = {len(r) for r in raws}
    fields, var = infer_boundaries(raws)
    merged = merge_fields(raws, fields)
    schema = assign_roles(raws, merged)
    out[cid] = {"count": len(g), "lengths": sorted(lens), "raw_fields": fields, "merged": merged, "schema": schema}
    print(f"\n-- cluster {cid}: n={len(g)} len={sorted(lens)}")
    print("   T2 fields :", fields)
    print("   merged    :", merged)
    print("   roles     :", [(s['offset'], s['len'], s['role']) for s in schema])
if a.out:
    json.dump(out, open(a.out, "w"), indent=1, default=list)
