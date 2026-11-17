"""Scores T2 field-boundary inference on OPC UA against a hand-decoded layout of the 93-byte
ReadRequest (the dominant message in the normal capture). Exact-offset precision/recall/F1.
    python3 eval_t2_boundaries.py

Needs on PYTHONPATH (they live outside this folder):
  clustering.py                        T1 message-type clustering   (branch main: paola_t1/)
  infer_boundaries.py, infer_merge.py, infer_roles.py   T2 + role inference (blind pipeline)
    PYTHONPATH=../paola_t1:/path/to/t2_scripts python3 eval_t2_boundaries.py ...
"""
import glob

import os
from pcap_loader_generic import load_tcp_payloads
from clustering import MessageTypeClusterer, group_messages
from infer_boundaries import infer_boundaries
from infer_merge import merge_fields
HERE = os.path.dirname(os.path.abspath(__file__))
PCAPS = os.path.join(HERE, "..", "pcaps", "opcua")
# ground truth field starts for the 93-byte ReadRequest (decoded by hand from OPC UA binary spec)
GT = [0,3,4,8,12,16,20,24,28,32,40,44,48,52,56,59,67,71,75,79,83,87,89]
def prf(pred, tol=0):
    P=set(pred)-{0}; G=set(GT)-{0}
    tp=sum(any(abs(p-g)<=tol for g in G) for p in P)
    tpg=sum(any(abs(p-g)<=tol for p in P) for g in G)
    pr=tp/len(P) if P else 0; rc=tpg/len(G)
    return pr, rc, (2*pr*rc/(pr+rc) if pr+rc else 0)
def run(files, label, min_samples=8):
    msgs=[]
    for f in files: msgs+=load_tcp_payloads(f,4840)
    msgs.sort(key=lambda m:m['ts'])
    a=MessageTypeClusterer(min_samples=min_samples).fit_predict(msgs); g=group_messages(msgs,a)
    print(f"\n== {label}: {len(msgs)} msgs, clusters { {k:len(v) for k,v in sorted(g.items())} }")
    # pooled 93-byte reads (what a T1 that merged reads would give) + per cluster
    for cid,grp in sorted(g.items()):
        raws=[m['raw'] for m in grp]
        if cid==-1 or len(raws)<3 or len({len(r) for r in raws})>1 or len(raws[0])!=93: 
            print(f"  cluster {cid}: n={len(raws)} lens={sorted({len(r) for r in raws})} (not a 93-byte read; skipped in scoring)"); continue
        f,_=infer_boundaries(raws); m_=merge_fields(raws,f)
        st=[o for o,_ in m_]
        print(f"  cluster {cid}: n={len(raws)} merged starts={st}  P/R/F1 exact={tuple(round(x,2) for x in prf(st))}  tol1={round(prf(st,1)[2],2)}")
    allreads=[m['raw'] for m in msgs if len(m['raw'])==93]
    f,_=infer_boundaries(allreads); m_=merge_fields(allreads,f); st=[o for o,_ in m_]
    print(f"  ALL 93-byte pooled (no T1): n={len(allreads)} starts={st} P/R/F1={tuple(round(x,2) for x in prf(st))}")
if __name__=="__main__":
  P=PCAPS+os.sep
  run([P+"opc_normal_only.pcapng"],"normal only")
  run(sorted(glob.glob(P+"*_only.pcapng")),"all *_only captures pooled")
