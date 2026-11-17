"""Sweeps T2 jump_threshold and merge max_merged_len against the ReadRequest ground truth
(see eval_t2_boundaries.py). Finding: no setting beats the defaults (best F1 0.28).
    python3 sweep_t2_params.py

Needs on PYTHONPATH (they live outside this folder):
  clustering.py                        T1 message-type clustering   (branch main: paola_t1/)
  infer_boundaries.py, infer_merge.py, infer_roles.py   T2 + role inference (blind pipeline)
    PYTHONPATH=../paola_t1:/path/to/t2_scripts python3 sweep_t2_params.py ...
"""
import glob
import os
from pcap_loader_generic import load_tcp_payloads
from infer_boundaries import infer_boundaries
from infer_merge import merge_fields
from eval_t2_boundaries import prf
P=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pcaps", "opcua") + os.sep
def reads(files):
    out=[]
    for f in files: out+=[m for m in load_tcp_payloads(f,4840) if len(m['raw'])==93]
    out.sort(key=lambda m:m['ts']); return [m['raw'] for m in out]
sets={"normal":reads([P+"opc_normal_only.pcapng"]),"pooled":reads(sorted(glob.glob(P+"*_only.pcapng")))}
rows=[]
for name,raws in sets.items():
    for jt in [0.02,0.04,0.06,0.08,0.10,0.12,0.15,0.2,0.25,0.3]:
        f,_=infer_boundaries(raws,jt)
        for ml in [2,3,4,8,16]:
            st=[o for o,_ in merge_fields(raws,f,max_merged_len=ml)]
            p,r,F=prf(st); rows.append((F,name,jt,ml,round(p,2),round(r,2),st))
rows.sort(key=lambda x:-x[0])
for name in sets:
    print("==",name,"top 6")
    for F,n,jt,ml,p,r,st in [x for x in rows if x[1]==name][:6]: print(f"  F1={F:.2f} P={p} R={r} jt={jt} max_len={ml} starts={st}")
    base=[x for x in rows if x[1]==name and x[2]==0.12 and x[3]==4][0]; print(f"  default (0.12,4): F1={base[0]:.2f}")
    print("  distinct F1 values over grid:",sorted({round(x[0],2) for x in rows if x[1]==name},reverse=True))
