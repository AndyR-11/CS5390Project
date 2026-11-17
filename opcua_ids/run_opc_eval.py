"""
OPC UA counterpart of modbus_ids/run_demo_real_multi.py: runs the structure, statistics
and behavioral detectors against real OPC UA captures and scores them with the SAME
scoring code (modbus_ids/evaluate.py).

    python3 run_opc_eval.py --train ../pcaps/opcua/opc_normal_only.pcapng \\
        --heldout /path/to/second_normal.pcap \\
        ../pcaps/opcua/opc_invalid_node_only.pcapng \\
        ../pcaps/opcua/opc_write_no_read_only.pcapng \\
        ../pcaps/opcua/opc_value_jump_only.pcapng \\
        ../pcaps/opcua/opc_read_flood_only.pcapng \\
        ../pcaps/opcua/opc_session_flood_only.pcapng

Attack file names must look like opc_<attack>_only.pcapng (see opc_labels.ATTACKS).

How scoring is done (and why):
  * Profiles are learned from --train (a clean normal capture).
  * False positives are measured on --heldout, a DIFFERENT normal capture. With only one
    capture a time split would put session teardown (CloseSession/CLO) in the test half
    only, and every detector would "false alarm" on it. If --heldout is omitted the script
    falls back to a 70/30 time split and says so.
  * The last (partial) window of every clean capture is dropped, in training and in false-positive
    scoring, so a capture that simply ends can't look like a rate anomaly.
  * The attack captures contain only the attacker's session and last 0.0-0.2 s, so a 5 s
    statistics window would be almost empty. Each attack is therefore also SPLICED onto the
    held-out normal traffic at message level, giving realistic mixed windows; the structure
    detector is scored on the raw attack file, the behavioral and statistics detectors on
    the spliced stream. Background messages are not re-counted as false positives there.
  * The behavioral detector needs the attacker's whole session (a write is judged against
    the reads before it). The statistics detector is fed only the attack's own messages by
    default (--stats-splice attack-only): splicing a whole extra session adds ~10 handshake
    messages to the window, which trips the rate check whether or not the attack changes the
    rate, and would make the statistics detector look like it detects write_no_read/value_jump.
    Use --stats-splice full-session to see that effect.
"""
import argparse
import importlib.util
import json
import os
from collections import Counter, defaultdict

from opc_loader import load_opc_pcap
from opc_labels import attack_name_from_path, label_attack_messages, splice
import opc_detectors as D

HERE = os.path.dirname(os.path.abspath(__file__))


def _load_modbus_evaluate():
    path = os.path.join(HERE, "..", "modbus_ids", "evaluate.py")
    spec = importlib.util.spec_from_file_location("modbus_evaluate", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


E = _load_modbus_evaluate()


def recall(c):
    return c["tp"] / (c["tp"] + c["fn"]) if (c["tp"] + c["fn"]) else 0.0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("attack_pcaps", nargs="+")
    ap.add_argument("--train", required=True, help="clean normal capture used to learn profiles")
    ap.add_argument("--heldout", action="append", default=[], help="separate clean normal capture(s) for false positives")
    ap.add_argument("--port", type=int, default=4840)
    ap.add_argument("--splice-at", type=float, default=0.5, help="where in the background the attack lands (0-1)")
    ap.add_argument("--stats-splice", choices=["attack-only", "full-session"], default="attack-only",
                    help="what the statistics detector sees of each attack: only its labeled messages (default) "
                         "or the whole attacker session including handshake")
    ap.add_argument("--json", default=None, help="write results to this JSON file")
    a = ap.parse_args()

    train_all = load_opc_pcap(a.train, a.port)
    if a.heldout:
        train = train_all
        heldout = [load_opc_pcap(p, a.port) for p in a.heldout]
    else:
        cut = int(len(train_all) * 0.7)
        train, heldout = train_all[:cut], [train_all[cut:]]
        print("WARNING: no --heldout capture; using a 70/30 time split of the training capture.\n"
              "         Session teardown only appears in the held-out part, so expect false\n"
              "         positives that say nothing about detector quality.\n")
    background = max(heldout, key=len)
    print(f"Training on {len(train)} normal messages; {sum(map(len, heldout))} held-out normal messages "
          f"in {len(heldout)} capture(s).")

    sp, stp, bp = D.build_struct_profile(train), D.build_stats_profile(train), D.build_behavioral_profile(train)
    print("Structure profile:  ", sp)
    print("Behavioral profile: ", bp)
    print("Stats profile:       " + ", ".join(f"{f}={stp.mean[f]:.2f}±{stp.std[f]:.2f}" for f in D.FEATURES))

    attacks = []
    for path in a.attack_pcaps:
        name = attack_name_from_path(path)
        msgs = label_attack_messages(load_opc_pcap(path, a.port, label="normal"), name)
        n_atk = sum(m["label"] != "normal" for m in msgs)
        print(f"{os.path.basename(path)}: {len(msgs)} messages, {n_atk} labeled attack:{name}, {len(msgs) - n_atk} labeled normal")
        stats_src = msgs if a.stats_splice == "full-session" else [m for m in msgs if m["label"] != "normal"]
        attacks.append((name, splice(background, msgs, a.splice_at), splice(background, stats_src, a.splice_at), msgs))

    reasons = {"structure": defaultdict(Counter), "behavioral": defaultdict(Counter), "statistics": defaultdict(Counter)}

    # ---------------- structure: per message, on held-out normal + raw attack files
    fp_tn, pieces = [], []
    for h in heldout:
        rs = [D.struct_detect(m, sp) for m in h]
        pt, fp, tn = E.evaluate_struct_counts(h, [r is not None for r in rs])
        fp_tn.append((fp, tn))
        for r in rs:
            if r:
                reasons["structure"]["FALSE_POSITIVE"][r] += 1
    for name, _, _, msgs in attacks:
        rs = [D.struct_detect(m, sp) for m in msgs]
        pt, fp, tn = E.evaluate_struct_counts(msgs, [r is not None for r in rs])
        pieces.append(pt)
        fp_tn.append((fp, tn))
        for m, r in zip(msgs, rs):
            if r:
                reasons["structure"]["FP" if m["label"] == "normal" else name][r] += 1
    res_struct = (E.merge_per_type(pieces), E.merge_counts(fp_tn))
    E.print_report("Structure-based detector (per message)", *res_struct)

    # ---------------- statistics: per window
    fp_tn, pieces = [], []
    for h in heldout:
        ws = D.windows_from_messages(h, drop_partial_tail=True)   # a capture just ending is not an anomaly
        als = [D.stats_detect(w, stp) for w in ws]
        pt, fp, tn = E.evaluate_windows_counts(ws, [x[0] for x in als])
        fp_tn.append((fp, tn))
    for name, _, stats_mixed, _ in attacks:
        ws = [w for w in D.windows_from_messages(stats_mixed)
              if any(m["label"] != "normal" for m in w)]              # only windows holding the attack
        als = [D.stats_detect(w, stp) for w in ws]
        pt, _, _ = E.evaluate_windows_counts(ws, [x[0] for x in als])
        pieces.append(pt)
        for x in als:
            reasons["statistics"][name].update(x[1] if x[0] else ["(no alert)"])
    res_stats = (E.merge_per_type(pieces), E.merge_counts(fp_tn))
    E.print_report(f"Statistics-only baseline (per 5 s window, {a.stats_splice} spliced into normal)", *res_stats)

    # ---------------- behavioral: per message, stateful
    fp_tn, pieces = [], []
    for h in heldout:
        rs = D.behavioral_detect(h, bp)
        pt, fp, tn = E.evaluate_struct_counts(h, [r is not None for r in rs])
        fp_tn.append((fp, tn))
        for r in rs:
            if r:
                reasons["behavioral"]["FALSE_POSITIVE"][r] += 1
    for name, mixed, _, _ in attacks:
        rs = D.behavioral_detect(mixed, bp)
        own = [(m, r) for m, r in zip(mixed, rs) if m["src"] == "atk"]     # background FPs counted above
        pt, fp, tn = E.evaluate_struct_counts([m for m, _ in own], [r is not None for _, r in own])
        pieces.append(pt)
        fp_tn.append((fp, tn))
        for m, r in own:
            if r:
                reasons["behavioral"]["FP" if m["label"] == "normal" else name][r] += 1
    res_beh = (E.merge_per_type(pieces), E.merge_counts(fp_tn))
    E.print_report("Behavioral detector (per message, per-connection state)", *res_beh)

    # ---------------- summary matrix
    print("\n--- Recall by attack and detector ---")
    print("(structure and behavioral are per message; statistics is per window)")
    print(f"{'attack':<16}{'structure':<12}{'statistics':<12}{'behavioral':<12}")
    summary = {}
    for name, _, _, _ in attacks:
        r = [recall(res[0].get(name, {"tp": 0, "fn": 0})) for res in (res_struct, res_stats, res_beh)]
        summary[name] = dict(zip(("structure", "statistics", "behavioral"), r))
        print(f"{name:<16}{r[0]:<12.2f}{r[1]:<12.2f}{r[2]:<12.2f}")
    print(f"{'false pos rate':<16}{res_struct[1]:<12.3f}{res_stats[1]:<12.3f}{res_beh[1]:<12.3f}")

    print("\n--- Why alerts fired ---")
    for det, per in reasons.items():
        for who, c in sorted(per.items()):
            print(f"  {det:<11} {who:<14} {dict(c)}")

    if a.json:
        out = {"recall": summary,
               "false_positive_rate": dict(zip(("structure", "statistics", "behavioral"),
                                              (res_struct[1], res_stats[1], res_beh[1]))),
               "reasons": {d: {k: dict(v) for k, v in per.items()} for d, per in reasons.items()}}
        with open(a.json, "w") as f:
            json.dump(out, f, indent=2)
        print(f"\nWrote {a.json}")


if __name__ == "__main__":
    main()
