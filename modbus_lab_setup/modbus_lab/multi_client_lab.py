"""
Random multi-client Modbus scenario.

A run picks a random number of normal clients (all with the stock modbus_client.py
behavior), then randomly designates ONE of them as the attacker. The attacker polls
like everyone else (a compromised host), and at a random moment launches one attack
from attacker.py on fresh connections. Everything random is logged to a ground-truth
JSON so captures can be labeled exactly, even with many long-lived client connections.

    python3 multi_client_lab.py --duration 60 --seed 1
    python3 multi_client_lab.py --min-clients 3 --max-clients 8 --attack random
    python3 multi_client_lab.py --attack value_jump --out-prefix run_value_jump

Capture traffic separately (tcpdump / Wireshark on the server interface), starting the
capture before this script. Outputs: <out-prefix>_truth.json
"""
import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CLIENT = os.path.join(HERE, "modbus_client.py")
ATTACKER = os.path.join(HERE, "attacker.py")
ATTACKS = ["illegal_func", "bad_length", "out_of_range", "replay",
           "read_flood", "write_no_read", "value_jump"]

# Client behavior profiles (hmi / historian / engineer) were removed for now: every normal
# client runs the stock behavior. To add them back, pass per-client --poll-gap, --read-addr,
# --read-count, --write-prob and --write-addr flags to modbus_client.py in client_cmd().


def client_cmd(a, name, start_delay, seed, info_file):
    cmd = [sys.executable, CLIENT, "--host", a.host, "--port", str(a.port),
           "--duration", str(a.duration), "--name", name,
           "--start-delay", str(start_delay), "--info-file", info_file]
    if seed is not None:
        cmd += ["--seed", str(seed)]
    return cmd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5020)
    ap.add_argument("--duration", type=float, default=60.0)
    ap.add_argument("--min-clients", type=int, default=2)
    ap.add_argument("--max-clients", type=int, default=6)
    ap.add_argument("--attack", default="random", choices=ATTACKS + ["random"])
    ap.add_argument("--stagger", type=float, default=0.5, help="max random start offset per client (s)")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--out-prefix", default="scenario")
    a = ap.parse_args()
    if a.min_clients < 1 or a.max_clients < a.min_clients:
        ap.error("need 1 <= min-clients <= max-clients")
    if a.duration < 10:
        ap.error("--duration must be at least 10 s so the attack has normal traffic on both sides")

    rng = random.Random(a.seed)
    n = rng.randint(a.min_clients, a.max_clients)
    attacker_idx = rng.randrange(n)
    attack = rng.choice(ATTACKS) if a.attack == "random" else a.attack
    # attack lands in the middle part of the run so there is normal traffic on both sides
    attack_at = rng.uniform(0.25, 0.65) * a.duration

    tmp = tempfile.mkdtemp(prefix="mbclients_")
    clients, procs = [], []
    for i in range(n):
        name = f"client{i}"
        info = os.path.join(tmp, f"{name}.json")
        delay = rng.uniform(0, a.stagger)
        seed = rng.randrange(1_000_000)
        procs.append(subprocess.Popen(client_cmd(a, name, delay, seed, info)))
        clients.append({"name": name, "role": "attacker" if i == attacker_idx else "normal",
                        "info_file": info})
    print(f"{n} clients, attacker = client{attacker_idx}, attack = {attack} at t+{attack_at:.1f}s")

    t_start = time.time()
    time.sleep(attack_at)
    t0 = time.time()
    atk = subprocess.run([sys.executable, ATTACKER, "--host", a.host, "--port", str(a.port),
                          "--attack", attack], stdout=subprocess.DEVNULL)
    t1 = time.time()
    if atk.returncode != 0:
        print(f"WARNING: attacker.py exited with {atk.returncode}; the attack window in the truth file may be empty")

    for p in procs:
        try:
            p.wait()
        except KeyboardInterrupt:
            p.terminate()

    for c in clients:  # collect each client's long-lived local port
        try:
            c["local_port"] = json.load(open(c.pop("info_file")))["local_port"]
        except Exception:
            c.pop("info_file", None)
            c["local_port"] = None
    shutil.rmtree(tmp, ignore_errors=True)
    truth = {"seed": a.seed, "target_port": a.port, "n_clients": n, "clients": clients,
             "attack": {"name": attack, "attacker_client": f"client{attacker_idx}",
                        "start_ts": t0, "end_ts": t1, "returncode": atk.returncode},
             "run_start_ts": t_start}
    path = f"{a.out_prefix}_truth.json"
    json.dump(truth, open(path, "w"), indent=2)
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
