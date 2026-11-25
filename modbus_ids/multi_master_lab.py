"""
Multi-client / random-attacker Modbus lab built ONLY from what's on
`main`: the real pymodbus server (modbus_lab_setup/modbus_lab/modbus_server.py),
the raw-packet format from attacker.py, and the merged generic detector
(modbus_ids/generic_pipeline.py). No code from Paola's unmerged
integrated_ids branch is used anywhere in this script.

3 masters, each owning one holding register (1, 2, 3), plus a read-only
monitor. One master is randomly selected per test run to misbehave on
its OWN existing connection (insider-threat model). All 7 of
attacker.py's attacks are implemented here, not just the 4 that fit
cleanly into a persistent-connection model -- bad_length needs an
explicit reconnect afterward (see ATTACKS['bad_length'] below) since
lying about the MBAP length field desyncs this connection's framing for
anything sent on it afterward.

Each attack instance is randomized, not templated: timing (which cycle
it fires on, within a window instead of always the midpoint) and the
attack's own parameters (jump size, flood size, bogus function code,
out-of-range quantity) are all drawn from a per-run seeded RNG. Each
attack type is also run across several different seeds (SEEDS_PER_ATTACK)
instead of once, so recall per attack type is a real fraction, not a
single coin flip.
"""
import random
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

# This file must live in modbus_ids/, as a sibling of generic_pipeline.py
# and evaluate.py (same place run_generic_eval.py lives) -- repo root is
# then just the parent folder, wherever that happens to be on disk.
REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / 'modbus_ids'))

from generic_pipeline import build_generic_profile, struct_detect_generic, behavioral_detect_generic
from evaluate import evaluate_struct, print_report, merge_per_type, merge_counts, evaluate_struct_counts

PROTO_ID = 0

# --- Tune these to trade off runtime vs. how much data/how many
# attack samples you get. At the defaults this takes a few minutes. ---
CYCLES = 300            # messages per role per run (normal + test runs)
SEEDS_PER_ATTACK = 5    # independent randomized instances per attack type


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def start_server():
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, str(REPO / 'modbus_lab_setup/modbus_lab/modbus_server.py'),
         '--host', '127.0.0.1', '--port', str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.3):
                return proc, port
        except OSError:
            time.sleep(0.2)
    proc.kill()
    raise RuntimeError('server did not start')


class Master:
    def __init__(self, port, name, log, log_lock):
        self.sock = socket.create_connection(('127.0.0.1', port), timeout=5)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.name, self.log, self.log_lock = name, log, log_lock
        self.tid = random.randrange(1, 20000)
        self.session = (*self.sock.getsockname(), *self.sock.getpeername())

    def _recv_exact(self, n):
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise EOFError
            data += chunk
        return data

    def _log(self, raw, label):
        with self.log_lock:
            self.log.append({'ts': time.time(), 'session': self.session,
                              'client': self.name, 'label': label, 'raw': raw})

    def request(self, func_code, addr, qty_or_value, label='normal'):
        self.tid = (self.tid + 1) % 65536
        pdu = struct.pack('>BHH', func_code, addr, qty_or_value)
        body = struct.pack('>B', 1) + pdu
        raw = struct.pack('>HHH', self.tid, PROTO_ID, len(body)) + body
        self._log(raw, label)
        self.sock.sendall(raw)
        header = self._recv_exact(6)
        _, _, size = struct.unpack('>HHH', header)
        self._recv_exact(size)

    def request_twice_identical(self, func_code, addr, qty_or_value, label, gap=0.2):
        """replay: send the exact same raw bytes (same trans_id included)
        twice in a row -- matches attacker.py's attack_replay, which
        builds one packet and sends that same object twice."""
        self.tid = (self.tid + 1) % 65536
        pdu = struct.pack('>BHH', func_code, addr, qty_or_value)
        body = struct.pack('>B', 1) + pdu
        raw = struct.pack('>HHH', self.tid, PROTO_ID, len(body)) + body
        for i in range(2):
            self._log(raw, label)
            self.sock.sendall(raw)
            header = self._recv_exact(6)
            _, _, size = struct.unpack('>HHH', header)
            self._recv_exact(size)
            if i == 0:
                time.sleep(gap)

    def request_no_response(self, func_code, addr, qty_or_value, label, bad_length):
        """bad_length: lies about the MBAP length field. The server will
        try to read `bad_length` body bytes instead of the ~5 actually
        sent, so it will NOT produce a clean response on this connection
        -- don't wait for one. The caller must reconnect afterward."""
        self.tid = (self.tid + 1) % 65536
        pdu = struct.pack('>BHH', func_code, addr, qty_or_value)
        body = struct.pack('>B', 1) + pdu
        raw = struct.pack('>HHH', self.tid, PROTO_ID, bad_length) + body
        self._log(raw, label)
        self.sock.sendall(raw)

    def raw_flood(self, n, label):
        for _ in range(n):
            self.request(3, 0, 2, label)

    def close(self):
        self.sock.close()


def _attack_illegal_func(m, role, rng, label):
    # Any code never used by normal traffic (which only ever sends 3 or 6).
    code = rng.choice([0x07, 0x0B, 0x11, 0x16, 0x2B, 0x50, 0x61])
    m.request(code, rng.randint(0, 9), rng.randint(0, 9), label)
    return False


def _attack_bad_length(m, role, rng, label):
    m.request_no_response(3, 10, 1, label, bad_length=rng.choice([60, 99, 150, 200]))
    return True  # framing is desynced now -- caller must reconnect


def _attack_out_of_range(m, role, rng, label):
    m.request(3, 10, rng.randint(500, 9999), label)
    return False


def _attack_replay(m, role, rng, label):
    m.request_twice_identical(3, 0, 2, label)
    return False


def _attack_read_flood(m, role, rng, label):
    m.raw_flood(rng.randint(40, 90), label)
    return False


def _attack_write_no_read(m, role, rng, label):
    # Value itself stays in the normal band -- only the missing read
    # before it is supposed to give this one away.
    m.request(6, role, rng.randint(490, 510), label)
    return False


def _attack_value_jump(m, role, rng, label):
    m.request(3, role, 1, 'normal')  # pre-read, so write_no_read doesn't also fire
    jump_value = rng.choice([rng.randint(700, 999), rng.randint(0, 200)])
    m.request(6, role, jump_value, label)
    m.request(6, role, rng.randint(495, 505), 'normal')  # settle back to normal
    return False


ATTACKS = {
    'illegal_func': _attack_illegal_func,
    'bad_length': _attack_bad_length,
    'out_of_range': _attack_out_of_range,
    'replay': _attack_replay,
    'read_flood': _attack_read_flood,
    'write_no_read': _attack_write_no_read,
    'value_jump': _attack_value_jump,
}


def run_scenario(port, seed, cycles=CYCLES, attack=None):
    """Returns the flat list of logged request messages. attack is one of
    None or a key in ATTACKS."""
    log, lock = [], threading.Lock()
    selected = random.Random(seed).randrange(1, 4) if attack else None
    errors = []

    def worker(role):
        name = f'master_{role}' if role else 'monitor'
        rng = random.Random(seed + 100 * role)
        m = Master(port, name, log, lock)
        # Randomized TIMING: a random cycle within the middle 40% of the
        # run, not always the exact midpoint.
        attack_cycle = rng.randint(int(cycles * 0.3), int(cycles * 0.7)) if role == selected else -1
        try:
            for i in range(cycles):
                if role == selected and i == attack_cycle:
                    label = 'attack:' + attack
                    try:
                        if ATTACKS[attack](m, role, rng, label):
                            m.close()
                            m = Master(port, name, log, lock)
                    except Exception as exc:
                        errors.append(f'{name} attack: {exc!r}')
                m.request(3, 0, 2)
                if role and i % 3 == 0:
                    m.request(6, role, rng.randint(490, 510))
                time.sleep(rng.uniform(.02, .04))
        except Exception as exc:
            errors.append(f'{name}: {exc!r}')
        finally:
            m.close()

    threads = [threading.Thread(target=worker, args=(r,)) for r in range(4)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=60)
    if errors:
        raise RuntimeError(errors)
    return log, selected


def main():
    proc, port = start_server()
    try:
        print(f'Server up on {port}  (CYCLES={CYCLES}, SEEDS_PER_ATTACK={SEEDS_PER_ATTACK})')
        train = run_scenario(port, seed=4001)[0] + run_scenario(port, seed=4002)[0]
        test_normal = run_scenario(port, seed=4003)[0]
        for m in train + test_normal:
            m['label'] = 'normal'
        print(f'train={len(train)} test_normal={len(test_normal)}')

        # Several independent, randomized instances per attack type.
        attack_files = []  # kept separate per run for the behavioral (per-file) evaluation
        for attack_idx, attack in enumerate(ATTACKS):
            for s in range(SEEDS_PER_ATTACK):
                # Deterministic, not Python's randomized str hash() -- same
                # seed every run, so results are reproducible run to run.
                seed = 6000 + attack_idx * 100 + s
                msgs, selected = run_scenario(port, seed=seed, attack=attack)
                attack_files.append((attack, s, msgs))
                print(f'{attack} seed#{s}: selected attacker = master_{selected}, {len(msgs)} messages')

        profile = build_generic_profile(train)
        print(f'\nInferred {len(profile.schemas)} clusters, write-like: {profile.write_like_clusters}\n')

        # --- structural: per-message, safe to pool across all runs ---
        all_msgs = list(test_normal)
        for _, _, msgs in attack_files:
            all_msgs += msgs
        struct_alerts = [struct_detect_generic(m['raw'], profile) is not None for m in all_msgs]
        per_type, fpr = evaluate_struct(all_msgs, struct_alerts)
        print_report(f'GENERIC structural (multi-master, random attacker, {SEEDS_PER_ATTACK} seeds/attack)',
                     per_type, fpr)

        # --- behavioral: per-file, NOT merged-then-sorted (see run_generic_eval.py) ---
        per_type_pieces, fp_tn_pieces = [], []
        tn_sorted = sorted(test_normal, key=lambda m: m['ts'])
        reasons = behavioral_detect_generic(tn_sorted, profile)
        alerts = [r is not None for r in reasons]
        pt, fp, tn = evaluate_struct_counts(tn_sorted, alerts)
        per_type_pieces.append(pt); fp_tn_pieces.append((fp, tn))
        for _, _, msgs in attack_files:
            file_sorted = sorted(msgs, key=lambda m: m['ts'])
            reasons = behavioral_detect_generic(file_sorted, profile)
            alerts = [r is not None for r in reasons]
            pt, fp, tn = evaluate_struct_counts(file_sorted, alerts)
            per_type_pieces.append(pt); fp_tn_pieces.append((fp, tn))
        per_type = merge_per_type(per_type_pieces)
        fpr = merge_counts(fp_tn_pieces)
        print_report(f'GENERIC behavioral (multi-master, random attacker, {SEEDS_PER_ATTACK} seeds/attack, per-file)',
                     per_type, fpr)
    finally:
        proc.kill()


if __name__ == '__main__':
    main()