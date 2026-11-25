"""
Multi-client / random-attacker Modbus lab built from what's on `main`:
the real pymodbus server (modbus_lab_setup/modbus_lab/modbus_server.py),
the raw-packet format from attacker.py, and the merged generic detector
(modbus_ids/generic_pipeline.py).

Ground truth is matched the SAME way the rest of the project does it
(integrated_ids/run_lab.py, integrated_ids/streams.py): traffic is
captured for real with dumpcap on the loopback interface, not just
logged in-memory at send time. The in-memory EventLog only supplies
labels, matched to the captured packets by exact SHA256 of the payload
plus connection + timestamp -- never trusted directly as "what the
detector saw." This closes the gap from the earlier in-memory-only
version, which skipped the TCP-stream-reconstruction step a real IDS
actually has to do.

Requires dumpcap (Wireshark) and Npcap's loopback capture driver --
Windows only, same as integrated_ids/run_lab.py. If dumpcap isn't
found, pass --no-pcap to fall back to the old in-memory-only mode
(useful for quick iteration on a machine without Npcap, but the result
then reflects detector logic under idealized capture conditions only
-- see the module docstring discussion in the project writeup).

3 masters, each owning one holding register (1, 2, 3), plus a read-only
monitor. One master is randomly selected per test run to misbehave on
its OWN existing connection (insider-threat model). All 7 of
attacker.py's attacks are implemented, each randomized in timing (a
random cycle in a window, not always the exact midpoint) and in its
own parameters (jump size, flood size, bogus function code). Each
attack type runs across SEEDS_PER_ATTACK independent seeds.
"""
import argparse
import random
import shutil
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

# Reused, not reimplemented: the same TCP-stream reconstruction and
# SHA256 ground-truth matching integrated_ids/run_lab.py already uses
# and that was just verified working on real captures.
from integrated_ids.lab import EventLog
from integrated_ids.streams import load_capture, attach_labels

PROTO_ID = 0

# --- Tune these to trade off runtime vs. how much data/how many
# attack samples you get. ---
CYCLES = 300            # messages per role per run (normal + test runs)
SEEDS_PER_ATTACK = 5    # independent randomized instances per attack type
CAPTURE_SECONDS = 15    # dumpcap capture duration per run; must comfortably
                        # exceed how long CYCLES actually takes to run


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
    def __init__(self, port, name, log, log_lock=None):
        self.sock = socket.create_connection(('127.0.0.1', port), timeout=5)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.name, self.log = name, log
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
        # EventLog.add() is the SAME ground-truth log integrated_ids/lab.py
        # uses -- records the raw bytes' SHA256, not the bytes themselves,
        # as what later gets matched against the real captured packets.
        self.log.add(raw, self.session, self.name, label)

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
    m.request(6, role, rng.randint(490, 510), label)
    return False


def _attack_value_jump(m, role, rng, label):
    m.request(3, role, 1, 'normal')
    jump_value = rng.choice([rng.randint(700, 999), rng.randint(0, 200)])
    m.request(6, role, jump_value, label)
    m.request(6, role, rng.randint(495, 505), 'normal')
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


def generate_traffic(port, log, seed, cycles=CYCLES, attack=None):
    """Runs the 3-masters-plus-monitor scenario, logging ground truth into
    `log` (an EventLog). Returns which master was selected (or None)."""
    selected = random.Random(seed).randrange(1, 4) if attack else None
    errors = []

    def worker(role):
        name = f'master_{role}' if role else 'monitor'
        rng = random.Random(seed + 100 * role)
        m = Master(port, name, log)
        attack_cycle = rng.randint(int(cycles * 0.3), int(cycles * 0.7)) if role == selected else -1
        try:
            for i in range(cycles):
                if role == selected and i == attack_cycle:
                    label = 'attack:' + attack
                    try:
                        if ATTACKS[attack](m, role, rng, label):
                            m.close()
                            m = Master(port, name, log)
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
    return selected


def run_captured_scenario(dumpcap, interface, out_dir, run_id, seed, attack=None, cycles=CYCLES):
    """Same pattern as integrated_ids/run_lab.py: start a real dumpcap
    capture on the loopback interface filtered to this run's port BEFORE
    generating any traffic, generate the traffic (which separately logs
    ground truth), then reconstruct the real captured packets and match
    ground truth onto them by SHA256 -- never trust the in-memory log
    directly as what the detector sees."""
    folder = out_dir / run_id
    folder.mkdir(parents=True, exist_ok=True)
    server, port = start_server()
    capture = folder / 'traffic.pcapng'
    log = EventLog()
    command = [dumpcap, '-i', interface, '-f', f'tcp port {port}',
               '-a', f'duration:{CAPTURE_SECONDS}', '-w', str(capture)]
    try:
        with (folder / 'capture.log').open('w') as logfile:
            recorder = subprocess.Popen(command, stdout=logfile, stderr=logfile,
                                         creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            try:
                deadline = time.monotonic() + 5
                while not capture.exists():
                    if recorder.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError(f'Capture did not start; see {folder / "capture.log"}')
                    time.sleep(.05)
                time.sleep(.3)  # let dumpcap actually start sniffing before traffic begins
                selected = generate_traffic(port, log, seed, cycles=cycles, attack=attack)
                log.save(folder / 'events.jsonl')
                if recorder.wait(timeout=CAPTURE_SECONDS + 5) != 0:
                    raise RuntimeError(f'Capture failed; see {folder / "capture.log"}')
            finally:
                if recorder.poll() is None:
                    recorder.terminate()
                    recorder.wait(timeout=5)
    finally:
        server.kill()

    messages, diagnostics = load_capture(capture, port, 'modbus')
    match_stats = attach_labels(messages, log.events)
    if match_stats['unmatched_messages']:
        print(f'  WARNING [{run_id}]: {match_stats["unmatched_messages"]} captured messages '
              f'had no matching ground-truth event (dropped packets or capture start race?)')
    labeled = [m for m in messages if m.get('label', '').startswith(('normal', 'attack:'))]
    return labeled, selected, diagnostics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', default='multi_master_captures')
    parser.add_argument('--dumpcap', default=shutil.which('dumpcap') or r'C:\Program Files\Wireshark\dumpcap.exe')
    parser.add_argument('--interface', default=r'\Device\NPF_Loopback')
    parser.add_argument('--no-pcap', action='store_true',
                         help='skip real packet capture; log raw bytes in-memory only '
                              '(no dumpcap/Npcap needed, but see the module docstring '
                              '-- this tests detector logic under idealized capture '
                              'conditions only, not real TCP-stream reconstruction)')
    args = parser.parse_args()

    if args.no_pcap:
        _main_no_pcap()
        return

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f'CYCLES={CYCLES}, SEEDS_PER_ATTACK={SEEDS_PER_ATTACK}, capturing with {args.dumpcap}')

    train, selected = [], None
    for ordinal, seed in enumerate([4001, 4002]):
        msgs, _, _ = run_captured_scenario(args.dumpcap, args.interface, out_dir,
                                            f'train_{ordinal:02d}', seed)
        train += msgs
    test_normal, _, _ = run_captured_scenario(args.dumpcap, args.interface, out_dir,
                                               'test_normal', 4003)
    for m in train + test_normal:
        m['label'] = 'normal'
    print(f'train={len(train)} test_normal={len(test_normal)}')

    attack_files = []
    for attack_idx, attack in enumerate(ATTACKS):
        for s in range(SEEDS_PER_ATTACK):
            seed = 6000 + attack_idx * 100 + s
            run_id = f'{attack}_{s:02d}'
            msgs, sel, _ = run_captured_scenario(args.dumpcap, args.interface, out_dir,
                                                  run_id, seed, attack=attack)
            attack_files.append((attack, s, msgs))
            print(f'{attack} seed#{s}: selected attacker = master_{sel}, {len(msgs)} captured messages')

    _evaluate(train, test_normal, attack_files)


def _main_no_pcap():
    print(f'(--no-pcap mode: idealized capture conditions only) CYCLES={CYCLES}, '
          f'SEEDS_PER_ATTACK={SEEDS_PER_ATTACK}')
    server, port = start_server()
    try:
        def run(seed, attack=None):
            log = EventLog()
            generate_traffic(port, log, seed, attack=attack)
            return [{'raw': bytes.fromhex(e['raw_hex']), 'ts': e['ts'],
                     'label': e['label'], 'client': e['client'],
                     'session': tuple(e['connection'])} for e in log.events]

        train = run(4001) + run(4002)
        test_normal = run(4003)
        for m in train + test_normal:
            m['label'] = 'normal'
        print(f'train={len(train)} test_normal={len(test_normal)}')

        attack_files = []
        for attack_idx, attack in enumerate(ATTACKS):
            for s in range(SEEDS_PER_ATTACK):
                seed = 6000 + attack_idx * 100 + s
                msgs = run(seed, attack=attack)
                attack_files.append((attack, s, msgs))
                print(f'{attack} seed#{s}: {len(msgs)} messages')

        _evaluate(train, test_normal, attack_files)
    finally:
        server.kill()


def _evaluate(train, test_normal, attack_files):
    profile = build_generic_profile(train)
    print(f'\nInferred {len(profile.schemas)} clusters, write-like: {profile.write_like_clusters}\n')

    all_msgs = list(test_normal)
    for _, _, msgs in attack_files:
        all_msgs += msgs
    struct_alerts = [struct_detect_generic(m['raw'], profile) is not None for m in all_msgs]
    per_type, fpr = evaluate_struct(all_msgs, struct_alerts)
    print_report(f'GENERIC structural (multi-master, random attacker, {SEEDS_PER_ATTACK} seeds/attack)',
                 per_type, fpr)

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


if __name__ == '__main__':
    main()