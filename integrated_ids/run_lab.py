"""Capture independent loopback runs; never connects to an external host."""
import argparse
import asyncio
import hashlib
import json
import logging
import random
from pathlib import Path
import shutil
import socket
import subprocess
import time

from .lab import EventLog, start_server, run_modbus, run_opc


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True)
    parser.add_argument('--dumpcap', default=shutil.which('dumpcap') or r'C:\Program Files\Wireshark\dumpcap.exe')
    parser.add_argument('--interface', default=r'\Device\NPF_Loopback')
    parser.add_argument('--protocol', choices=['modbus', 'opcua', 'both'], default='both')
    parser.add_argument('--seed', type=int, default=5390)
    parser.add_argument('--capture-seconds', type=int, default=8)
    parser.add_argument('--cycles', type=int, default=120)
    args = parser.parse_args()
    out = Path(args.out).resolve()
    if out.exists():
        raise SystemExit('Use a new output directory to preserve prior experiments')
    out.mkdir(parents=True)
    manifest = {'seed': args.seed, 'capture_method': 'dumpcap Npcap loopback; real socket traffic',
                'runs': [], 'protocol_units': {'modbus': 'MBAP application request', 'opcua': 'UA TCP chunk'},
                'roles': {'masters': 3, 'monitor': 1}, 'complete': False,
                'expected_runs': 20 if args.protocol == 'both' else 10}
    (out/'manifest.json').write_text(json.dumps(manifest, indent=2))
    protocols = ['modbus', 'opcua'] if args.protocol == 'both' else [args.protocol]
    logging.getLogger('asyncua').setLevel(logging.ERROR)
    for protocol in protocols:
        schedule = [('train', None), ('train', None), ('validation', None),
                    ('validation', None), ('test', None), ('test', None)]
        schedule += [('test', attack) for attack in
                     ['illegal_func' if protocol == 'modbus' else 'invalid_node',
                      'value_jump', 'write_no_read', 'read_flood']]
        for ordinal, (split, attack) in enumerate(schedule):
            run_id = f'{protocol}_{ordinal:02d}_{split}_{attack or "normal"}'
            folder = out/run_id
            folder.mkdir()
            server = start_server()
            port = server.server_address[1] if protocol == 'modbus' else free_port()
            capture = folder/'traffic.pcapng'
            events = EventLog()
            seed = args.seed+ordinal
            cycles = max(12, args.cycles+random.Random(seed).randint(-12, 12))
            command = [args.dumpcap, '-i', args.interface, '-f', f'tcp port {port}',
                       '-a', f'duration:{args.capture_seconds}', '-w', str(capture)]
            print(f'Capturing {run_id} on loopback port {port}', flush=True)
            try:
                with (folder/'capture.log').open('w') as log:
                    recorder = subprocess.Popen(command, stdout=log, stderr=log,
                                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
                    try:
                        deadline = time.monotonic()+5
                        while not capture.exists():
                            if recorder.poll() is not None or time.monotonic() > deadline:
                                raise RuntimeError('Capture did not start; see capture.log')
                            time.sleep(.05)
                        time.sleep(.3)
                        if protocol == 'modbus':
                            details = run_modbus(port, events, seed, attack, cycles=cycles)
                        else:
                            details = asyncio.run(run_opc(port, server.server_address[1], events, seed, attack, cycles=cycles))
                        events.save(folder/'events.jsonl')
                        if recorder.wait(timeout=args.capture_seconds+5) != 0:
                            raise RuntimeError('Capture failed; see capture.log')
                    finally:
                        if recorder.poll() is None:
                            recorder.terminate()
                            recorder.wait(timeout=5)
            finally:
                server.shutdown()
                server.server_close()
            # Normalize console progress carriage returns for portable text logs.
            log_path = folder/'capture.log'
            log_path.write_text('\n'.join(line.rstrip() for line in
                                           log_path.read_text().splitlines())+'\n', encoding='utf-8')
            record = {'id': run_id, 'protocol': protocol, 'split': split,
                      'attack': attack, 'port': port, 'cycles_per_client': cycles,
                      'capture_seconds': args.capture_seconds, 'pcap': f'{run_id}/traffic.pcapng',
                      'events': f'{run_id}/events.jsonl', 'details': details,
                      'sha256': hashlib.sha256(capture.read_bytes()).hexdigest()}
            manifest['runs'].append(record)
            (out/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    versions = subprocess.check_output([__import__('sys').executable, '-m', 'pip', 'freeze'], text=True)
    (out/'environment.txt').write_text(versions)
    manifest['complete'] = True
    (out/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print(f'Completed {len(manifest["runs"])} captures: {out}', flush=True)
    from .evaluate import evaluate
    result = evaluate(out/'manifest.json')
    print(json.dumps({p: r['aggregate']['hybrid_combined']
                      for p, r in result['protocols'].items()}, indent=2), flush=True)


if __name__ == '__main__':
    main()
