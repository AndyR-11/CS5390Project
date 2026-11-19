"""Frozen train/validation/test evaluation with log-verified message labels."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from .streams import load_capture, attach_labels, read_events
from .detection import fit, score, rate_scores, normal_threshold, counts, fixed_windows
from .behavior import decode, fit_behavior, predict_behavior


def ownership_audit(messages, protocol):
    writes = {}
    monitor_reads = 0
    for message in messages:
        event = decode(message['raw'], protocol)
        if not event:
            continue
        client = message['client']
        if client == 'monitor':
            if event.get('writes'):
                raise ValueError('Monitor issued a write')
            monitor_reads += event['kind'] == 'read'
        if message['label'] != 'normal':
            continue
        for write in event.get('writes', []):
            if not client.startswith('master_'):
                raise ValueError('Unexpected writer')
            master = int(client.split('_')[1])
            expected = master if protocol == 'modbus' else f'ns=2;s=HR{master}'
            if write['node'] != expected:
                raise ValueError('Normal master wrote outside its owned register')
            writes[client] = writes.get(client, 0)+1
    if len(writes) != 3 or not monitor_reads:
        raise ValueError('Capture does not demonstrate three writers and a read-only monitor')
    return {'normal_writes_by_master': writes, 'monitor_read_requests': monitor_reads,
            'ownership_conflicts': 0}


def process_evidence(path, port):
    responses, diagnostics = load_capture(path, port, 'modbus', direction='response')
    snapshots = []
    for message in responses:
        raw = message['raw']
        if len(raw) == 17 and raw[7:9] == bytes([3, 8]):
            snapshots.append(struct.unpack('>4H', raw[9:]))
    return {'four_register_read_responses': len(snapshots),
            'observed_ranges': [{'register': i, 'min': min(s[i] for s in snapshots),
                                 'max': max(s[i] for s in snapshots),
                                 'distinct_values': len({s[i] for s in snapshots})}
                                for i in range(4)] if snapshots else [],
            'response_reassembly': diagnostics}


def evaluate(manifest_path):
    path = Path(manifest_path)
    manifest = json.loads(path.read_text())
    if not manifest.get('complete') or len(manifest['runs']) != manifest.get('expected_runs'):
        raise ValueError('Capture run is incomplete; evaluation is not final')
    seen_ids, seen_hashes = set(), set()
    loaded = []
    for run in manifest['runs']:
        if run['split'] not in ('train', 'validation', 'test'):
            raise ValueError('Unrecognized split')
        capture = path.parent/run['pcap']
        digest = hashlib.sha256(capture.read_bytes()).hexdigest()
        if digest != run['sha256'] or digest in seen_hashes or run['id'] in seen_ids:
            raise ValueError('Changed or duplicated capture; refusing split leakage')
        seen_ids.add(run['id'])
        seen_hashes.add(digest)
        messages, diagnostics = load_capture(capture, run['port'], run['protocol'])
        labels = attach_labels(messages, read_events(path.parent/run['events']))
        if not messages or labels['unmatched_messages'] or labels['unmatched_events']:
            raise ValueError(f'{run["id"]}: incomplete event matching {labels}')
        if diagnostics['quarantined_connections'] or diagnostics['framing_errors']:
            raise ValueError(f'{run["id"]}: reconstruction failed {diagnostics}')
        if run['split'] != 'test' and any(m['label'] != 'normal' for m in messages):
            raise ValueError('Only clean normal traffic may train or calibrate')
        loaded.append((run, messages, diagnostics, labels))
    output = {'unit': 'per reconstructed request/frame', 'validation_fpr_target': .05,
              'protocols': {}, 'capture_audit': {r['id']: {'tcp': d, 'labels': l,
                                                         'ownership': ownership_audit(m, r['protocol'])}
                                              for r, m, d, l in loaded}}
    for run, _, _, _ in loaded:
        if run['protocol'] == 'modbus':
            output['capture_audit'][run['id']]['process'] = process_evidence(
                path.parent/run['pcap'], run['port'])
    for protocol in sorted({r['protocol'] for r, _, _, _ in loaded}):
        runs = [(r, m) for r, m, _, _ in loaded if r['protocol'] == protocol]
        train = [m for r, msgs in runs if r['split'] == 'train' for m in msgs]
        validation_runs = [(r, m) for r, m in runs if r['split'] == 'validation']
        test_runs = [(r, m) for r, m in runs if r['split'] == 'test']
        if not train or not validation_runs or not test_runs:
            raise ValueError('Each protocol needs independent train, validation and test runs')
        artifact, model = fit(train)
        reference = fit_behavior(train, protocol)
        val_structure, val_rates, val_window_rates = [], [], []
        for _, messages in validation_runs:
            val_structure += [s['score'] for s in score(messages, artifact, model)]
            val_rates += rate_scores(messages)
            val_window_rates += [w['rate'] for w in fixed_windows(messages)]
        structural_threshold = normal_threshold(val_structure)
        rate_threshold = normal_threshold(val_rates)
        window_threshold = normal_threshold(val_window_rates)
        protocol_result = {'train_count': len(train), 'validation_count': len(val_structure),
                           'thresholds': {'structure': structural_threshold, 'rate': rate_threshold,
                                          'fixed_window_rate': window_threshold},
                           'training_decode_errors': reference['training_decode_errors'],
                           'per_run': {}, 'aggregate': {}}
        all_messages = []
        all_flags = {k: [] for k in ['inferred_structure', 'rate_only', 'blind_combined',
                                    'protocol_aware_behavior', 'hybrid_combined', 'uncalibrated_structure']}
        predictions = []
        all_windows, all_window_rate, all_window_hybrid = [], [], []
        for run, messages in test_runs:
            scored = score(messages, artifact, model)
            structural = [s['score'] > structural_threshold for s in scored]
            rate = [s > rate_threshold for s in rate_scores(messages)]
            behavior_reasons, decode_errors = predict_behavior(messages, reference, protocol)
            behavior = [bool(r) for r in behavior_reasons]
            flags = {'inferred_structure': structural, 'rate_only': rate,
                     'blind_combined': [s or r for s, r in zip(structural, rate)],
                     'protocol_aware_behavior': behavior,
                     'hybrid_combined': [s or r or b for s, r, b in zip(structural, rate, behavior)],
                     'uncalibrated_structure': [bool(s['score']) for s in scored]}
            windows = fixed_windows(messages)
            window_rate = [w['rate'] > window_threshold for w in windows]
            window_hybrid = [r or any(structural[i] or behavior[i] for i in w['indices'])
                             for r, w in zip(window_rate, windows)]
            protocol_result['per_run'][run['id']] = {
                'selected_attacker': run['details']['selected_attacker'],
                'decode_errors': decode_errors,
                'window_metrics': {'rate_only': counts(windows, window_rate),
                                   'hybrid_combined': counts(windows, window_hybrid)},
                'windows': [dict(w, rate_alert=r, hybrid_alert=h) for w,r,h in
                            zip(windows, window_rate, window_hybrid)],
                'metrics': {k: counts(messages, v) for k, v in flags.items()}}
            all_windows.extend(windows)
            all_window_rate.extend(window_rate)
            all_window_hybrid.extend(window_hybrid)
            all_messages.extend(messages)
            for key in all_flags:
                all_flags[key].extend(flags[key])
            for i, message in enumerate(messages):
                predictions.append({'run': run['id'], 'event_id': message['event_id'],
                                    'label': message['label'], 'client': message['client'],
                                    'structural': scored[i], 'behavior_reasons': behavior_reasons[i],
                                    'alerts': {k: v[i] for k, v in flags.items()}})
        protocol_result['aggregate'] = {k: counts(all_messages, v) for k, v in all_flags.items()}
        protocol_result['test_count'] = len(all_messages)
        protocol_result['window_metrics'] = {
            'unit': '1-second window, positive if it contains a logged attack request',
            'rate_only': counts(all_windows, all_window_rate),
            'hybrid_combined': counts(all_windows, all_window_hybrid)}
        protocol_result['warning'] = (
            'Small loopback experiment; no confidence of generalization. Hybrid uses protocol knowledge. '
            'A structural threshold of 1 disables binary structural alerts when normal validation is too anomalous. '
            'Uncalibrated metrics are diagnostic only; not selected using test labels.')
        output['protocols'][protocol] = protocol_result
        (path.parent/f'{protocol}_inferred_profile.json').write_text(json.dumps(artifact, indent=2)+'\n')
        (path.parent/f'{protocol}_predictions.json').write_text(json.dumps(predictions, indent=2)+'\n')
    (path.parent/'evaluation.json').write_text(json.dumps(output, indent=2)+'\n')
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest')
    args = parser.parse_args()
    result = evaluate(args.manifest)
    print(json.dumps({k: v['aggregate'] for k, v in result['protocols'].items()}, indent=2))


if __name__ == '__main__':
    main()
