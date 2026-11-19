"""Learn T1 groups and run the existing T2 functions within each group.

Run from the repository root with python -m opcua_ids.chain_t1_t2.
Input units are TCP payloads, not reassembled application messages.
The output is an inference artifact, not a detector profile.
"""
import argparse
from collections import Counter
import json
from pathlib import Path

from paola_t1.clustering import MessageTypeClusterer, group_messages
from modbus_ids.infer_boundaries import infer_boundaries
from modbus_ids.infer_merge import merge_fields
from modbus_ids.infer_roles import assign_roles


def run_chain(messages, clusterer_kwargs=None):
    messages = list(messages)
    model = MessageTypeClusterer(**(clusterer_kwargs or {}))
    assignments = model.fit_predict(messages)
    results = {}
    for cluster_id, group in sorted(group_messages(messages, assignments).items()):
        if cluster_id == -1:
            results['unassigned'] = {'count': len(group)}
            continue
        raws = [m['raw'] for m in group]
        fields, variability = infer_boundaries(raws)
        fields = merge_fields(raws, fields)
        results[str(cluster_id)] = {
            'count': len(group), 'length': len(raws[0]),
            'schema': assign_roles(raws, fields),
            'byte_variability': variability,
        }
    return {'t1': model.describe(), 't2_per_cluster': results}, model


def summarize(model, messages):
    assignments = model.predict(messages)
    counts = Counter(assignments)
    return {'count': len(assignments),
            'cluster_counts': {str(k): v for k, v in sorted(counts.items())},
            'unknown_count': counts[-1],
            'known_fraction': (1 - counts[-1] / len(assignments)) if assignments else None}


def main():
    from opcua_ids.pcap_loader import load_tcp_payloads
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pcap', help='Normal training capture only')
    parser.add_argument('--port', type=int, default=4840)
    parser.add_argument('--out', default='opcua_ids/t1_t2_schema.json')
    parser.add_argument('--train-fraction', type=float, default=0.7)
    parser.add_argument('--test-pcap', action='append', default=[])
    args = parser.parse_args()
    if not 0 < args.train_fraction < 1:
        parser.error('--train-fraction must be between 0 and 1')
    messages = load_tcp_payloads(args.pcap, args.port)
    split = int(len(messages) * args.train_fraction)
    if not 0 < split < len(messages):
        parser.error('Capture needs enough payloads for nonempty train and test sets')
    result, model = run_chain(messages[:split])
    result['source'] = args.pcap
    result['port'] = args.port
    result['unit'] = 'client-to-server TCP payload; no stream reassembly'
    result['limitations'] = [
        'Grouping coverage is not attack detection accuracy or boundary accuracy.',
        'OPC UA service types and true boundaries have not been validated.',
        'T2 uses the existing big-endian merge/role heuristics and default threshold.',
        'This schema is not wired into the OPC UA detectors.',
    ]
    result['train_count'] = split
    result['held_out'] = summarize(model, messages[split:])
    result['test_captures'] = {
        p: summarize(model, load_tcp_payloads(p, args.port)) for p in args.test_pcap
    }
    target = Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'train_count': split, 'clusters': len(model.clusters),
                      'held_out': result['held_out'],
                      'test_captures': result['test_captures']}, indent=2))


if __name__ == '__main__':
    main()
