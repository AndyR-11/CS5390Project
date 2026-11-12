import argparse
import json
from statistics import median
from pcap_loader_generic import load_tcp_payloads


def load_schema(path):
    with open(path) as f:
        return json.load(f)


def structural_alert(raw, schema, prefix_width):
    key = raw[:prefix_width].hex() if len(raw) >= prefix_width else raw.hex()
    cmap = {c['cluster_key_hex']: c for c in schema['clusters']}
    c = cmap.get(key)
    if c is None:
        return 'unseen_message_cluster'
    if not (c['min_len'] <= len(raw) <= c['max_len']):
        return 'unexpected_length'
    return None


def is_opc_msg(m):
    raw = m['raw']
    return len(raw) >= 3 and raw[:3] == b'MSG'


def peak_msg_rate(msgs, window=1.0):
    msg_times = [m['ts'] for m in msgs if is_opc_msg(m)]

    if not msg_times:
        return 0.0

    left = 0
    peak = 0

    for right in range(len(msg_times)):
        while msg_times[right] - msg_times[left] > window:
            left += 1

        count = right - left + 1
        peak = max(peak, count)

    return peak / window


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('schema')
    ap.add_argument('normal_pcap')
    ap.add_argument('attack_pcaps', nargs='+')
    ap.add_argument('--port', type=int, default=4840)
    ap.add_argument('--rate-multiplier', type=float, default=3.0)
    args = ap.parse_args()

    schema = load_schema(args.schema)
    prefix_width = int(schema.get('prefix_width', 3))

    normal = load_tcp_payloads(args.normal_pcap, args.port)
    normal_rate = peak_msg_rate(normal)
    threshold = normal_rate * args.rate_multiplier

    print(f'Normal request rate: {normal_rate:.2f} req/s')
    print(f'Statistics alert threshold: {threshold:.2f} req/s')

    for p in args.attack_pcaps:
        msgs = load_tcp_payloads(p, args.port, label='attack')
        struct_reasons = [structural_alert(m['raw'], schema, prefix_width) for m in msgs]
        struct_hits = sum(r is not None for r in struct_reasons)
        rate = peak_msg_rate(msgs)
        stats_hit = rate > threshold if threshold > 0 else False

        print('\n' + p)
        print(f'  messages={len(msgs)} rate={rate:.2f} req/s')
        print(f'  structure_alerts={struct_hits}/{len(msgs)}')
        print(f'  stats_alert={stats_hit}')
        if struct_hits:
            reasons = {}
            for r in struct_reasons:
                if r:
                    reasons[r] = reasons.get(r, 0) + 1
            print(f'  structure_reasons={reasons}')


if __name__ == '__main__':
    main()
