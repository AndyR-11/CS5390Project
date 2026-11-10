import argparse
from pcap_loader_generic import load_tcp_payloads
from infer_structure import infer, save_schema


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('pcap')
    ap.add_argument('--port', type=int, default=4840)
    ap.add_argument('--out', default='opcua_inferred_schema.json')
    ap.add_argument('--prefix-width', type=int, default=3)
    args = ap.parse_args()

    msgs = load_tcp_payloads(args.pcap, server_port=args.port, keep_responses=False)
    if not msgs:
        raise SystemExit('No client->server TCP payloads found. Check the pcap and port.')

    schema = infer(msgs, prefix_width=args.prefix_width)
    save_schema(schema, args.out)

    print(f'Loaded {len(msgs)} request payloads from {args.pcap}')
    print(f'Inferred {len(schema["clusters"])} message clusters')
    for c in schema['clusters']:
        name = c['cluster_key_ascii'] or c['cluster_key_hex']
        print(f"  {name!r}: count={c['count']} len={c['min_len']}..{c['max_len']}")
        print(f"    segments={c['segments'][:8]}")
        if c['length_candidates']:
            print(f"    length_candidates={c['length_candidates']}")
    print(f'Wrote {args.out}')


if __name__ == '__main__':
    main()
