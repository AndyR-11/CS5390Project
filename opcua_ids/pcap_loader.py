from scapy.all import rdpcap, TCP, IP


def load_tcp_payloads(path, server_port, keep_responses=False, label='normal'):
    packets = rdpcap(path)
    messages = []

    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            continue

        tcp = pkt[TCP]
        payload = bytes(tcp.payload)
        if not payload:
            continue

        is_request = tcp.dport == server_port
        is_response = tcp.sport == server_port
        if not (is_request or (keep_responses and is_response)):
            continue

        messages.append({
            'raw': payload,
            'ts': float(pkt.time),
            'label': label,
            'src_port': int(tcp.sport if is_request else tcp.dport),
            'dst_port': int(tcp.dport if is_request else tcp.sport),
            'direction': 'request' if is_request else 'response',
            'raw_len': len(payload),
        })

    messages.sort(key=lambda m: m['ts'])
    return messages
