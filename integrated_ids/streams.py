"""Offline TCP reconstruction and explicit protocol framing adapters.
Protocol knowledge is confined to framing; T1/T2 receive only framed raw bytes.
Connections with gaps or conflicting retransmissions are rejected, not guessed.
OPC UA units are UA TCP chunks (not reassembled multi-chunk service bodies).
"""
from collections import Counter, defaultdict, deque
import hashlib
import json


def frames(data, protocol):
    offset = 0
    while offset < len(data):
        header = 6 if protocol == 'modbus' else 8
        if len(data) - offset < header:
            raise ValueError(f'incomplete header at {offset}')
        if protocol == 'modbus':
            length = int.from_bytes(data[offset+4:offset+6], 'big')
            if not 2 <= length <= 254:
                raise ValueError(f'invalid MBAP length at {offset}')
            size = 6 + length
        elif protocol == 'opcua':
            size = int.from_bytes(data[offset+4:offset+8], 'little')
            if not 8 <= size <= 16 * 1024 * 1024:
                raise ValueError(f'invalid UA TCP length at {offset}')
        else:
            raise ValueError('Unknown framing protocol')
        if offset + size > len(data):
            raise ValueError(f'incomplete frame at {offset}')
        yield offset, data[offset:offset+size]
        offset += size


def reconstruct(segments):
    """Segments: seq, data, ts; supports reordering, wrap and identical overlap."""
    if not segments:
        return b'', [], 0
    anchor = segments[0]['seq']
    spans = []
    for segment in segments:
        delta = ((segment['seq'] - anchor + 2**31) % 2**32) - 2**31
        spans.append((delta, segment))
    low = min(n for n, _ in spans)
    high = max(n+len(s['data']) for n, s in spans)
    if high-low > 64*1024*1024:
        raise ValueError('stream exceeds offline memory limit')
    data = bytearray(high-low)
    seen = bytearray(high-low)
    times = [0.] * (high-low)
    duplicates = 0
    for start, segment in spans:
        for i, byte in enumerate(segment['data'], start-low):
            if seen[i]:
                if data[i] != byte:
                    raise ValueError('conflicting TCP overlap')
                times[i] = min(times[i], segment['ts'])
                duplicates += 1
            else:
                seen[i], data[i], times[i] = 1, byte, segment['ts']
    if not all(seen):
        raise ValueError('TCP gap: connection quarantined')
    return bytes(data), times, duplicates


def load_capture(path, port, protocol, direction='request'):
    from scapy.all import IP, IPv6, TCP, PcapReader
    if direction not in ('request', 'response'):
        raise ValueError('direction must be request or response')
    streams = defaultdict(list)
    active = {}
    generations = Counter()
    diagnostics = {'payload_segments': 0, 'duplicate_bytes': 0,
                   'quarantined_connections': [], 'midstream_connections': [],
                   'framing_errors': [], 'opc_continuation_chunks': 0}
    with PcapReader(str(path)) as packets:
        for packet in packets:
            if TCP not in packet:
                continue
            if (packet[TCP].dport if direction == 'request' else packet[TCP].sport) != port:
                continue
            ip = packet.getlayer(IP) or packet.getlayer(IPv6)
            if ip is None:
                continue
            tcp = packet[TCP]
            conn = (str(ip.src), int(tcp.sport), str(ip.dst), int(tcp.dport))
            syn = bool(int(tcp.flags) & 2)
            if syn and (conn not in active or active[conn][1] != int(tcp.seq)):
                generations[conn] += 1
                active[conn] = (generations[conn], int(tcp.seq))
            elif conn not in active:
                generations[conn] += 1
                active[conn] = (generations[conn], None)
                diagnostics['midstream_connections'].append(list(conn))
            raw = bytes(tcp.payload)
            if raw:
                diagnostics['payload_segments'] += 1
                key = conn + (active[conn][0],)
                streams[key].append({'seq': (int(tcp.seq)+int(syn)) % 2**32,
                                     'data': raw, 'ts': float(packet.time)})
    messages = []
    for key, segments in streams.items():
        try:
            data, times, duplicate_bytes = reconstruct(segments)
        except ValueError as exc:
            diagnostics['quarantined_connections'].append({'connection': key, 'error': str(exc)})
            continue
        diagnostics['duplicate_bytes'] += duplicate_bytes
        try:
            for offset, raw in frames(data, protocol):
                if protocol == 'opcua' and raw[3:4] in (b'C', b'A'):
                    diagnostics['opc_continuation_chunks'] += 1
                messages.append({'raw': raw, 'ts': min(times[offset:offset+len(raw)]),
                                 'end_ts': max(times[offset:offset+len(raw)]),
                                 'connection': list(key[:4]), 'session': list(key),
                                 'stream_offset': offset})
        except ValueError as exc:
            diagnostics['framing_errors'].append({'connection': key, 'error': str(exc)})
    messages.sort(key=lambda m: (m['ts'], m['connection'], m['stream_offset']))
    diagnostics['framed_messages'] = len(messages)
    return messages, diagnostics


def attach_labels(messages, events, tolerance=2.0):
    """Match: full connection + exact payload SHA256 + send time, in send order.

    When two or more events on the same connection share an identical payload
    (a repeated read of an unchanged value, a flood of identical requests, a
    deliberate replay), they are not ambiguous: TCP preserves order on a single
    connection, so the event log and the reconstructed stream agree on which
    occurrence came first. Within a (connection, sha256) bucket, events and
    messages are each already in send-time order; pairing them FIFO recovers
    the correct correspondence instead of discarding both as unmatched.

    The tolerance check still applies to each pairing, so a message that is
    not actually close in time to the next unmatched event of that bucket is
    left unmatched rather than guessed. Unmatched traffic is unlabeled, never
    silently treated as normal.
    """
    index = defaultdict(deque)
    for event in sorted(events, key=lambda e: e['ts']):
        index[(tuple(event['connection']), event['sha256'])].append(event)
    matched = 0
    for message in sorted(messages, key=lambda m: m['ts']):
        key = (tuple(message['connection']), hashlib.sha256(message['raw']).hexdigest())
        candidates = index.get(key)
        if candidates and abs(candidates[0]['ts'] - message['ts']) <= tolerance:
            event = candidates.popleft()
            message.update(label=event['label'], client=event['client'], event_id=event['event_id'])
            matched += 1
        else:
            message['label'] = 'unlabeled'
    return {'matched': matched, 'unmatched_messages': len(messages)-matched,
            'unmatched_events': sum(len(q) for q in index.values())}


def read_events(path):
    with open(path, encoding='utf-8') as stream:
        return [json.loads(line) for line in stream if line.strip()]