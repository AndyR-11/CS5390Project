"""Protocol-aware comparison baseline, kept separate from blind T1/T2."""
import struct


def decode(raw, protocol):
    if protocol == 'modbus':
        if len(raw) != 12:
            return {'kind': 'malformed'}
        function, address, value = raw[7], *struct.unpack('>HH', raw[8:12])
        if function == 3:
            return {'kind': 'read', 'nodes': list(range(address, address+value))}
        if function == 6:
            return {'kind': 'write', 'writes': [{'node': address, 'value': value}]}
        return {'kind': 'unknown_function'}
    from opcua_ids.opcua_decode import decode_request_frame
    return decode_request_frame(raw)


def fit_behavior(messages, protocol):
    nodes = set()
    values = {}
    errors = 0
    for message in messages:
        try:
            event = decode(message['raw'], protocol)
        except Exception:
            errors += 1
            continue
        if not event:
            continue
        nodes.update(event.get('nodes', []))
        for write in event.get('writes', []):
            nodes.add(write['node'])
            value = write['value']
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                values.setdefault(write['node'], []).append(value)
    return {'nodes': nodes, 'ranges': {k: (min(v), max(v)) for k, v in values.items()},
            'training_decode_errors': errors}


def predict_behavior(messages, profile, protocol):
    reads = {}
    results, errors = [], 0
    for message in messages:
        reasons = []
        try:
            event = decode(message['raw'], protocol)
        except Exception:
            errors += 1
            event = None
        session = tuple(message['session'])
        if event:
            if event['kind'] in ('malformed', 'unknown_function'):
                reasons.append(event['kind'])
            for node in event.get('nodes', []):
                if node not in profile['nodes']:
                    reasons.append('unknown_node')
                reads[(session, node)] = message['ts']
            for write in event.get('writes', []):
                node, value = write['node'], write['value']
                last = reads.get((session, node))
                if last is None or message['ts']-last > 5:
                    reasons.append('write_without_recent_read_on_this_connection')
                if node not in profile['nodes']:
                    reasons.append('unknown_node')
                if node in profile['ranges'] and isinstance(value, (int, float)):
                    lo, hi = profile['ranges'][node]
                    margin = max(1, (hi-lo)*.5)
                    if not lo-margin <= value <= hi+margin:
                        reasons.append('write_outside_learned_range')
        results.append(reasons)
    return results, errors
