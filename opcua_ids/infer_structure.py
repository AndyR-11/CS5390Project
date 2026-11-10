import json
from collections import Counter, defaultdict


def _classify_byte(values):
    uniq = len(set(values))
    if uniq == 1:
        return 'constant'
    ratio = uniq / max(1, len(values))
    if ratio <= 0.10:
        return 'low_cardinality'
    return 'variable'


def _merge_runs(classes):
    if not classes:
        return []
    out = []
    start = 0
    cur = classes[0]
    for i in range(1, len(classes)):
        if classes[i] != cur:
            out.append({'offset': start, 'len': i - start, 'variation': cur})
            start = i
            cur = classes[i]
    out.append({'offset': start, 'len': len(classes) - start, 'variation': cur})
    return out


def _find_length_candidates(raw_messages, min_len):
    cands = []
    for width, endian in [(2, 'little'), (2, 'big'), (4, 'little'), (4, 'big')]:
        for off in range(0, max(0, min_len - width + 1)):
            hits = 0
            total = 0
            for raw in raw_messages:
                if len(raw) < off + width:
                    continue
                total += 1
                value = int.from_bytes(raw[off:off+width], endian)
                if value == len(raw):
                    hits += 1
            if total and hits / total >= 0.80:
                cands.append({
                    'offset': off,
                    'len': width,
                    'role': 'length_candidate',
                    'endian': endian,
                    'match_rate': round(hits / total, 3),
                })
    return cands


def infer(messages, prefix_width=3, min_cluster_size=2):
    # No protocol knowledge: cluster by the first N raw bytes only.
    clusters = defaultdict(list)
    for m in messages:
        raw = m['raw']
        key = raw[:prefix_width].hex() if len(raw) >= prefix_width else raw.hex()
        clusters[key].append(raw)

    result = {
        'method': 'blind-prefix-clustering + byte-variability segmentation',
        'prefix_width': prefix_width,
        'clusters': []
    }

    for key, raws in sorted(clusters.items(), key=lambda kv: len(kv[1]), reverse=True):
        if len(raws) < min_cluster_size:
            continue

        min_len = min(map(len, raws))
        max_len = max(map(len, raws))
        byte_classes = []
        for i in range(min_len):
            vals = [r[i] for r in raws]
            byte_classes.append(_classify_byte(vals))

        segments = _merge_runs(byte_classes)
        length_candidates = _find_length_candidates(raws, min_len)

        # Add simple printable preview for the clustering prefix only.
        prefix_bytes = bytes.fromhex(key)
        try:
            prefix_ascii = prefix_bytes.decode('ascii') if all(32 <= b < 127 for b in prefix_bytes) else None
        except Exception:
            prefix_ascii = None

        result['clusters'].append({
            'cluster_key_hex': key,
            'cluster_key_ascii': prefix_ascii,
            'count': len(raws),
            'min_len': min_len,
            'max_len': max_len,
            'segments': segments,
            'length_candidates': length_candidates,
        })

    return result


def save_schema(schema, path):
    with open(path, 'w') as f:
        json.dump(schema, f, indent=2)
