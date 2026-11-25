"""Blind T1/T2 structural detector plus a timing-only baseline.
No protocol names, labels, connection identifiers or known field offsets enter
the learner. Labels are used only after prediction, in the evaluation module.
"""
from collections import deque
import math

from opcua_ids.chain_t1_t2 import run_chain
from paola_t1.clustering import group_messages


def fit(messages):
    # min_samples=4 (default 8): with 3 masters splitting traffic three
    # ways, each legitimate sub-pattern gets fewer training examples, so
    # the default threshold was calling genuinely-normal validation
    # traffic "unknown" ~14% (Modbus) / ~4-6% (OPC UA) of the time --
    # exactly as often as some real attacks, which made them
    # unscoreable: identical score, no possible separating threshold.
    artifact, model = run_chain(messages, clusterer_kwargs={'min_samples': 4})
    groups = group_messages(messages, model.predict(messages))
    profiles = {}
    for cluster, group in groups.items():
        if cluster == -1:
            continue
        schema = artifact['t2_per_cluster'][str(cluster)]['schema']
        entries = []
        for field in schema:
            offset, length = field['offset'], field['len']
            values = [m['raw'][offset:offset+length] for m in group]
            entry = dict(field)
            if field['role'] == 'constant':
                entry['expected_hex'] = values[0].hex()
            elif field['role'] != 'counter' and length <= 8:
                # An explicit inherited heuristic, not decoded protocol semantics.
                ints = [int.from_bytes(v, 'big') for v in values]
                lo, hi = min(ints), max(ints)
                # Safety margin, same idea as the max_write_step*1.5 margin
                # already used for the behavioral detector: an exact
                # training min/max leaves zero room for a second master's
                # legitimate value range to differ slightly from the first
                # master's training sample, which is what was pushing the
                # calibrated threshold to disable the detector entirely.
                margin = max(1, round((hi-lo)*0.15))
                entry.update(min=lo-margin, max=hi+margin)
            entries.append(entry)
        profiles[str(cluster)] = entries
    artifact['field_profiles'] = profiles
    return artifact, model


def score(messages, artifact, model):
    output = []
    for message, cluster in zip(messages, model.predict(messages)):
        reasons = []
        if cluster == -1 or str(cluster) not in artifact['field_profiles']:
            reasons.append('unknown_cluster')
        else:
            for field in artifact['field_profiles'][str(cluster)]:
                raw = message['raw'][field['offset']:field['offset']+field['len']]
                if 'expected_hex' in field and raw.hex() != field['expected_hex']:
                    reasons.append('constant:'+field['name'])
                elif 'min' in field and not field['min'] <= int.from_bytes(raw, 'big') <= field['max']:
                    reasons.append('range:'+field['name'])
        # Graded, not binary: counts HOW MANY fields violate, instead of
        # just whether any did. With a binary 0/1 score, once >5% of clean
        # validation messages trip even one field, the 95th-percentile
        # threshold becomes 1 and "score > 1" can never be true again --
        # the detector silently goes dead. A graded count gives the
        # threshold real room (e.g. settle at 1, so only >=2 simultaneous
        # violations alert) instead of collapsing to all-or-nothing.
        output.append({'score': float(len(reasons)), 'reasons': reasons, 'cluster': cluster})
    return output


def rate_scores(messages, window=1.0):
    history = deque()
    output = []
    for message in sorted(messages, key=lambda m: m['ts']):
        now = message['ts']
        while history and now-history[0] > window:
            history.popleft()
        history.append(now)
        output.append(len(history)/window)
    return output


def normal_threshold(values, allowed_fpr=0.05):
    if not values:
        raise ValueError('Independent normal validation traffic is required')
    ordered = sorted(values)
    return ordered[max(0, math.ceil((1-allowed_fpr)*len(ordered))-1)]


def fixed_windows(messages, width=1.0):
    """
    Lab captures continue past the final traffic bin. Width is also the rate
    denominator. A window is attack-positive if any logged attack is in it.
    """
    if not messages:
        return []
    start = messages[0]['ts']
    bins = [[] for _ in range(int((messages[-1]['ts']-start)//width)+1)]
    for index, message in enumerate(messages):
        bins[int((message['ts']-start)//width)].append(index)
    windows = []
    for bucket, indices in enumerate(bins):
        labels = {messages[i].get('label', 'unlabeled') for i in indices}
        attacks = sorted(x for x in labels if x.startswith('attack:'))
        label = attacks[0] if attacks else ('normal' if not labels or labels == {'normal'} else 'unlabeled')
        windows.append({'label': label, 'rate': len(indices)/width,
                        'indices': indices, 'start': start+bucket*width,
                        'attack_types': attacks})
    return windows


def counts(messages, flags):
    if len(messages) != len(flags):
        raise ValueError('One prediction per message is required')
    tp = fp = tn = fn = excluded = 0
    by_attack = {}
    for message, alert in zip(messages, flags):
        label = message.get('label', 'unlabeled')
        if label == 'normal':
            fp += bool(alert)
            tn += not alert
        elif label.startswith('attack:'):
            tp += bool(alert)
            fn += not alert
            entry = by_attack.setdefault(label[7:], {'tp': 0, 'fn': 0})
            entry['tp' if alert else 'fn'] += 1
        else:
            excluded += 1
    return {'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn, 'excluded': excluded,
            'recall': tp/(tp+fn) if tp+fn else None,
            'false_positive_rate': fp/(fp+tn) if fp+tn else None,
            'precision': tp/(tp+fp) if tp+fp else None, 'by_attack': by_attack}