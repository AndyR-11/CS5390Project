"""Conservative, protocol-blind T1 baseline. Standard library only.

Input must already contain individual messages, in one direction. No protocol
offsets, labels, ports, timestamps or field names are used by the learner.
"""
from collections import Counter, defaultdict
from math import log2


class MessageTypeClusterer:
    def __init__(self, max_values=16, max_entropy=1.5, min_samples=8):
        if max_values < 2 or max_entropy <= 0 or min_samples < 2:
            raise ValueError("Invalid clustering parameters")
        self.max_values = max_values
        self.max_entropy = max_entropy
        self.min_samples = min_samples
        self.offsets = {}
        self.clusters = {}
        self.fitted = False

    @staticmethod
    def _raws(messages):
        raws = [m["raw"] for m in messages]
        if any(not isinstance(r, bytes) or not r for r in raws):
            raise ValueError("Each message needs non-empty bytes in 'raw'")
        return raws

    def _key(self, raw):
        offsets = self.offsets.get(len(raw))
        if offsets is None:
            return None
        return (len(raw), tuple(raw[i] for i in offsets))

    def fit(self, messages):
        raws = self._raws(messages)
        if not raws:
            raise ValueError("Training data is empty")
        self.offsets = {}
        self.clusters = {}
        self.fitted = False
        by_length = defaultdict(list)
        for raw in raws:
            by_length[len(raw)].append(raw)
        for length, group in sorted(by_length.items()):
            # Rare lengths remain unknown, not confidently learned types.
            if len(group) < self.min_samples:
                continue
            selected = []
            for i in range(length):
                counts = Counter(raw[i] for raw in group)
                entropy = -sum((n / len(group)) * log2(n / len(group))
                               for n in counts.values())
                # Constant bytes cannot distinguish types within this length.
                if 2 <= len(counts) <= self.max_values and entropy <= self.max_entropy:
                    selected.append(i)
            self.offsets[length] = selected
        counts = Counter(self._key(raw) for raw in raws)
        keys = sorted(k for k, n in counts.items()
                      if k is not None and n >= self.min_samples)
        self.clusters = {k: i for i, k in enumerate(keys)}
        self.fitted = True
        return self

    def predict(self, messages):
        if not self.fitted:
            raise ValueError("Call fit before predict")
        return [self.clusters.get(self._key(r), -1) for r in self._raws(messages)]

    def fit_predict(self, messages):
        messages = list(messages)
        return self.fit(messages).predict(messages)

    def describe(self):
        if not self.fitted:
            raise ValueError("Call fit before describe")
        return {
            "method": "length + learned low-entropy categorical byte signature",
            "parameters": {"max_values": self.max_values,
                           "max_entropy": self.max_entropy,
                           "min_samples": self.min_samples},
            "offsets_by_length": self.offsets,
            "clusters": [{"id": v, "length": k[0], "signature": list(k[1])}
                         for k, v in self.clusters.items()],
            "unknown_id": -1,
        }


def group_messages(messages, assignments):
    """T2 adapter: preserve original records and order; -1 is unassigned."""
    messages, assignments = list(messages), list(assignments)
    if len(messages) != len(assignments):
        raise ValueError("One assignment is required for every message")
    groups = defaultdict(list)
    for message, cluster_id in zip(messages, assignments):
        groups[cluster_id].append(message)
    return dict(groups)
