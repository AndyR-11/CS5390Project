import copy
import random
import unittest

from .clustering import MessageTypeClusterer, group_messages


def samples():
    # Type is deliberately at offset 3, not a Modbus function-code offset.
    return [{"raw": bytes([i % 256, 0, 0, kind, (i * 31) % 256]), "label": str(i), "ts": i}
            for i in range(256) for kind in (11, 22)]


class ClusteringTests(unittest.TestCase):
    def test_counter_is_not_a_type(self):
        msgs = samples()
        model = MessageTypeClusterer().fit(msgs)
        self.assertEqual(model.offsets[5], [3])
        self.assertEqual(len(set(model.predict(msgs))), 2)

    def test_unknown_and_new_length(self):
        model = MessageTypeClusterer().fit(samples())
        self.assertEqual(model.predict([{"raw": b"\x01\0\0\x21\x02"},
                                        {"raw": b"longer"}]), [-1, -1])

    def test_input_and_metadata_ignored(self):
        msgs = samples()
        before = copy.deepcopy(msgs)
        model = MessageTypeClusterer().fit(msgs)
        expected = model.predict(msgs)
        changed = [{"raw": m["raw"], "label": "attack", "ts": -1} for m in msgs]
        self.assertEqual(model.predict(changed), expected)
        self.assertEqual(msgs, before)

    def test_order_determinism(self):
        msgs = samples()
        shuffled = list(msgs)
        random.Random(7).shuffle(shuffled)
        self.assertEqual(MessageTypeClusterer().fit(msgs).describe(), MessageTypeClusterer().fit(shuffled).describe())

    def test_predict_does_not_retrain(self):
        model = MessageTypeClusterer().fit(samples())
        before = copy.deepcopy(model.describe())
        model.predict([{"raw": b"unseen"}])
        self.assertEqual(model.describe(), before)

    def test_rare_lengths_and_signatures(self):
        model = MessageTypeClusterer().fit(samples() + [{"raw": b"a"}])
        self.assertEqual(model.predict([{"raw": b"a"}]), [-1])
        msgs = [{"raw": b"AA"}] * 20 + [{"raw": b"AB"}]
        model.fit(msgs)
        self.assertEqual(model.predict([{"raw": b"AB"}]), [-1])

    def test_constant_fallback_is_length_only(self):
        model = MessageTypeClusterer().fit([{"raw": b"AA"}] * 8)
        self.assertEqual(model.offsets[2], [])
        # Documented blind spot: unseen constant-byte changes need to T2/detection.
        self.assertEqual(model.predict([{"raw": b"ZZ"}]), [0])

    def test_validation(self):
        for msgs in ([], [{"raw": b""}], [{"raw": "abc"}]):
            with self.assertRaises(ValueError):
                MessageTypeClusterer().fit(msgs)
        with self.assertRaises(ValueError):
            MessageTypeClusterer().predict([])
        with self.assertRaises(ValueError):
            MessageTypeClusterer(max_entropy=0)

    def test_refit_discards_previous_model(self):
        model = MessageTypeClusterer().fit(samples())
        model.fit([{"raw": b"a"}] * 8)
        self.assertEqual(model.predict(samples()[:1]), [-1])

    def test_t2_groups_preserve_records(self):
        msgs = samples()[:3]
        groups = group_messages(msgs, [0, -1, 0])
        self.assertEqual(groups[0], [msgs[0], msgs[2]])
        self.assertIs(groups[-1][0], msgs[1])
        with self.assertRaises(ValueError):
            group_messages(msgs, [0])


if __name__ == "__main__":
    unittest.main()
