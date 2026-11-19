import copy
import unittest
from unittest.mock import patch

from opcua_ids.chain_t1_t2 import run_chain, summarize
from modbus_ids.infer_boundaries import infer_boundaries


class ChainTests(unittest.TestCase):
    def messages(self):
        return [{'raw': bytes([kind, i, 0, 0, 0, 0]), 'ts': i}
                for i in range(32) for kind in (1, 2)]

    def test_t2_receives_each_cluster_separately_in_original_order(self):
        messages = self.messages()
        original = copy.deepcopy(messages)
        with patch('opcua_ids.chain_t1_t2.infer_boundaries', wraps=infer_boundaries) as infer:
            result, model = run_chain(messages)
        self.assertEqual(len(model.clusters), 2)
        self.assertEqual(infer.call_count, 2)
        for call in infer.call_args_list:
            raws = call.args[0]
            self.assertEqual(len({r[0] for r in raws}), 1)
            self.assertEqual([r[1] for r in raws], list(range(32)))
        self.assertEqual(messages, original)
        for info in result['t2_per_cluster'].values():
            end = 0
            for field in info['schema']:
                self.assertEqual(field['offset'], end)
                self.assertGreater(field['len'], 0)
                end += field['len']
            self.assertEqual(end, info['length'])

    def test_unknown_training_payload_is_not_sent_to_t2(self):
        messages = self.messages() + [{'raw': b'rare'}]
        result, _ = run_chain(messages)
        self.assertEqual(result['t2_per_cluster']['unassigned'], {'count': 1})

    def test_held_out_does_not_retrain(self):
        _, model = run_chain(self.messages())
        before = copy.deepcopy(model.describe())
        summary = summarize(model, [{'raw': bytes([3, 99, 0, 0, 0, 0])}])
        self.assertEqual(summary['unknown_count'], 1)
        self.assertEqual(before, model.describe())

    def test_empty_training_rejected(self):
        with self.assertRaises(ValueError):
            run_chain([])


if __name__ == '__main__':
    unittest.main()
