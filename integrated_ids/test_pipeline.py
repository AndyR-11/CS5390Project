import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from .streams import frames, reconstruct, load_capture, attach_labels
from .detection import fit, score, counts, normal_threshold, rate_scores, fixed_windows
from .behavior import fit_behavior, predict_behavior
from .lab import Process
from .evaluate import evaluate, ownership_audit


def request(tid=1, function=3, address=0, value=4):
    return struct.pack('>HHHBBHH', tid, 0, 6, 1, function, address, value)


class StreamTests(unittest.TestCase):
    def test_fragment_reorder_retransmission_and_coalescing(self):
        data = request()+request(2)
        segments = [{'seq': 109, 'data': data[9:], 'ts': 2},
                    {'seq': 100, 'data': data[:12], 'ts': 1},
                    {'seq': 100, 'data': data[:12], 'ts': 3}]
        raw, _, duplicates = reconstruct(segments)
        self.assertEqual(raw, data)
        self.assertEqual(duplicates, 15)
        self.assertEqual([r for _, r in frames(raw, 'modbus')], [request(), request(2)])

    def test_wrap(self):
        raw, _, _ = reconstruct([{'seq': 2**32-2, 'data': b'ab', 'ts': 1},
                                 {'seq': 0, 'data': b'cd', 'ts': 2}])
        self.assertEqual(raw, b'abcd')

    def test_gaps_and_conflicting_overlap_rejected(self):
        for seq, raw in [(103, b'd'), (101, b'xx')]:
            with self.assertRaises(ValueError):
                reconstruct([{'seq': 100, 'data': b'ab', 'ts': 1},
                             {'seq': seq, 'data': raw, 'ts': 2}])

    def test_opc_frames_and_incomplete_tail(self):
        raw = b'HELF'+struct.pack('<I', 12)+b'abcd'
        self.assertEqual(list(frames(raw+raw, 'opcua')), [(0, raw), (12, raw)])
        with self.assertRaises(ValueError):
            list(frames(raw[:-1], 'opcua'))

    def test_real_pcap_connection_isolation_and_reuse(self):
        from scapy.all import IP, TCP, Raw, wrpcap
        packets = []
        def add(port, seq, flags, data=b''):
            p = IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=port, dport=502, seq=seq, flags=flags)
            if data:
                p = p/Raw(data)
            p.time = 1+len(packets)*.01
            packets.append(p)
        add(2000, 100, 'S')
        add(2001, 200, 'S')
        add(2000, 106, 'PA', request()[5:])
        add(2001, 201, 'PA', request(2))
        add(2000, 101, 'PA', request()[:5])
        add(2000, 101, 'PA', request()[:5])
        add(2000, 900, 'S')
        add(2000, 901, 'PA', request(3))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'test.pcap'
            wrpcap(str(path), packets)
            messages, diagnostics = load_capture(path, 502, 'modbus')
        self.assertEqual(len(messages), 3)
        self.assertEqual(len({tuple(m['session']) for m in messages}), 3)
        self.assertEqual(diagnostics['duplicate_bytes'], 5)
        self.assertFalse(diagnostics['quarantined_connections'])


class LabelTests(unittest.TestCase):
    def test_exact_connection_and_hash_required(self):
        conn = ['127.0.0.1', 2000, '127.0.0.1', 502]
        event = {'connection': conn, 'sha256': hashlib.sha256(request()).hexdigest(),
                 'ts': 1, 'label': 'attack:value_jump', 'client': 'master_1', 'event_id': 1}
        msgs = [{'connection': conn, 'raw': request(), 'ts': 1.01},
                {'connection': conn, 'raw': request(2), 'ts': 1.02},
                {'connection': ['127.0.0.2', 2000, '127.0.0.1', 502], 'raw': request(), 'ts': 1.03}]
        audit = attach_labels(msgs, [event])
        self.assertEqual(audit['matched'], 1)
        self.assertEqual(msgs[0]['label'], 'attack:value_jump')
        self.assertEqual(msgs[1]['label'], 'unlabeled')

    def test_ambiguous_and_old_events_not_assumed_normal(self):
        event = {'connection': ['a', 1, 'b', 2], 'sha256': hashlib.sha256(b'x').hexdigest(),
                 'ts': 1, 'label': 'normal', 'client': 'c', 'event_id': 1}
        msgs = [{'connection': event['connection'], 'raw': b'x', 'ts': 1}]
        attach_labels(msgs, [event, dict(event, event_id=2)])
        self.assertEqual(msgs[0]['label'], 'unlabeled:ambiguous')
        attach_labels(msgs, [dict(event, ts=20)])
        self.assertEqual(msgs[0]['label'], 'unlabeled')


class DetectorTests(unittest.TestCase):
    def test_inferred_constant_field_is_actually_used(self):
        # T1 ignores constant positions, so this mutation must be caught by T2 profile.
        train = [{'raw': bytes([1, i, 0, 0, 0, 0])} for i in range(32)]
        artifact, model = fit(train)
        frozen = copy.deepcopy((artifact, model.describe()))
        result = score([{'raw': bytes([1, 2, 0, 0, 0, 99])}], artifact, model)[0]
        self.assertNotEqual(result['cluster'], -1)
        self.assertTrue(any(r.startswith('constant:') for r in result['reasons']))
        self.assertEqual(frozen, (artifact, model.describe()))

    def test_metadata_independence(self):
        train = [{'raw': bytes([1, i, 0, 0, 0, 0]), 'label': 'normal'} for i in range(32)]
        a, m = fit(train)
        b, n = fit([dict(x, label='attack:fake', client='other') for x in train])
        self.assertEqual(a, b)
        self.assertEqual(m.describe(), n.describe())

    def test_metrics_unlabeled_excluded(self):
        result = counts([{'label': x} for x in ['normal','normal','attack:x','attack:x','unlabeled']],
                        [True, False, True, False, True])
        self.assertEqual((result['tp'], result['fn'], result['fp'], result['tn'], result['excluded']),
                         (1, 1, 1, 1, 1))
        self.assertEqual(result['recall'], .5)

    def test_validation_and_rate_windows(self):
        self.assertEqual(normal_threshold([0]*95+[1]*5), 0)
        self.assertEqual(normal_threshold([0]*90+[1]*10), 1)
        self.assertEqual(rate_scores([{'ts': x} for x in [0, .1, 2]]), [1, 2, 1])
        with self.assertRaises(ValueError):
            normal_threshold([])

    def test_window_labels_include_mixed_traffic_without_relabeling_messages(self):
        messages = [{'ts': 0, 'label': 'normal'}, {'ts': .2, 'label': 'attack:flood'},
                    {'ts': .8, 'label': 'normal'}, {'ts': 1.2, 'label': 'normal'}]
        windows = fixed_windows(messages)
        self.assertEqual([w['label'] for w in windows], ['attack:flood', 'normal'])
        self.assertEqual([w['rate'] for w in windows], [3, 1])
        self.assertEqual(messages[2]['label'], 'normal')

    def test_behavior_reads_cover_range_but_not_other_client(self):
        normal = [{'raw': request(1)}, {'raw': request(2, 6, 1, 500)}]
        profile = fit_behavior(normal, 'modbus')
        msgs = [{'raw': request(), 'ts': 1, 'session': ['a']},
                {'raw': request(2, 6, 1, 500), 'ts': 2, 'session': ['a']},
                {'raw': request(3, 6, 1, 500), 'ts': 2, 'session': ['b']}]
        result, errors = predict_behavior(msgs, profile, 'modbus')
        self.assertEqual(errors, 0)
        self.assertFalse(result[1])
        self.assertIn('write_without_recent_read_on_this_connection', result[2])

    def test_shared_process_changes_and_registers_separate(self):
        process = Process()
        process.request(request(1, 6, 1, 505)[6:])
        process.request(request(2, 6, 2, 497)[6:])
        process.request(request(3, 6, 3, 499)[6:])
        process.last -= 1
        response = process.request(request()[6:])
        vals = struct.unpack('>4H', response[3:])
        self.assertGreater(vals[0], 500)
        self.assertEqual(vals[1:], (505, 497, 499))
        self.assertEqual(process.request(request(4,6,0,1)[6:]), bytes([1,134,2]))


class EvaluationTests(unittest.TestCase):
    def test_incomplete_capture_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'manifest.json'
            path.write_text(json.dumps({'complete': False, 'runs': [], 'expected_runs': 20}))
            with self.assertRaisesRegex(ValueError, 'incomplete'):
                evaluate(path)

    def test_training_attack_rejected_before_fit(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            (folder/'capture.pcap').write_bytes(b'test')
            (folder/'events.jsonl').write_text('')
            run = {'id': 'training', 'split': 'train', 'protocol': 'modbus', 'port': 502,
                   'pcap': 'capture.pcap', 'events': 'events.jsonl',
                   'sha256': hashlib.sha256(b'test').hexdigest()}
            manifest = folder/'manifest.json'
            manifest.write_text(json.dumps({'complete': True, 'runs': [run], 'expected_runs': 1}))
            with patch('integrated_ids.evaluate.load_capture', return_value=(
                    [{'raw': request(), 'label': 'attack:x'}],
                    {'quarantined_connections': [], 'framing_errors': []})), \
                 patch('integrated_ids.evaluate.attach_labels', return_value={
                     'matched': 1, 'unmatched_messages': 0, 'unmatched_events': 0}), \
                 patch('integrated_ids.evaluate.fit') as learner:
                with self.assertRaisesRegex(ValueError, 'clean normal'):
                    evaluate(manifest)
                learner.assert_not_called()

    def test_capture_hash_is_verified(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            (folder/'capture.pcap').write_bytes(b'changed')
            manifest = folder/'manifest.json'
            manifest.write_text(json.dumps({'complete': True, 'expected_runs': 1, 'runs': [
                {'id': 'x', 'split': 'train', 'pcap': 'capture.pcap', 'sha256': 'wrong'}]}))
            with self.assertRaisesRegex(ValueError, 'Changed or duplicated'):
                evaluate(manifest)

    def test_monitor_write_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Monitor'):
            ownership_audit([{'raw': request(1,6,1,500), 'client': 'monitor', 'label': 'normal'}], 'modbus')

    def test_wrong_owner_write_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'outside'):
            ownership_audit([{'raw': request(1,6,2,500), 'client': 'master_1', 'label': 'normal'}], 'modbus')


if __name__ == '__main__':
    unittest.main()
