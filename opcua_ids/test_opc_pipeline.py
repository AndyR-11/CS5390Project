"""
Tests for the OPC UA eval pipeline.   python3 -m unittest test_opc_pipeline -v

Real-capture tests use ../pcaps/opcua/opc_normal_only.pcapng; reassembly is tested on a
synthetic pcap so segment boundaries are known exactly.
"""
import os
import tempfile
import unittest

from scapy.all import Ether, IP, TCP, wrpcap

import opc_detectors as D
from opc_decode import decode
from opc_labels import attack_name_from_path, label_attack_messages, splice
from opc_loader import load_opc_pcap

HERE = os.path.dirname(os.path.abspath(__file__))
NORMAL = os.path.join(HERE, "..", "pcaps", "opcua", "opc_normal_only.pcapng")
FLOOD = os.path.join(HERE, "..", "pcaps", "opcua", "opc_session_flood_only.pcapng")


def _msg(service, nodes=(), value=None, conn=1, ts=0.0):
    """Build a synthetic message with a hand-made decode result."""
    dec = {"msg_type": "MSG", "service": service, "nodes": list(nodes), "attr": 13 if nodes else None,
           "value": value, "n_items": len(nodes) or None, "parse_ok": True, "problem": None}
    return {"raw": b"x" * 93, "ts": ts, "label": "normal", "conn_id": conn, "src_port": 1000 + conn, "dec": dec}


class RealCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.msgs = load_opc_pcap(NORMAL)

    def test_all_messages_decode(self):
        self.assertEqual(len(self.msgs), 195)
        self.assertTrue(all(m["dec"]["parse_ok"] for m in self.msgs))

    def test_service_mix(self):
        from collections import Counter
        c = Counter(m["dec"]["service"] for m in self.msgs)
        self.assertEqual(c["Read"], 181)
        self.assertEqual(c["Write"], 5)

    def test_write_values_decoded(self):
        vals = [m["dec"]["value"] for m in self.msgs if m["dec"]["service"] == "Write"]
        self.assertEqual(vals, [499, 506, 496, 488, 483])

    def test_session_flood_has_20_connections(self):
        self.assertEqual(len({m["conn_id"] for m in load_opc_pcap(FLOOD)}), 20)


class StructureDetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.msgs = load_opc_pcap(NORMAL)
        cls.p = D.build_struct_profile(cls.msgs)
        cls.read = next(m for m in cls.msgs if m["dec"]["service"] == "Read" and m["dec"]["nodes"] == [(2, 2)])

    def _mutate(self, raw):
        return {"raw": raw, "ts": 0, "label": "normal", "conn_id": 1, "src_port": 1, "dec": decode(raw)}

    def test_normal_traffic_is_clean(self):
        self.assertEqual([D.struct_detect(m, self.p) for m in self.msgs if D.struct_detect(m, self.p)], [])

    def test_same_length_unknown_node_is_caught(self):
        raw = bytearray(self.read["raw"])
        # locate the ReadValueId node ns=2,id=2 (FourByte NodeId: 01 02 02 00)
        i = bytes(raw).index(bytes([0x01, 0x02, 0x02, 0x00]), 60)
        raw[i + 2] = 0x77                                              # id 2 -> 0x77, same length
        m = self._mutate(bytes(raw))
        self.assertEqual(len(m["raw"]), len(self.read["raw"]))
        self.assertEqual(D.struct_detect(m, self.p), "unseen_node")

    def test_size_mismatch(self):
        self.assertEqual(D.struct_detect(self._mutate(self.read["raw"][:-3]), self.p), "size_mismatch")

    def test_unknown_message_type(self):
        raw = b"XYZF" + self.read["raw"][4:]
        self.assertEqual(D.struct_detect(self._mutate(raw), self.p), "unknown_msg_type")


class BehavioralDetectorTests(unittest.TestCase):
    def setUp(self):
        self.p = D.BehavioralProfile()
        self.p.max_write_step, self.p.write_lo, self.p.write_hi = 15, 468, 521
        self.sp = (2, 3)

    def test_write_after_own_read_is_ok(self):
        r = D.behavioral_detect([_msg("Read", [self.sp], ts=0), _msg("Write", [self.sp], 500, ts=1)], self.p)
        self.assertEqual(r, [None, None])

    def test_write_without_read(self):
        self.assertEqual(D.behavioral_detect([_msg("Write", [self.sp], 500)], self.p), ["write_no_read"])

    def test_other_connections_read_does_not_mask(self):
        """The Modbus detector tracks reads globally, so another client's read hides an attacker's write."""
        r = D.behavioral_detect([_msg("Read", [self.sp], conn=1, ts=0), _msg("Write", [self.sp], 500, conn=2, ts=1)], self.p)
        self.assertEqual(r, [None, "write_no_read"])

    def test_stale_read_expires(self):
        r = D.behavioral_detect([_msg("Read", [self.sp], ts=0), _msg("Write", [self.sp], 500, ts=30)], self.p)
        self.assertEqual(r[1], "write_no_read")

    def test_value_jump_absolute_and_step(self):
        read = _msg("Read", [self.sp], ts=0)
        self.assertEqual(D.behavioral_detect([read, _msg("Write", [self.sp], 999, ts=1)], self.p)[1], "value_jump")
        seq = [read, _msg("Write", [self.sp], 500, ts=1), _msg("Write", [self.sp], 520, ts=2)]   # in range, step 20 > 15
        self.assertEqual(D.behavioral_detect(seq, self.p)[2], "value_jump")


class LoaderReassemblyTests(unittest.TestCase):
    def _pcap(self, segments):
        """segments: list of payload bytes sent in order on one connection (port 4840)."""
        pkts, seq = [], 1000
        base = Ether() / IP(src="127.0.0.1", dst="127.0.0.1")
        pkts.append(base / TCP(sport=40000, dport=4840, flags="S", seq=seq))
        for i, seg in enumerate(segments):
            p = base / TCP(sport=40000, dport=4840, flags="PA", seq=seq + 1) / seg
            p.time = 10.0 + i
            pkts.append(p)
            seq += len(seg)
        path = tempfile.mktemp(suffix=".pcap")
        wrpcap(path, pkts)
        return path

    def test_two_messages_in_one_segment_and_one_split(self):
        real = [m["raw"] for m in load_opc_pcap(NORMAL)][:4]          # HEL, OPN, CreateSession, ActivateSession
        a, b, c, d = real
        path = self._pcap([a + b, c[:20], c[20:] + d])
        out = load_opc_pcap(path)
        os.remove(path)
        self.assertEqual([m["raw"] for m in out], real)


class LabelAndSpliceTests(unittest.TestCase):
    def test_attack_name_from_path(self):
        self.assertEqual(attack_name_from_path("x/opc_read_flood_only.pcapng"), "read_flood")
        with self.assertRaises(ValueError):
            attack_name_from_path("opc_unknown_only.pcapng")

    def test_read_flood_label_count(self):
        msgs = label_attack_messages(load_opc_pcap(
            os.path.join(HERE, "..", "pcaps", "opcua", "opc_read_flood_only.pcapng")), "read_flood")
        self.assertEqual(sum(m["label"] != "normal" for m in msgs), 50)

    def test_splice_keeps_background_and_shifts_attack(self):
        bg = load_opc_pcap(NORMAL)
        atk = label_attack_messages(load_opc_pcap(
            os.path.join(HERE, "..", "pcaps", "opcua", "opc_value_jump_only.pcapng")), "value_jump")
        out = splice(bg, atk, 0.5)
        self.assertEqual(len(out), len(bg) + len(atk))
        mid = bg[0]["ts"] + 0.5 * (bg[-1]["ts"] - bg[0]["ts"])
        first_atk = min(m["ts"] for m in out if m["src"] == "atk")
        self.assertAlmostEqual(first_atk, mid, places=3)
        self.assertEqual(len({m["conn_id"] for m in out if m["src"] == "atk"} & {m["conn_id"] for m in out if m["src"] == "bg"}), 0)


class RegressionTests(unittest.TestCase):
    """One test per bug that was found and fixed; each fails on the pre-fix code."""

    def _stream(self, pieces, isn=1000):
        """pieces: list of (offset_into_stream, payload). Builds a one-connection pcap."""
        base = Ether() / IP(src="127.0.0.1", dst="127.0.0.1")
        pkts = [base / TCP(sport=41000, dport=4840, flags="S", seq=isn)]
        for i, (off, payload) in enumerate(pieces):
            p = base / TCP(sport=41000, dport=4840, flags="PA", seq=(isn + 1 + off) & 0xFFFFFFFF) / payload
            p.time = 10.0 + i
            pkts.append(p)
        path = tempfile.mktemp(suffix=".pcap")
        wrpcap(path, pkts)
        return path

    def setUp(self):
        self.real = [m["raw"] for m in load_opc_pcap(NORMAL)][:3]   # HEL, OPN, CreateSession

    def _load(self, pieces, **kw):
        path = self._stream(pieces, **kw)
        try:
            return [m["raw"] for m in load_opc_pcap(path)]
        finally:
            os.remove(path)

    def test_retransmitted_segment_is_not_a_duplicate_message(self):
        a, b, c = self.real
        out = self._load([(0, a), (len(a), b), (len(a), b), (len(a) + len(b), c)])
        self.assertEqual(out, [a, b, c])

    def test_partially_overlapping_retransmission_keeps_only_new_bytes(self):
        a, b, c = self.real
        stream = a + b + c
        # second segment re-sends the last 10 bytes of `a`, then carries b and c
        out = self._load([(0, a), (len(a) - 10, stream[len(a) - 10:])])
        self.assertEqual(out, [a, b, c])

    def test_sequence_number_wraparound(self):
        a, b, c = self.real
        out = self._load([(0, a), (len(a), b), (len(a) + len(b), c)], isn=0xFFFFFFFF - 20)
        self.assertEqual(out, [a, b, c])

    def test_attack_write_does_not_poison_next_legit_write(self):
        p = D.BehavioralProfile()
        p.max_write_step, p.write_lo, p.write_hi = 15, 468, 521
        sp = (2, 3)
        seq = [_msg("Read", [sp], ts=0), _msg("Write", [sp], 500, ts=1),
               _msg("Read", [sp], ts=2), _msg("Write", [sp], 999, ts=3),   # attack
               _msg("Read", [sp], ts=4), _msg("Write", [sp], 495, ts=5)]   # legitimate again
        r = D.behavioral_detect(seq, p)
        self.assertEqual([r[1], r[3], r[5]], [None, "value_jump", None])

    def test_in_range_level_shift_alerts_once_not_forever(self):
        p = D.BehavioralProfile()
        p.max_write_step, p.write_lo, p.write_hi = 15, 400, 600
        sp = (2, 3)
        seq = [_msg("Read", [sp], ts=0), _msg("Write", [sp], 500, ts=1),
               _msg("Read", [sp], ts=2), _msg("Write", [sp], 540, ts=3),   # jump of 40, in range
               _msg("Read", [sp], ts=4), _msg("Write", [sp], 545, ts=5)]
        r = D.behavioral_detect(seq, p)
        self.assertEqual([r[1], r[3], r[5]], [None, "value_jump", None])

    def test_partial_tail_window_is_dropped_only_when_asked(self):
        msgs = [_msg("Read", [(2, 2)], ts=t) for t in (0.0, 1.0, 2.0, 6.0, 7.0, 11.0)]   # 3 windows, last is partial
        self.assertEqual(len(D.windows_from_messages(msgs)), 3)
        self.assertEqual(len(D.windows_from_messages(msgs, drop_partial_tail=True)), 2)
        self.assertEqual(len(D.windows_from_messages(msgs[:3], drop_partial_tail=True)), 1)   # single window is kept


if __name__ == "__main__":
    unittest.main()
