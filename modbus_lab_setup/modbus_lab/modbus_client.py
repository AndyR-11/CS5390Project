import argparse
import logging
import random
import time

from pymodbus.client import ModbusTcpClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("modbus_client")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5020)
    parser.add_argument("--duration", type=float, default=60.0, help="seconds to run, 0 = forever")
    parser.add_argument("--poll-gap", type=float, default=1.0, help="seconds between polls")
    # Multi-client options. Defaults reproduce the original single-client behavior.
    parser.add_argument("--name", default="client", help="label used in log lines")
    parser.add_argument("--read-addr", type=int, default=0, help="first holding register to read")
    parser.add_argument("--read-count", type=int, default=2, help="number of registers per read")
    parser.add_argument("--write-prob", type=float, default=0.1, help="chance of a setpoint write per cycle (0 = read-only)")
    parser.add_argument("--write-addr", type=int, default=1, help="register used for setpoint writes")
    parser.add_argument("--write-min", type=int, default=490)
    parser.add_argument("--write-max", type=int, default=510)
    parser.add_argument("--start-delay", type=float, default=0.0, help="seconds to wait before first poll")
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--info-file", default=None, help="write {name, local_port} JSON here after connecting (ground truth)")
    args = parser.parse_args()
    if args.seed is not None:
        random.seed(args.seed)
    global log   # rebind the module-level logger so log lines carry the client's name
    log = logging.getLogger(f"modbus_client.{args.name}")

    if args.start_delay > 0:
        time.sleep(args.start_delay)
    client = ModbusTcpClient(args.host, port=args.port)
    if not client.connect():
        log.error("Could not connect to server")
        return

    if args.info_file:
        import json
        with open(args.info_file, "w") as f:
            json.dump({"name": args.name, "local_port": client.socket.getsockname()[1]}, f)

    start = time.time()
    count = 0
    try:
        while args.duration == 0 or (time.time() - start) < args.duration:
            #read the "tank level" register most of the time
            rr = client.read_holding_registers(address=args.read_addr, count=args.read_count, device_id=1)
            if rr.isError():
                log.warning(f"Read error: {rr}")
            else:
                log.info(f"holding regs: {rr.registers}")

            #occasionally write (like operator adjusting a setpoint)
            if random.random() < args.write_prob:
                new_val = random.randint(args.write_min, args.write_max)
                wr = client.write_register(address=args.write_addr, value=new_val, device_id=1)
                log.info(f"wrote setpoint {new_val}: {'ok' if not wr.isError() else wr}")

            count += 1
            time.sleep(args.poll_gap + random.uniform(-0.1, 0.1))
    except KeyboardInterrupt:
        pass
    finally:
        client.close()
        log.info(f"Sent {count} poll cycles")


if __name__ == "__main__":
    main()
