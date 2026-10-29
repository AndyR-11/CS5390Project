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
    args = parser.parse_args()

    client = ModbusTcpClient(args.host, port=args.port)
    if not client.connect():
        log.error("Could not connect to server")
        return

    start = time.time()
    count = 0
    try:
        while args.duration == 0 or (time.time() - start) < args.duration:
            #read the "tank level" register most of the time
            rr = client.read_holding_registers(address=0, count=2, device_id=1)
            if rr.isError():
                log.warning(f"Read error: {rr}")
            else:
                log.info(f"holding regs: {rr.registers}")

            #occasionally write (like operator adjusting a setpoint)
            if random.random() < 0.1:
                new_val = random.randint(490, 510)
                wr = client.write_register(address=1, value=new_val, device_id=1)
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
