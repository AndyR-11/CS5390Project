import argparse
import asyncio
import logging
import random
import time

from asyncua import Client, ua

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("opcua_client")

NAMESPACE_URI = "urn:cps-project:modbus-opcua-gateway"


async def main():
    parser = argparse.ArgumentParser(description="Normal OPC UA traffic generator")
    parser.add_argument("--url", default="opc.tcp://127.0.0.1:4840/cps/")
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument("--poll-gap", type=float, default=1.0)
    args = parser.parse_args()

    async with Client(url=args.url) as client:
        idx = await client.get_namespace_index(NAMESPACE_URI)
        process = await client.nodes.root.get_child(
            ["0:Objects", f"{idx}:TankProcess"]
        )
        tank_level = await process.get_child(f"{idx}:TankLevel")
        setpoint = await process.get_child(f"{idx}:Setpoint")

        start = time.time()
        polls = 0

        while args.duration == 0 or (time.time() - start) < args.duration:
            level = int(await tank_level.read_value())
            sp = int(await setpoint.read_value())
            log.info("TankLevel=%d Setpoint=%d", level, sp)

            # Normal operator behavior: occasional small setpoint adjustment.
            if random.random() < 0.10:
                new_sp = max(0, min(65535, sp + random.randint(-10, 10)))
                await setpoint.write_value(ua.UInt16(new_sp))
                log.info("Normal setpoint change -> %d", new_sp)

            polls += 1
            await asyncio.sleep(max(0.05, args.poll_gap + random.uniform(-0.1, 0.1)))

        log.info("Completed %d normal OPC UA poll cycles", polls)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
