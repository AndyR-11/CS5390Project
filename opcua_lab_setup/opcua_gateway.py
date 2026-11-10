import argparse
import asyncio
import logging

from asyncua import Server, ua
from pymodbus.client import ModbusTcpClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("opcua_gateway")

NAMESPACE_URI = "urn:cps-project:modbus-opcua-gateway"


def read_modbus_pair(client: ModbusTcpClient):
    rr = client.read_holding_registers(address=0, count=2, device_id=1)
    if rr.isError():
        raise RuntimeError(f"Modbus read failed: {rr}")
    return int(rr.registers[0]), int(rr.registers[1])


def write_modbus_setpoint(client: ModbusTcpClient, value: int):
    wr = client.write_register(address=1, value=int(value), device_id=1)
    if wr.isError():
        raise RuntimeError(f"Modbus write failed: {wr}")


async def main():
    parser = argparse.ArgumentParser(description="Modbus-to-OPC-UA gateway")
    parser.add_argument("--modbus-host", default="127.0.0.1")
    parser.add_argument("--modbus-port", type=int, default=5020)
    parser.add_argument("--opc-host", default="0.0.0.0")
    parser.add_argument("--opc-port", type=int, default=4840)
    parser.add_argument("--poll-gap", type=float, default=0.25)
    args = parser.parse_args()

    mb = ModbusTcpClient(args.modbus_host, port=args.modbus_port)
    if not mb.connect():
        raise SystemExit(
            f"Could not connect to Modbus server at {args.modbus_host}:{args.modbus_port}"
        )

    server = Server()
    await server.init()
    server.set_endpoint(f"opc.tcp://{args.opc_host}:{args.opc_port}/cps/")
    server.set_server_name("CS5390 Modbus to OPC UA Gateway")

    # Explicitly expose only an unencrypted OPC UA endpoint for this lab.
    server.set_security_policy([ua.SecurityPolicyType.NoSecurity])

    idx = await server.register_namespace(NAMESPACE_URI)
    process = await server.nodes.objects.add_object(idx, "TankProcess")

    tank_level = await process.add_variable(idx, "TankLevel", ua.UInt16(500))
    setpoint = await process.add_variable(idx, "Setpoint", ua.UInt16(500))

    # TankLevel is read-only to OPC UA clients. Setpoint is writable.
    await setpoint.set_writable()

    last_published_setpoint = 500

    log.info(
        "OPC UA endpoint: opc.tcp://127.0.0.1:%d/cps/ (Security=None)",
        args.opc_port,
    )
    log.info(
        "Gateway mapping: Modbus HR0 -> TankLevel, Modbus HR1 <-> Setpoint"
    )

    try:
        async with server:
            while True:
                # First check whether an OPC UA client changed Setpoint.
                opc_setpoint = int(await setpoint.read_value())
                if opc_setpoint != last_published_setpoint:
                    if 0 <= opc_setpoint <= 65535:
                        await asyncio.to_thread(
                            write_modbus_setpoint, mb, opc_setpoint
                        )
                        last_published_setpoint = opc_setpoint
                        log.info("OPC UA -> Modbus setpoint write: %d", opc_setpoint)
                    else:
                        log.warning("Ignoring out-of-range OPC UA value: %d", opc_setpoint)

                # Mirror current Modbus process values into OPC UA.
                level, mb_setpoint = await asyncio.to_thread(read_modbus_pair, mb)
                await tank_level.write_value(ua.UInt16(level))

                if mb_setpoint != last_published_setpoint:
                    await setpoint.write_value(ua.UInt16(mb_setpoint))
                    last_published_setpoint = mb_setpoint

                await asyncio.sleep(args.poll_gap)
    finally:
        mb.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
