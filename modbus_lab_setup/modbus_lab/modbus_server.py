import argparse
import logging

from pymodbus.server import StartTcpServer
from pymodbus.simulator.simdata import SimData, DataType
from pymodbus.simulator.simdevice import SimDevice

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("modbus_server")

#mutable state the "tank level" action reads/writes across requests
_state = {"level": 500, "direction": 1}


async def tank_action(function_code, start_address, address, count, current_registers, set_values):
    """Called whenever a client touches the holding/input register block.
    On a READ (set_values is None), nudge register 0 ("tank level") up or
    down a bit so traffic looks like a real, slowly changing process
    rather than a flat constant."""
    if set_values is None and function_code in (3, 4):
        _state["level"] += _state["direction"] * 2
        if _state["level"] >= 600 or _state["level"] <= 400:
            _state["direction"] *= -1
        idx = 0 - start_address
        if 0 <= idx < len(current_registers):
            current_registers[idx] = _state["level"]
    return None


def build_device():
    coils = [SimData(address=0, count=10, values=0, datatype=DataType.BITS)]
    discrete = [SimData(address=0, count=10, values=0, datatype=DataType.BITS)]
    holding = [SimData(address=0, count=10, values=500, datatype=DataType.REGISTERS)]
    inputs = [SimData(address=0, count=10, values=500, datatype=DataType.REGISTERS)]

    return SimDevice(
        id=1,
        simdata=(coils, discrete, holding, inputs),
        action=tank_action,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5020)
    args = parser.parse_args()

    device = build_device()
    log.info(f"Starting Modbus/TCP server on {args.host}:{args.port}")
    StartTcpServer(context=device, address=(args.host, args.port))


if __name__ == "__main__":
    main()
