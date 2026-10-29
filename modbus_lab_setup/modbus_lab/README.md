# Modbus/TCP Lab -- Setup Guide

All three scripts here are tested and confirmed working (pymodbus 3.16,
Python 3.13). What's left is wiring them up across real VMs so you get
a real network capture instead of localhost loopback traffic.

## 1. VM layout

Three VMs on an **isolated, host-only network** (no bridge to your
real LAN or the internet):

| VM | Role | Runs |
|---|---|---|
| VM 1 | Server (fake PLC) | `modbus_server.py` |
| VM 2 | Client (fake HMI/SCADA) | `modbus_client.py` |
| VM 3 | Attacker + capture point | `attacker.py`, `tcpdump` |

**VirtualBox / VMware:** create a Host-Only network (VirtualBox:
File > Host Network Manager > Create). Attach all three VMs' network
adapters to it instead of NAT/Bridged. Give each a static IP, e.g.:

- VM 1 (server): 192.168.56.10
- VM 2 (client): 192.168.56.11
- VM 3 (attacker): 192.168.56.12

**Docker alternative (faster to set up, works on one machine):**

```bash
docker network create --subnet=192.168.56.0/24 modbus-lab
docker run -it --name server  --network modbus-lab --ip 192.168.56.10 python:3.13 bash
docker run -it --name client  --network modbus-lab --ip 192.168.56.11 python:3.13 bash
docker run -it --name attacker --network modbus-lab --ip 192.168.56.12 python:3.13 bash
```

Copy these three scripts into each container (`docker cp` or a shared
volume), then `pip install pymodbus` inside the server and client
containers only (the attacker script needs no extra packages).

## 2. Install dependencies

On the **server** and **client** VMs only:

```bash
pip install --break-system-packages pymodbus
```

The **attacker** script uses only Python's standard library -- nothing
to install there.

## 3. Run order

**On VM 1 (server):**
```bash
python3 modbus_server.py --host 0.0.0.0 --port 502
```
(Port 502 needs root/sudo. Use `--port 5020` if you'd rather not run as
root -- just point the client and attacker at that port instead.)

**On VM 2 (client) -- generates your NORMAL traffic:**
```bash
python3 modbus_client.py --host 192.168.56.10 --port 502 --duration 1800
```
Run this for 20-30 minutes to get a solid normal-traffic dataset. Do a
few separate runs at different times/poll-gaps rather than one long run,
so your training and test sets aren't identical in shape.

**On VM 3 (attacker) -- start the capture FIRST, then run attacks:**
```bash
sudo tcpdump -i eth0 port 502 -w attack_traffic.pcap &
python3 attacker.py --host 192.168.56.10 --port 502 --attack all
# wait a few seconds, then:
sudo kill %1   # stops tcpdump
```

Also capture a separate normal-only pcap while only the client is
running (no attacker), so you have clean traffic to measure false
positives against:
```bash
sudo tcpdump -i eth0 port 502 -w normal_traffic.pcap
```

## 4. Verify in Wireshark

Open each pcap in Wireshark. Every packet should show up as `Modbus/TCP`
in the protocol column with no "Malformed Packet" errors on the NORMAL
capture. The attack capture may show some packets Wireshark itself
flags oddly (e.g. the bad_length one) -- that's expected and is
actually useful: it's an early sanity check that your attack really
is structurally abnormal before you even run your own detector on it.

## 5. What each attack actually does on the wire (confirmed by testing)

| Attack | What happens |
|---|---|
| `illegal_func` | Server replies with a Modbus exception response (function code OR 0x80) |
| `bad_length` | Server silently drops the connection -- no response at all |
| `out_of_range` | Server rejects it with an exception; logs show the invalid count explicitly |
| `replay` | Both copies get valid responses (the register value may differ slightly between them since the simulated process keeps drifting) -- this is the one your structure detector can't catch alone, as discussed |
| `read_flood` | 50 individually-valid read requests fire back to back -- nothing wrong with any single one |

## 6. Known quirks worth knowing about

- `modbus_server.py` uses pymodbus's newer `SimDevice`/`SimData` API
  (not the older `ModbusSlaveContext` API you'll see in most pymodbus
  tutorials online -- that API is deprecated in this version and will
  be removed in v4). If you look up pymodbus examples elsewhere and
  they don't match this code, that's why.
- `read_holding_registers()` and `write_register()` take `device_id=`,
  not the `slave=` kwarg used in older pymodbus tutorials.
- The server keeps running fine even after receiving malformed
  attack traffic -- confirmed by testing a client against it
  immediately after an attack run.

## 7. Next steps (once you have real pcaps)

Feed `normal_traffic.pcap` and `attack_traffic.pcap` into the
`modbus_ids_starter` project from earlier -- replace
`generate_normal()` / `inject_attacks()` in `run_demo.py` with a real
pcap loader (e.g. using `scapy.utils.rdpcap` or `pyshark`) that builds
the same `{"raw": ..., "ts": ..., "label": ...}` message format.
Everything downstream (profile building, both detectors, evaluation)
stays unchanged.
