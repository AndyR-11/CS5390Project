"""Bounded loopback-only multi-master Modbus lab and OPC UA gateway.
Three masters own HR1, HR2 and HR3; the monitor reads HR0..HR3 only.
Attacks run from a seeded randomly selected master on its normal connection
(write-without-read uses that master's fresh connection).
"""
import asyncio
import hashlib
import json
from pathlib import Path
import random
import socket
import socketserver
import struct
import threading
import time

from .streams import frames


class EventLog:
    def __init__(self):
        self.events = []
        self.lock = threading.Lock()

    def add(self, raw, connection, client, label='normal'):
        with self.lock:
            self.events.append({'event_id': len(self.events), 'ts': time.time(),
                                'connection': list(connection), 'client': client,
                                'label': label, 'sha256': hashlib.sha256(raw).hexdigest(),
                                'raw_hex': raw.hex()})

    def save(self, path):
        Path(path).write_text(''.join(json.dumps(e)+'\n' for e in self.events), encoding='utf-8')


def recv_exact(sock, size):
    data = b''
    while len(data) < size:
        chunk = sock.recv(size-len(data))
        if not chunk:
            raise EOFError('connection closed')
        data += chunk
    return data


class Process:
    def __init__(self):
        self.lock = threading.Lock()
        self.registers = [500, 500, 500, 500]
        self.last = time.monotonic()

    def request(self, body):
        unit, func = body[:2]
        with self.lock:
            now = time.monotonic()
            elapsed = now-self.last
            self.last = now
            # Shared tank affected by three independently owned controls.
            delta = ((self.registers[1]-500)+(self.registers[2]-500)-(self.registers[3]-500))*elapsed
            self.registers[0] = max(0, min(1000, self.registers[0]+delta))
            if func not in (3, 6):
                return bytes([unit, func | 128, 1])
            if len(body) != 6:
                return bytes([unit, func | 128, 3])
            address, value = struct.unpack('>HH', body[2:])
            if func == 3:
                if value < 1 or address+value > len(self.registers):
                    return bytes([unit, 131, 2])
                return bytes([unit, 3, value*2])+b''.join(
                    struct.pack('>H', int(v)) for v in self.registers[address:address+value])
            if address not in (1, 2, 3):
                return bytes([unit, 134, 2])
            self.registers[address] = value
            return body


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            while True:
                header = recv_exact(self.request, 6)
                tid, proto, size = struct.unpack('>HHH', header)
                if proto != 0 or not 2 <= size <= 254:
                    return
                body = recv_exact(self.request, size)
                response = self.server.process.request(body)
                self.request.sendall(struct.pack('>HHH', tid, 0, len(response))+response)
        except (EOFError, OSError):
            return


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_server(port=0):
    server = Server(('127.0.0.1', port), Handler)
    server.process = Process()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class ModbusClient:
    def __init__(self, port, name, log=None, seed=0):
        self.port, self.name, self.log = port, name, log
        self.tid = random.Random(seed).randrange(1, 20000)
        self.connect()

    def connect(self):
        self.socket = socket.create_connection(('127.0.0.1', self.port), timeout=5)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def close(self):
        self.socket.close()

    def request(self, function, address, value, label='normal', fragment=False):
        self.tid = (self.tid+1) % 65536
        raw = struct.pack('>HHHBBHH', self.tid, 0, 6, 1, function, address, value)
        local, peer = self.socket.getsockname(), self.socket.getpeername()
        if self.log:
            self.log.add(raw, (*local, *peer), self.name, label)
        if fragment:
            self.socket.sendall(raw[:5])
            time.sleep(.002)
            self.socket.sendall(raw[5:])
        else:
            self.socket.sendall(raw)
        header = recv_exact(self.socket, 6)
        tid, proto, size = struct.unpack('>HHH', header)
        if tid != self.tid or proto != 0 or not 2 <= size <= 254:
            raise ValueError('Unexpected Modbus response')
        return recv_exact(self.socket, size)

    def request_bad_length(self, function, address, value, label, bad_length):
        """Lies about the MBAP length field. The server will try to read
        `bad_length` body bytes instead of the 6 actually sent, so it will
        NOT produce a clean response on this connection -- don't wait for
        one. The caller must close() and connect() again afterward."""
        self.tid = (self.tid+1) % 65536
        raw = struct.pack('>HHHBBHH', self.tid, 0, bad_length, 1, function, address, value)
        local, peer = self.socket.getsockname(), self.socket.getpeername()
        if self.log:
            self.log.add(raw, (*local, *peer), self.name, label)
        self.socket.sendall(raw)

    def request_replay(self, function, address, value, label, gap=0.05):
        """Sends the exact same raw bytes (same transaction id included)
        twice in a row."""
        self.tid = (self.tid+1) % 65536
        raw = struct.pack('>HHHBBHH', self.tid, 0, 6, 1, function, address, value)
        local, peer = self.socket.getsockname(), self.socket.getpeername()
        for i in range(2):
            if self.log:
                self.log.add(raw, (*local, *peer), self.name, label)
            self.socket.sendall(raw)
            header = recv_exact(self.socket, 6)
            tid, proto, size = struct.unpack('>HHH', header)
            if proto != 0 or not 2 <= size <= 254:
                raise ValueError('Unexpected Modbus response')
            recv_exact(self.socket, size)
            if i == 0:
                time.sleep(gap)


def run_modbus(port, log, seed, attack=None, cycles=36):
    selected = random.Random(seed).randrange(1, 4) if attack else None
    errors = []
    barrier = threading.Barrier(4)

    def worker(master):
        name = f'master_{master}' if master else 'monitor'
        client = None
        rng = random.Random(seed+100*master)
        # Randomized TIMING: a random cycle within the middle 40% of the
        # run, not always the exact midpoint -- a fixed signature shape
        # makes for a weaker test of whether detection generalizes.
        attack_cycle = rng.randint(int(cycles*0.3), int(cycles*0.7)) if master == selected else -1
        try:
            client = ModbusClient(port, name, log, seed+master)
            barrier.wait(timeout=5)
            for i in range(cycles):
                if master == selected and i == attack_cycle:
                    label = 'attack:'+attack
                    if attack == 'write_no_read':
                        client.close()
                        client.connect()
                        # Value itself stays in the normal band -- only the
                        # missing read before it is supposed to give it away.
                        client.request(6, master, rng.randint(490, 510), label)
                    elif attack == 'value_jump':
                        client.request(3, master, 1)
                        jump_value = rng.choice([rng.randint(700, 999), rng.randint(0, 200)])
                        client.request(6, master, jump_value, label)
                        client.request(6, master, rng.randint(495, 505))
                    elif attack == 'illegal_func':
                        code = rng.choice([7, 11, 17, 22, 43, 80, 97])
                        client.request(code, master, rng.randint(0, 9), label)
                    elif attack == 'read_flood':
                        for _ in range(rng.randint(40, 90)):
                            client.request(3, 0, 4, label)
                    elif attack == 'out_of_range':
                        client.request(3, 10, rng.randint(500, 9999), label)
                    elif attack == 'replay':
                        client.request_replay(3, 0, 4, label)
                    elif attack == 'bad_length':
                        client.request_bad_length(3, 10, 1, label,
                                                   bad_length=rng.choice([60, 99, 150, 200]))
                        client.close()
                        client.connect()
                    else:
                        raise ValueError('Unsupported attack')
                client.request(3, 0, 4, fragment=(i % 7 == 0))
                if master and i % 3 == 0:
                    client.request(6, master, rng.randint(495, 505))
                time.sleep(rng.uniform(.02, .04))
        except Exception as exc:
            errors.append(f'{name}: {exc!r}')
        finally:
            if client is not None:
                client.close()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)
    if errors or any(t.is_alive() for t in threads):
        raise RuntimeError(errors or 'Lab worker timeout')
    return {'selected_attacker': f'master_{selected}' if selected else None,
            'ownership': {'master_1': 1, 'master_2': 2, 'master_3': 3},
            'monitor': 'read-only HR0..HR3', 'seed': seed}


async def run_opc(port, modbus_port, log, seed, attack=None, cycles=36):
    from asyncua import Client, Server as UAServer, ua
    server = UAServer()
    await server.init()
    url = f'opc.tcp://127.0.0.1:{port}/lab/'
    server.set_endpoint(url)
    server.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    idx = await server.register_namespace('urn:cs5390:multi-master')
    process = await server.nodes.objects.add_object(idx, 'SharedTank')
    nodes = [await process.add_variable(ua.NodeId(f'HR{i}', idx), f'HR{i}', ua.UInt16(500))
             for i in range(4)]
    for node in nodes[1:]:
        await node.set_writable()
    gateway = ModbusClient(modbus_port, 'opc_gateway', seed=seed)
    stop = asyncio.Event()
    selected = random.Random(seed).randrange(1, 4) if attack else None

    async def mirror():
        previous = [500]*4
        while not stop.is_set():
            for i in (1, 2, 3):
                value = int(await nodes[i].read_value())
                if value != previous[i]:
                    await asyncio.to_thread(gateway.request, 6, i, value)
                    previous[i] = value
            response = await asyncio.to_thread(gateway.request, 3, 0, 4)
            vals = struct.unpack('>4H', response[3:])
            await nodes[0].write_value(ua.UInt16(vals[0]))
            await asyncio.sleep(.01)

    def attach_logging(client, name, label):
        """Patches a Client so every frame it sends is logged under `name`
        with whatever label[0] currently holds. Factored out so a
        session_flood attack's own short-lived throwaway connections get
        logged too, not just each worker's main, long-lived one."""
        original_connect = client.uaclient.connect_socket

        async def logged_connect(*args, **kwargs):
            await original_connect(*args, **kwargs)
            transport = client.uaclient.protocol.transport
            original_write = transport.write
            local, peer = transport.get_extra_info('sockname'), transport.get_extra_info('peername')

            def write(raw):
                for _, frame in frames(bytes(raw), 'opcua'):
                    log.add(frame, (*local[:2], *peer[:2]), name, label[0])
                return original_write(raw)
            transport.write = write
        client.uaclient.connect_socket = logged_connect

    async def worker(master):
        name = f'master_{master}' if master else 'monitor'
        client = Client(url)
        label = ['normal']
        attach_logging(client, name, label)
        rng = random.Random(seed+100*master)
        # Randomized TIMING: a random cycle within the middle 40% of the
        # run, not always the exact midpoint.
        attack_cycle = rng.randint(int(cycles*0.3), int(cycles*0.7)) if master == selected else -1
        async with client:
            reads = [client.get_node(n.nodeid) for n in nodes]
            for i in range(cycles):
                if master == selected and i == attack_cycle:
                    if attack == 'write_no_read':
                        await client.disconnect()
                        await client.connect()
                    label[0] = 'attack:'+attack
                    try:
                        if attack == 'invalid_node':
                            try:
                                await client.get_node(ua.NodeId('missing', idx)).read_value()
                            except ua.UaStatusCodeError:
                                pass
                        elif attack == 'value_jump':
                            jump_value = rng.choice([rng.randint(700, 999), rng.randint(0, 200)])
                            await reads[master].write_value(ua.UInt16(jump_value))
                        elif attack == 'write_no_read':
                            await reads[master].write_value(ua.UInt16(rng.randint(490, 510)))
                        elif attack == 'read_flood':
                            for _ in range(rng.randint(40, 90)):
                                await reads[0].read_value()
                        elif attack == 'session_flood':
                            # Rapidly open and close sessions instead of
                            # reusing this master's normal one -- a flood
                            # of new connections/sessions, not of reads.
                            for _ in range(rng.randint(15, 30)):
                                flood_client = Client(url)
                                attach_logging(flood_client, name, label)
                                async with flood_client:
                                    await flood_client.get_node(nodes[0].nodeid).read_value()
                        else:
                            raise ValueError('Unsupported attack')
                    finally:
                        label[0] = 'normal'
                    if attack == 'value_jump':
                        await reads[master].write_value(ua.UInt16(rng.randint(495, 505)))
                await client.read_values(reads)
                if master and i % 3 == 0:
                    await reads[master].write_value(ua.UInt16(rng.randint(495, 505)))
                await asyncio.sleep(rng.uniform(.02, .04))

    async with server:
        mirror_task = asyncio.create_task(mirror())
        try:
            await asyncio.gather(*(worker(i) for i in range(4)))
        finally:
            stop.set()
            await mirror_task
            gateway.close()
    return {'selected_attacker': f'master_{selected}' if selected else None,
            'ownership': {'master_1': 'HR1', 'master_2': 'HR2', 'master_3': 'HR3'},
            'monitor': 'read-only HR0..HR3', 'seed': seed,
            'gateway': 'OPC UA HR1..HR3 writes forwarded to live Modbus server'}