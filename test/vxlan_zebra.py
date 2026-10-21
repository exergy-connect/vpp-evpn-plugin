#!/usr/bin/env python3
"""Compiled VPP/Zebra protocol integration. Run in a disposable privileged container.

Checks IPv4/IPv6 VTEPs, actual VXLAN flood packets, Type-2 moves/withdrawal,
local MAC reporting, transport isolation, and reconnect cleanup/replay.
"""
import os
import select
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path

FRAME = struct.Struct('!IBBBBI16s16sI10sHB3s')
MAC = bytes.fromhex('020000000022')
HOST = bytes.fromhex('020000000011')


def command(*args):
    return subprocess.check_output(args, text=True)


def wait_for(fn, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        result = fn()
        if result:
            return result
        time.sleep(.05)
    raise AssertionError('timeout waiting for VPP state')


def address(ip):
    return socket.inet_pton(socket.AF_INET6, ip if ':' in ip else '::ffff:' + ip)


def frame(op, kind=0, add=1, key=bytes(16), peer=bytes(16), transport=1, vni=100):
    return FRAME.pack(0x45565036, 7, op, kind, add, vni, key, peer,
                      0, bytes(10), 0, 0, bytes([transport, 0, 0]))


def main():
    assert os.geteuid() == 0
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind('\0zebra-evpn-srv6')
    server.listen(1)
    server.settimeout(10)
    with tempfile.TemporaryDirectory(prefix='vxlan-zebra-') as tmp:
        cli = tmp + '/cli.sock'
        startup = Path(tmp) / 'vpp.conf'
        startup.write_text(f'''unix {{ nodaemon nosyslog cli-listen {cli} }}
memory {{ main-heap-page-size 4k }}
buffers {{ buffers-per-numa 1024 page-size 4k }}
plugins {{ plugin default {{ disable }} plugin evpn_plugin.so {{ enable }}
plugin vxlan_plugin.so {{ enable }} plugin af_packet_plugin.so {{ enable }} }}
''')
        log = open(Path(tmp) / 'vpp.log', 'w+')
        vpp = subprocess.Popen(['vpp', '-c', str(startup)], stdout=log, stderr=log)
        client = None
        try:
            wait_for(lambda: Path(cli).exists())

            def ctl(text):
                out = command('vppctl', '-s', cli, *text.split())
                assert not any(s in out.lower() for s in ['unknown input', 'failed', 'required']), (text, out)
                return out

            for a, b in [('vx-access', 'vx-host'), ('vx-core', 'vx-peer')]:
                command('ip', 'link', 'add', a, 'type', 'veth', 'peer', 'name', b)
                for name in [a, b]:
                    command('ip', 'link', 'set', name, 'up')
                ctl('create host-interface name ' + a)
                ctl('set interface state host-' + a + ' up')
            command('ip', 'link', 'add', 'vxlan100', 'type', 'vxlan', 'id', '100', 'local', '192.0.2.1', 'dstport', '4789')
            ctl('set interface ip address host-vx-core 192.0.2.1/24')
            ctl('set interface ip address host-vx-core 2001:db8::1/64')
            ctl('set ip neighbor host-vx-core 192.0.2.2 02:00:00:00:00:02 static')
            ctl('create bridge-domain 100')
            ctl('set interface l2 bridge host-vx-access 100')
            ctl('evpn evi add evi 100 vni 100 bd 100')
            for peer in ['192.0.2.2', '192.0.2.3', '2001:db8::2']:
                local = '2001:db8::1' if ':' in peer else '192.0.2.1'
                ctl(f'evpn vtep add local {local} remote {peer}')
            # A second EVI uses SRv6 on the same connection.
            command('ip', 'link', 'add', 'vxlan200', 'type', 'vxlan', 'id', '200', 'local', '2001:db8::1', 'dstport', '4789')
            ctl('create bridge-domain 200')
            ctl('evpn evi add evi 200 vni 200 bd 200')
            ctl('evpn srv6 service add evi 200 bd 200 source 2001:db8::1 unicast 5f00:0:1:200:1:: multicast 5f00:0:1:200:2::')
            ctl('evpn learn enable')
            ctl('evpn zebra enable')
            pending = bytearray()

            def connect():
                nonlocal client
                client, _ = server.accept()
                client.settimeout(10)
                pending.clear()
                client.sendall(frame(1) + frame(2))
                for kind in [2, 3]:
                    client.sendall(frame(13, kind, key=address('2001:db8::1'),
                                         peer=address(f'5f00:0:1:200:{kind-1}::'), transport=2, vni=200))

            def receive(op, mac=None):
                end = time.monotonic() + 10
                while time.monotonic() < end:
                    if select.select([client], [], [], .1)[0]:
                        data = client.recv(4096)
                        assert data
                        pending.extend(data)
                    while len(pending) >= FRAME.size:
                        msg = FRAME.unpack(pending[:FRAME.size])
                        del pending[:FRAME.size]
                        if msg[2] == op and (mac is None or msg[6][:6] == mac):
                            return msg
                raise AssertionError(f'no control message {op}')

            connect()
            services = [receive(9), receive(9)]
            assert {m[5]: m[3] for m in services} == {100: 1, 200: 2}, services
            client.sendall(frame(3, 3, key=address('2001:db8::2'),
                                 peer=address('5f00:0:2:200:2::'), transport=2, vni=200))
            wait_for(lambda: 'evi 200 IMET sid 5f00:0:2:200:2::' in ctl('show evpn srv6'))
            client.sendall(frame(3, 3, key=address('192.0.2.2')))
            wait_for(lambda: 'remote 192.0.2.2' in ctl('show evpn imet'))
            # ARP flooding must use the native VXLAN tunnel, not Linux's metadata interface.
            core = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            core.bind(('vx-peer', 0))
            core.settimeout(5)
            host = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            host.bind(('vx-host', 0))
            arp = b'\xff' * 6 + HOST + bytes.fromhex('08060001080006040001') + HOST + socket.inet_aton('10.10.0.2') + bytes(6) + socket.inet_aton('10.10.0.4')
            host.send(arp)
            while True:
                packet = core.recv(4096)
                if len(packet) > 50 and packet[12:14] == b'\x08\x00' and packet[23] == 17 and packet[36:38] == struct.pack('!H', 4789):
                    assert packet[46:49] == (100).to_bytes(3, 'big'), packet.hex()
                    assert packet[50:] == arp, packet.hex()
                    break
            local = receive(4, HOST)
            assert local[6][:6] == HOST, local
            for peer in ['192.0.2.2', '192.0.2.3', '2001:db8::2']:
                client.sendall(frame(3, 2, key=MAC + bytes(10), peer=address(peer)))
                wait_for(lambda: ('remote ' + peer) in ctl('show evpn mac'))
                # Duplicate adds must be idempotent.
                client.sendall(frame(3, 2, key=MAC + bytes(10), peer=address(peer)))
            # Keep explicit API-owned IMET state across control disconnect.
            ctl('evpn imet add evi 100 remote 192.0.2.3')
            client.close()
            wait_for(lambda: MAC.hex(':') not in ctl('show evpn mac'))
            wait_for(lambda: 'remote 192.0.2.2' not in ctl('show evpn imet'))
            assert 'remote 192.0.2.3' in ctl('show evpn imet')
            connect()
            receive(9)
            receive(4, HOST)  # Local MAC ownership replay.
            client.sendall(frame(3, 3, key=address('192.0.2.2')) + frame(3, 2, key=MAC + bytes(10), peer=address('192.0.2.2')))
            wait_for(lambda: MAC.hex(':') in ctl('show evpn mac'))
            client.sendall(frame(3, 2, add=0, key=MAC + bytes(10)) + frame(3, 3, add=0, key=address('192.0.2.2')))
            wait_for(lambda: MAC.hex(':') not in ctl('show evpn mac'))
            wait_for(lambda: 'remote 192.0.2.2' not in ctl('show evpn imet'))
            host.close()
            core.close()
            print('PASS mixed VXLAN/SRv6: service registration, Type-2/3 IPv4+IPv6, packet flooding, local learning, moves, idempotence, withdrawal, reconnect/replay and CLI ownership preservation')
        finally:
            if client:
                client.close()
            vpp.terminate()
            vpp.wait(timeout=10)
            for name in ['vxlan200', 'vxlan100', 'vx-access', 'vx-core']:
                subprocess.run(['ip', 'link', 'del', name], capture_output=True)
            server.close()
            log.close()


if __name__ == '__main__':
    main()
