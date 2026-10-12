#!/usr/bin/env python3
"""Exercise compiled VPP local ES/MAC signaling with real Ethernet input.

Run as root in a disposable privileged container with VPP + evpn_plugin:
  python3 test/srv6_mh_vpp.py
No FRR daemon is needed: a test socket checks VPP's actual control messages.
"""
import os
import re
import select
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path

FRAME = struct.Struct('!IBBBBI16s16sI10sHB3s')
ESI = bytes.fromhex('00010000000000000001')
MAC = bytes.fromhex('020000ff0001')


def command(*args):
    return subprocess.check_output(args, text=True)


def wait_for(predicate, timeout=10):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        value = predicate()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError('timed out')


def main():
    assert os.geteuid() == 0, 'requires root in a disposable container'
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind('\0zebra-evpn-srv6')
    server.listen(1)
    server.settimeout(10)
    with tempfile.TemporaryDirectory(prefix='evpn-mh-') as directory:
        cli = directory + '/cli.sock'
        config = Path(directory) / 'startup.conf'
        config.write_text(f'''unix {{ nodaemon nosyslog cli-listen {cli} }}
memory {{ main-heap-page-size 4k }}
buffers {{ buffers-per-numa 1024 page-size 4k }}
plugins {{ vat-path {directory} plugin default {{ disable }}
 plugin evpn_plugin.so {{ enable }} plugin af_packet_plugin.so {{ enable }} }}
''')
        log = open(Path(directory) / 'vpp.log', 'w+')
        vpp = subprocess.Popen(['vpp', '-c', str(config)], stdout=log, stderr=log)
        client = None
        try:
            wait_for(lambda: Path(cli).exists())

            def ctl(text):
                result = command('vppctl', '-s', cli, *text.split())
                assert not any(word in result.lower() for word in
                               ['unknown input', 'failed', 'required', 'already in use']), result
                return result

            command('ip', 'link', 'add', 'mh-access', 'type', 'veth', 'peer', 'name', 'mh-host')
            for interface in ['mh-access', 'mh-host']:
                command('ip', 'link', 'set', interface, 'up')
            ctl('create host-interface name mh-access')
            ctl('set interface state host-mh-access up')
            ctl('create bond mode active-backup id 1')
            ctl('bond add BondEthernet1 host-mh-access')
            ctl('set interface state BondEthernet1 up')
            ctl('create bridge-domain 100')
            ctl('set interface l2 bridge BondEthernet1 100')
            ctl('evpn evi add evi 100 vni 100 bd 100')
            ctl('evpn srv6 service add evi 100 bd 100 source 2001:db8::2 unicast 5f00:0:1:100:1:: multicast 5f00:0:1:100:2::')
            assert 'Zebra pending/pending' in ctl('show evpn srv6')
            assert '5f00:0:1:100:1::/128' not in ctl('show ip6 fib')
            ctl('evpn es add evi 100 interface BondEthernet1 esi 00:01:00:00:00:00:00:00:00:01 source 2001:db8::2 df-pref 10')
            command('ip', 'link', 'add', 'br100', 'type', 'bridge')
            command('ip', 'link', 'add', 'BondEthernet1', 'type', 'dummy')
            linux_bond = socket.if_nametoindex('BondEthernet1')
            ctl('evpn zebra enable')
            received = bytearray()

            def frame(op):
                return FRAME.pack(0x45565036, 5, op, 0, 0, 0, bytes(16), bytes(16),
                                  0, bytes(10), 0, 0, bytes(3))

            def connect():
                nonlocal client, received
                client, _ = server.accept()
                client.settimeout(10)
                received.clear()
                client.sendall(frame(1) + frame(2))  # BEGIN / END
                for kind in [2, 3]:
                    client.sendall(FRAME.pack(0x45565036, 5, 13, kind, 1, 100,
                                   socket.inet_pton(socket.AF_INET6, '2001:db8::2'),
                                   socket.inet_pton(socket.AF_INET6, f'5f00:0:1:100:{kind-1}::'),
                                   0, bytes(10), 0, 0, bytes(3)))

            def expect(op, add, key=None, flags=None, esi=ESI):
                until = time.monotonic() + 10
                while time.monotonic() < until:
                    if len(received) < FRAME.size:
                        if not select.select([client], [], [], 0.1)[0]:
                            continue
                        chunk = client.recv(4096)
                        assert chunk, 'unexpected disconnect'
                        received.extend(chunk)
                    while len(received) >= FRAME.size:
                        fields = FRAME.unpack(received[:FRAME.size])
                        del received[:FRAME.size]
                        assert fields[:2] == (0x45565036, 5), fields
                        if fields[2] != op or fields[4] != add:
                            continue
                        if key is not None and fields[6][:6] != key:
                            continue
                        if flags is not None and fields[11] != flags:
                            continue
                        assert fields[5] == 100 and fields[9] == esi, fields
                        if op == 6:
                            assert fields[10] == 10, fields
                        return fields
                raise AssertionError(f'missing op={op} add={add} key={key} flags={flags}')

            def learn():
                packet = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                try:
                    packet.bind(('mh-host', 0))
                    packet.send(bytes.fromhex('ffffffffffff') + MAC + bytes.fromhex('88b5') + bytes(46))
                finally:
                    packet.close()

            connect()
            es = expect(6, 1, flags=1)
            learn()
            mac = expect(4, 1, MAC)
            assert mac[8] == es[8], 'MAC attachment must match ES bond'
            # Real SRv6 frames exercise the egress decision after L2 replication.
            command('ip', 'link', 'add', 'mh-core', 'type', 'veth', 'peer', 'name', 'mh-wire')
            for interface in ['mh-core', 'mh-wire']:
                command('ip', 'link', 'set', interface, 'up')
            ctl('create host-interface name mh-core')
            ctl('set interface state host-mh-core up')
            ctl('set interface ip address host-mh-core 2001:db8:ffff::2/64')
            core_mac = bytes.fromhex(re.search(r'([0-9a-f]{2}:){5}[0-9a-f]{2}', ctl('show hardware-interfaces host-mh-core')).group().replace(':', ''))
            ctl('ip route add ::/0 via 2001:db8:ffff::1 host-mh-core')
            receiver = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            receiver.bind(('mh-host', 0))
            sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            sender.bind(('mh-wire', 0))

            def control(op, flags=0, peer='2001:db8::3'):
                client.sendall(FRAME.pack(0x45565036, 5, op, 4, 1, 0, bytes(16),
                               socket.inet_pton(socket.AF_INET6, peer), es[8], bytes(10),
                               0, flags, bytes(3)))

            def inject(name, expect_delivery, origin='2001:db8::4', unicast=False, unknown=False, ether_type=0x88b5, target=MAC):
                receiver.setblocking(False)
                try:
                    while receiver.recv(4096):
                        pass
                except BlockingIOError:
                    pass
                inner = (target if unicast else bytes.fromhex('0200fffffffe') if unknown else b'\xff' * 6)
                inner += bytes.fromhex('0200aabbccdd') + struct.pack('!H', ether_type) + name.encode()
                inner = inner.ljust(60, b'\0')
                ip = struct.pack('!IHBB', 6 << 28, len(inner), 143, 64)
                ip += socket.inet_pton(socket.AF_INET6, origin)
                ip += socket.inet_pton(socket.AF_INET6, '5f00:0:1:100:1::' if unicast else '5f00:0:1:100:2::')
                sender.send(core_mac + sender.getsockname()[4] + bytes.fromhex('86dd') + ip + inner)
                receiver.settimeout(0.3)
                copies = 0
                try:
                    while True:
                        if name.encode() in receiver.recv(4096):
                            copies += 1
                except socket.timeout:
                    pass
                assert copies == int(expect_delivery), (name, copies, ctl('show errors'))
                print('PASS:', name, flush=True)

            alias = bytes.fromhex('020000ff0002')
            def remote_mac(local=True, add=1, address=alias):
                client.sendall(FRAME.pack(0x45565036, 5, 3, 2, add, 100,
                               address + bytes(10), socket.inet_pton(socket.AF_INET6, '5f00:0:2:100:1::'),
                               linux_bond if local else 0, bytes(10), 0, 1 if local else 0, bytes(3)))
            remote_mac(True)
            wait_for(lambda: '02:00:00:ff:00:02' in ctl('show l2fib verbose'))
            inject('same-es-alias-unicast-on-non-df', True, unicast=True, target=alias)
            remote_mac(False)  # Same SID, different ES: resolve to the core.
            wait_for(lambda: any('02:00:00:ff:00:02' in line and 'evpn-srv6' in line
                                 for line in ctl('show l2fib verbose').splitlines()))
            inject('other-es-core-split-horizon', False, unicast=True, target=alias)
            remote_mac(True)
            wait_for(lambda: any('02:00:00:ff:00:02' in line and 'BondEthernet1' in line
                                 for line in ctl('show l2fib verbose').splitlines()))
            inject('same-es-alias-restored', True, unicast=True, target=alias)
            remote_mac(True, address=MAC)
            # A peer advertisement must preserve locally learned ownership.
            time.sleep(0.1)
            assert any('02:00:00:ff:00:01' in line and '*' not in line
                       for line in ctl('show l2fib verbose').splitlines()), ctl('show l2fib verbose')
            remote_mac(True, add=0)
            wait_for(lambda: '02:00:00:ff:00:02' not in ctl('show l2fib verbose'))
            inject('alias-withdrawn', False, unicast=True, target=alias)
            # Zebra supplies FDB NH and NHG IDs; VPP hashes over that membership.
            remote = bytes.fromhex('020000ff0099')
            wire = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            wire.bind(('mh-wire', 0))
            access = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            access.bind(('mh-host', 0))
            ctl('set ip neighbor host-mh-core 2001:db8:ffff::1 ' + sender.getsockname()[4].hex(':'))
            def program(op, identity=0, member=0, flags=0, peer='2001:db8::3', sid='5f00:0:2:100:1::'):
                client.sendall(FRAME.pack(0x45565036, 5, op, 2, 1, 100 if op == 10 else member,
                               socket.inet_pton(socket.AF_INET6, peer) if op == 10 else bytes(16),
                               socket.inet_pton(socket.AF_INET6, sid if op == 10 else peer),
                               identity, bytes(10), 0, flags, bytes(3)))
            program(10)
            program(10, peer='2001:db8::4', sid='5f00:0:3:100:1::')
            program(11, identity=101)
            program(11, identity=102, peer='2001:db8::4')
            program(12, identity=201, flags=2)
            program(12, identity=201, member=101, flags=1)
            program(12, identity=201, member=102, flags=1)
            program(12, identity=201)
            client.sendall(FRAME.pack(0x45565036, 5, 3, 2, 1, 100, remote + bytes(10),
                           bytes(16), 201, bytes(10), 0, 2, bytes(3)))
            wait_for(lambda: '02:00:00:ff:00:99' in ctl('show l2fib verbose'))
            def destinations(count=32):
                wire.setblocking(False)
                try:
                    while wire.recv(4096): pass
                except BlockingIOError: pass
                for i in range(count):
                    # Several independent L2 flows exercise both supplied members.
                    src = bytes.fromhex('020000ffff00')[:-1] + bytes([i])
                    access.send(remote + src + bytes.fromhex('88b5') + b'zebra-nhg'.ljust(46, b'0'))
                wire.settimeout(0.3)
                found = set()
                try:
                    while True:
                        data = wire.recv(4096)
                        if len(data) >= 54 and data[12:14] == b'\x86\xdd' and data[20] == 143:
                            found.add(socket.inet_ntop(socket.AF_INET6, data[38:54]))
                except socket.timeout: pass
                return found
            expected = {'5f00:0:2:100:1::', '5f00:0:3:100:1::'}
            assert destinations() == expected, ctl('show evpn srv6')
            program(12, identity=201, flags=2)
            program(12, identity=201, member=102, flags=1)
            program(12, identity=201)
            time.sleep(0.1)
            assert destinations() == {'5f00:0:3:100:1::'}
            program(10, peer='2001:db8::4', sid='5f00:0:3:100:9::')
            time.sleep(0.1)
            assert destinations() == {'5f00:0:3:100:9::'}
            print('PASS: Zebra NHG membership, member withdrawal and SID replacement', flush=True)
            access.close()
            wire.close()
            inject('non-df-broadcast', False)
            inject('non-df-unicast', True, unicast=True)
            inject('non-df-ip4', False, ether_type=0x0800)
            inject('non-df-ip6', False, ether_type=0x86dd)
            control(7, flags=2)
            control(8)
            control(7, flags=1)
            wait_for(lambda: 'DF yes peers 1' in ctl('show evpn es'))
            inject('df-broadcast', True)
            inject('df-ip4', True, ether_type=0x0800)
            inject('df-ip6', True, ether_type=0x86dd)
            inject('df-unknown-unicast', True, unknown=True)
            inject('same-es-broadcast', False, origin='2001:db8::3')
            inject('same-es-unknown-unicast', False, origin='2001:db8::3', unknown=True)
            inject('same-es-known-unicast', True, origin='2001:db8::3', unicast=True)
            control(7, flags=2)
            wait_for(lambda: 'DF no peers 0' in ctl('show evpn es'))
            inject('df-revoked', False)
            ctl('set interface state BondEthernet1 down')
            expect(4, 0, MAC)
            expect(6, 1, flags=0)
            ctl('set interface state BondEthernet1 up')
            expect(6, 1, flags=1)
            learn()
            expect(4, 1, MAC)
            client.close()
            wait_for(lambda: "Zebra pending/pending" in ctl("show evpn srv6"))
            assert "5f00:0:1:100:1::/128" not in ctl("show ip6 fib")
            connect()
            expect(6, 1, flags=1)  # Replay must register ES before MAC.
            expect(4, 1, MAC)
            inject('reconnect-fail-closed', False)
            sender.close()
            receiver.close()
            ctl('evpn es del evi 100 interface BondEthernet1')
            expect(4, 0, MAC)
            expect(6, 0)
            expect(4, 1, MAC, esi=bytes(10))  # Now single-homed ownership.
            ctl('evpn es add evi 100 interface BondEthernet1 esi 00:01:00:00:00:00:00:00:00:01 source 2001:db8::2 df-pref 10')
            expect(6, 1, flags=1)
            expect(4, 1, MAC)
            ctl('delete bond BondEthernet1')
            expect(4, 0, MAC)
            expect(6, 0)
            assert not ctl('show evpn es').strip(), 'ES leaked after bond deletion'
            print('PASS: Ethernet learning, ESI ownership, ES down/up, reconnect ordering, ES/bond removal')
        finally:
            if client:
                client.close()
            vpp.terminate()
            vpp.wait(timeout=10)
            log.seek(0)
            if vpp.returncode not in (0, -15):
                print(log.read())
            log.close()
            subprocess.run(['ip', 'link', 'del', 'mh-access'], check=False)
            subprocess.run(['ip', 'link', 'del', 'mh-core'], check=False)
            subprocess.run(['ip', 'link', 'del', 'br100'], check=False)
            subprocess.run(['ip', 'link', 'del', 'BondEthernet1'], check=False)
    server.close()


if __name__ == '__main__':
    main()
