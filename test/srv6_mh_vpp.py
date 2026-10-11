#!/usr/bin/env python3
"""Exercise compiled VPP local ES/MAC signaling with real Ethernet input.

Run as root in a disposable privileged container with VPP + evpn_plugin:
  python3 test/srv6_mh_vpp.py
No FRR daemon is needed: a test socket checks VPP's actual control messages.
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
    server.bind('\0frr-evpn-srv6')
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
            ctl('evpn es add evi 100 interface BondEthernet1 esi 00:01:00:00:00:00:00:00:00:01 source 2001:db8::2 df-pref 10')
            ctl('evpn frr enable')
            received = bytearray()

            def frame(op):
                return FRAME.pack(0x45565036, 2, op, 0, 0, 0, bytes(16), bytes(16),
                                  0, bytes(10), 0, 0, bytes(3))

            def connect():
                nonlocal client, received
                client, _ = server.accept()
                client.settimeout(10)
                received.clear()
                client.sendall(frame(1) + frame(2))  # BEGIN / END

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
                        assert fields[:2] == (0x45565036, 2), fields
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
            ctl('set interface state BondEthernet1 down')
            expect(4, 0, MAC)
            expect(6, 1, flags=0)
            ctl('set interface state BondEthernet1 up')
            expect(6, 1, flags=1)
            learn()
            expect(4, 1, MAC)
            client.close()
            connect()
            expect(6, 1, flags=1)  # Replay must register ES before MAC.
            expect(4, 1, MAC)
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
    server.close()


if __name__ == '__main__':
    main()
