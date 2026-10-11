#!/usr/bin/env python3
"""Native FRR ES/MAC ownership integration test against a disposable bgpd.
Run in a container with matching bgpd/vtysh: python3 test/srv6_mh_frr.py
"""
import json
import os
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path

FRAME = struct.Struct('!IBBBBI16s16sI10sHB3s')
ESI = bytes.fromhex('00010000000000000001')
ESI_TEXT = '00:01:00:00:00:00:00:00:00:01'
MAC = bytes.fromhex('020000ff0001')


def wait_for(predicate, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = predicate()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError('timed out waiting for route state')


def objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from objects(child)


def main():
    assert os.geteuid() == 0
    with tempfile.TemporaryDirectory(prefix='frr-mh-') as directory:
        config = Path(directory) / 'bgpd.conf'
        config.write_text('''hostname mh-test
router bgp 65000
 bgp router-id 10.0.0.1
 address-family l2vpn evpn
  advertise-all-vni
  vni 100
   rd 10.0.0.1:100
   route-target both 65000:100
   srv6 source 2001:db8::1 unicast 5f00:0:1:100:1:: multicast 5f00:0:1:100:2::
  exit-vni
 exit-address-family
''')
        os.chmod(directory, 0o777)
        log = open(Path(directory) / 'bgpd.log', 'w+')
        daemon = subprocess.Popen(['/usr/lib/frr/bgpd', '-S', '-Z', '-n', '-p', '0',
                                   '-f', str(config), '-i', directory + '/bgpd.pid',
                                   '--vty_socket', directory], stdout=log, stderr=log)
        client = None
        try:
            wait_for(lambda: Path(directory + '/bgpd.vty').exists())

            def show(text):
                return json.loads(subprocess.check_output(
                    ['vtysh', '--vty_socket', directory, '-d', 'bgpd', '-c', text + ' json'], text=True))

            def paths():
                return [item for item in objects(show('show bgp l2vpn evpn')) if 'routeType' in item]

            def connect():
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect('\0frr-evpn-srv6')
                while True:
                    data = bytearray()
                    while len(data) < FRAME.size:
                        chunk = sock.recv(FRAME.size - len(data))
                        assert chunk
                        data.extend(chunk)
                    fields = FRAME.unpack(data)
                    assert fields[0:2] == (0x45565036, 2), fields
                    if fields[2] == 2:
                        return sock

            def message(op, add=1, up=1, interface=7, esi=ESI):
                return FRAME.pack(0x45565036, 2, op, 4 if op == 6 else 2, add,
                                  100, MAC + bytes(10) if op == 4 else bytes(16),
                                  socket.inet_pton(socket.AF_INET6, '2001:db8::1') if op == 6 else bytes(16),
                                  interface, esi, 10, up if op == 6 else 0, bytes(3))

            client = connect()
            # Fragment ES registration and coalesce the end with MAC add.
            registration = message(6)
            client.sendall(registration[:5])
            client.sendall(registration[5:] + message(4))
            def advertised():
                current = paths()
                return current if {1, 2, 4} <= {q['routeType'] for q in current} else None

            current = wait_for(advertised)
            mac = next(p for p in current if p['routeType'] == 2)
            assert mac.get('esi') == ESI_TEXT, mac
            assert mac.get('remoteSid') == '5f00:0:1:100:1::', mac
            eads = [p for p in current if p['routeType'] == 1]
            assert len(eads) == 2, eads
            assert {p.get('srv6EndpointBehavior') for p in eads} == {23, 24}, eads
            assert all('VXLAN' not in p.get('extendedCommunity', {}).get('string', '') for p in eads), eads
            client.sendall(message(6, up=0))
            wait_for(lambda: not any(p['routeType'] in (2, 4) for p in paths()))
            client.sendall(message(6) + message(4))
            wait_for(lambda: any(p['routeType'] == 2 for p in paths()))
            # A stale delete from a former attachment cannot remove current ownership.
            client.sendall(message(4, add=0, interface=8))
            time.sleep(0.1)
            assert any(p['routeType'] == 2 for p in paths())
            client.close()
            wait_for(lambda: not any(p['routeType'] in (1, 2, 4) for p in paths()))
            assert not show('show bgp l2vpn evpn es'), 'ES leaked after disconnect'
            client = connect()
            client.sendall(message(6) + message(4))
            wait_for(lambda: any(p['routeType'] == 2 for p in paths()))
            client.sendall(message(6, add=0))
            wait_for(lambda: not any(p['routeType'] in (1, 2, 4) for p in paths()))
            print('PASS: Type-1/2/4, ESI/SRv6 attributes, ES down/up, stale delete, disconnect cleanup, ES removal')
        finally:
            if client:
                client.close()
            daemon.terminate()
            daemon.wait(timeout=10)
            log.seek(0)
            if daemon.returncode not in (0, -15):
                print(log.read())
            log.close()


if __name__ == '__main__':
    main()
