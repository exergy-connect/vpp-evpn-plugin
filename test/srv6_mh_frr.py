#!/usr/bin/env python3
"""Exercise native Zebra -> bgpd local ES/MAC signaling in a disposable container.

Requires root, iproute2, and matching compiled zebra/bgpd/vtysh. The VPP client
is simulated; route origination, MAC synchronization and DF election are FRR's.
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


def wait_for(predicate, timeout=15):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = predicate()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError('timed out waiting for native EVPN state')


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
    def ip(*args):
        subprocess.run(['ip', *args], check=True)
    ip('link', 'add', 'br100', 'type', 'bridge')
    ip('link', 'add', 'vxlan100', 'type', 'vxlan', 'id', '100', 'local', '2001:db8::1', 'dstport', '4789', 'nolearning')
    ip('link', 'add', 'BondEthernet1', 'type', 'bond', 'mode', 'active-backup')
    ip('link', 'add', 'es1', 'type', 'dummy')
    ip('link', 'set', 'es1', 'master', 'BondEthernet1')
    for name in ['vxlan100', 'BondEthernet1']:
        ip('link', 'set', name, 'master', 'br100')
    for name in ['br100', 'es1', 'BondEthernet1', 'vxlan100']:
        ip('link', 'set', name, 'up')
    with tempfile.TemporaryDirectory(prefix='frr-mh-') as directory:
        os.chmod(directory, 0o777)
        zebra_config = Path(directory) / 'zebra.conf'
        zebra_config.write_text('hostname mh-test\nevpn mh startup-delay 1\nevpn mh redirect-off\n')
        bgp_config = Path(directory) / 'bgpd.conf'
        bgp_config.write_text('''hostname mh-test
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
        daemons, logs = [], []
        client = None
        try:
            for name, config in [('zebra', zebra_config), ('bgpd', bgp_config)]:
                log = open(Path(directory) / (name + '.log'), 'w+')
                logs.append(log)
                args = ['/usr/lib/frr/' + name, '-f', '/dev/null', '-i', '/run/frr/' + name + '.pid',
                        '--vty_socket', '/run/frr', '-z', '/run/frr/zserv.api']
                args += ['-S', '-p', '0'] if name == 'bgpd' else []
                daemons.append(subprocess.Popen(args, stdout=log, stderr=log))
                wait_for(lambda: Path('/run/frr/' + name + '.vty').exists())
                os.chmod(directory, 0o777)
                subprocess.run(['vtysh', '--vty_socket', '/run/frr', '-d', name, '-f', str(config)], check=True)

            def show(text, daemon='bgpd'):
                return subprocess.check_output(['vtysh', '--vty_socket', '/run/frr', '-d', daemon, '-c', text], text=True)

            def paths():
                return [p for p in objects(json.loads(show('show bgp l2vpn evpn json'))) if 'routeType' in p]

            def has_type(kind):
                return any(p['routeType'] == kind for p in paths())

            def has_mac():
                return '02:00:00:ff:00:01' in show('show bgp l2vpn evpn route type macip')

            def connect():
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(15)
                sock.connect('\0zebra-evpn-srv6')
                for op in [1, 2]:
                    data = bytearray()
                    while len(data) < FRAME.size:
                        data.extend(sock.recv(FRAME.size - len(data)))
                    fields = FRAME.unpack(data)
                    assert fields[:3] == (0x45565036, 4, op), fields
                return sock

            def send(op, add=1, up=1):
                name = 'br100' if op == 9 else 'BondEthernet1'
                client.sendall(FRAME.pack(0x45565036, 4, op, 2 if op == 4 else 4, add, 100,
                                         MAC + bytes(10) if op == 4 else bytes(16), bytes(16),
                                         socket.if_nametoindex(name), ESI if op == 6 else bytes(10),
                                         10, up if op == 6 else 0, bytes(3)))

            wait_for(lambda: '100' in show('show evpn vni', 'zebra'))
            client = connect()
            send(9)
            send(6)
            wait_for(lambda: has_type(4) and has_type(1))
            wait_for(lambda: 'DF status: df' in show('show evpn es detail', 'zebra'))
            print('PASS: native Zebra ES/EVI registration, Type-1/4 origination, DF election', flush=True)
            send(4)
            wait_for(lambda: has_mac())
            macs = show('show evpn mac vni 100 mac 02:00:00:ff:00:01', 'zebra')
            assert '02:00:00:ff:00:01' in macs and ESI_TEXT in macs, macs
            print('PASS: VPP MAC ownership enters native Zebra MAC database and bgpd', flush=True)
            send(4, add=0)
            send(6, up=0)
            wait_for(lambda: not has_mac() and not has_type(4))
            print('PASS: native attachment-down withdrawals', flush=True)
            send(6)
            send(4)
            wait_for(lambda: has_mac() and has_type(4))
            client.close()
            client = None
            wait_for(lambda: not has_mac() and not has_type(4))
            client = connect()
            send(9)
            send(6)
            send(4)
            wait_for(lambda: has_mac() and has_type(4))
            print('PASS: disconnect withdrawals and local-state replay through ZAPI', flush=True)
        finally:
            if client:
                client.close()
            for daemon in reversed(daemons):
                daemon.terminate()
                daemon.wait(timeout=10)
            for log in logs:
                log.seek(0)
                print(log.read())
                log.close()
            for name in ['vxlan100', 'BondEthernet1', 'es1', 'br100']:
                subprocess.run(['ip', 'link', 'del', name], check=False)


if __name__ == '__main__':
    main()
