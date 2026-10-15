#!/usr/bin/env python3
"""Exercise native Zebra -> bgpd local ES/MAC signaling in a disposable container.

Requires root, iproute2, and matching compiled zebra/bgpd/vtysh. The VPP client
is simulated; route origination, MAC synchronization and DF election are FRR's.
"""
import json
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
    ip('link', 'add', 'br100', 'type', 'bridge', 'vlan_filtering', '1', 'vlan_default_pvid', '0')
    ip('link', 'add', 'vxlan100', 'type', 'vxlan', 'id', '100', 'local', '2001:db8::1', 'dstport', '4789', 'nolearning')
    ip('link', 'add', 'BondEthernet1', 'type', 'bond', 'mode', 'active-backup')
    ip('link', 'add', 'es1', 'type', 'dummy')
    ip('link', 'set', 'es1', 'master', 'BondEthernet1')
    for name in ['vxlan100', 'BondEthernet1']:
        ip('link', 'set', name, 'master', 'br100')
    for name in ['BondEthernet1', 'vxlan100']:
        subprocess.run(['bridge', 'vlan', 'add', 'dev', name, 'vid', '100', 'pvid', 'untagged'], check=True)
    for name in ['br100', 'es1', 'BondEthernet1', 'vxlan100']:
        ip('link', 'set', name, 'up')
    with tempfile.TemporaryDirectory(prefix='frr-mh-') as directory:
        os.chmod(directory, 0o777)
        zebra_config = Path(directory) / 'zebra.conf'
        zebra_config.write_text('hostname mh-test\nevpn mh startup-delay 1\nevpn mh redirect-off\nsegment-routing\n srv6\n  locators\n   locator mh-test\n    prefix 5f00:0:1::/48 block-len 32 node-len 16 func-bits 32\n')
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
                    assert fields[:3] == (0x45565036, 6, op), fields
                return sock

            def send(op, add=1, up=1, vni=100):
                name = f'vxlan{vni}' if op == 9 else 'BondEthernet1'
                client.sendall(FRAME.pack(0x45565036, 6, op, 2 if op == 4 else 4, add, vni,
                                         MAC + bytes(10) if op == 4 else bytes(16), bytes(16),
                                         socket.if_nametoindex(name), ESI if op == 6 else bytes(10),
                                         10, up if op == 6 else 0, bytes(3)))

            wait_for(lambda: '100' in show('show evpn vni', 'zebra'))
            def local_sids():
                return json.loads(show('show segment-routing srv6 sid json', 'zebra'))
            wait_for(lambda: 'End.DT2U' in str(local_sids()) and 'End.DT2M' in str(local_sids()))
            sid_table = show('show segment-routing srv6 sid', 'zebra')
            assert 'bgp' in sid_table and 'explicit' in sid_table and 'VNI 100' in sid_table, sid_table
            print('PASS: Zebra owns explicit End.DT2U/DT2M allocations for VNI 100', flush=True)
            client = connect()
            pending_frames = bytearray()
            def endpoints(add):
                found = {}
                end = time.monotonic() + 5
                while time.monotonic() < end and len(found) < 2:
                    if select.select([client], [], [], 0.1)[0]:
                        chunk = client.recv(4096)
                        assert chunk, 'provider disconnected while programming local SIDs'
                        pending_frames.extend(chunk)
                    while len(pending_frames) >= FRAME.size:
                        fields = FRAME.unpack(pending_frames[:FRAME.size])
                        del pending_frames[:FRAME.size]
                        if fields[2] == 13 and fields[4] == add:
                            found[fields[3]] = fields
                assert set(found) == {2, 3}, found
                for kind, fields in found.items():
                    assert fields[5] == 100
                    assert fields[6] == socket.inet_pton(socket.AF_INET6, '2001:db8::1')
                    assert fields[7] == socket.inet_pton(socket.AF_INET6, f'5f00:0:1:100:{kind-1}::')
            send(9)
            endpoints(1)
            print('PASS: Zebra programs both owned local endpoints into its VPP provider', flush=True)
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
            subprocess.run(['vtysh', '-d', 'bgpd', '-c', 'configure terminal', '-c', 'router bgp 65000',
                            '-c', 'address-family l2vpn evpn', '-c', 'vni 100', '-c', 'no srv6'], check=True)
            wait_for(lambda: 'End.DT2' not in str(local_sids()))
            endpoints(0)
            subprocess.run(['vtysh', '-d', 'bgpd', '-c', 'configure terminal', '-c', 'router bgp 65000',
                            '-c', 'address-family l2vpn evpn', '-c', 'vni 100',
                            '-c', 'srv6 source 2001:db8::1 unicast 5f00:0:1:100:1:: multicast 5f00:0:1:100:2::'], check=True)
            wait_for(lambda: 'End.DT2U' in str(local_sids()) and 'End.DT2M' in str(local_sids()))
            print('PASS: Zebra releases and reallocates EVPN local SIDs on configuration change', flush=True)
            subprocess.run(['vtysh', '-d', 'bgpd', '-c', 'configure terminal', '-c', 'router bgp 65000',
                            '-c', 'address-family l2vpn evpn', '-c', 'vni 100',
                            '-c', 'srv6 source 2001:db8::1 unicast 2001:db8:dead::1 multicast 2001:db8:dead::2'], check=True)
            wait_for(lambda: 'End.DT2' not in str(local_sids()))
            wait_for(lambda: not has_type(2) and not has_type(3))
            print('PASS: unallocatable SIDs fail closed without EVPN service advertisements', flush=True)
            subprocess.run(['vtysh', '-d', 'bgpd', '-c', 'configure terminal', '-c', 'router bgp 65000',
                            '-c', 'address-family l2vpn evpn', '-c', 'vni 100',
                            '-c', 'srv6 source 2001:db8::1 unicast 5f00:0:1:100:1:: multicast 5f00:0:1:100:2::'], check=True)
            wait_for(lambda: 'End.DT2U' in str(local_sids()) and 'End.DT2M' in str(local_sids()))
            daemons[1].terminate()
            daemons[1].wait(timeout=5)
            Path('/run/frr/bgpd.vty').unlink(missing_ok=True)
            wait_for(lambda: 'End.DT2' not in str(local_sids()))
            log = open(Path(directory) / 'bgpd-restart.log', 'w+')
            logs.append(log)
            daemons.append(subprocess.Popen(['/usr/lib/frr/bgpd', '-f', '/dev/null',
                            '-i', '/run/frr/bgpd.pid', '--vty_socket', '/run/frr',
                            '-z', '/run/frr/zserv.api', '-S', '-p', '0'], stdout=log, stderr=log))
            wait_for(lambda: Path('/run/frr/bgpd.vty').exists())
            subprocess.run(['vtysh', '-d', 'bgpd', '-f', str(bgp_config)], check=True)
            wait_for(lambda: 'End.DT2U' in str(local_sids()) and 'End.DT2M' in str(local_sids()))
            print('PASS: BGP disconnect releases SID ownership; reconnect restores allocations', flush=True)
            subprocess.run(['vtysh', '-d', 'zebra', '-c', 'configure terminal', '-c', 'segment-routing',
                            '-c', 'srv6', '-c', 'locators', '-c', 'no locator mh-test'], check=True)
            wait_for(lambda: 'End.DT2' not in str(local_sids()))
            subprocess.run(['vtysh', '-d', 'zebra', '-f', str(zebra_config)], check=True)
            wait_for(lambda: 'End.DT2U' in str(local_sids()) and 'End.DT2M' in str(local_sids()))
            print('PASS: locator deletion withdraws allocations; recreation retries pending SIDs', flush=True)
            # A second VLAN-based EVI shares the same physical bond and ESI.
            ip('link', 'add', 'vxlan101', 'type', 'vxlan', 'id', '101', 'local', '2001:db8::1', 'dstport', '4789', 'nolearning')
            ip('link', 'set', 'vxlan101', 'master', 'br100')
            for name in ['BondEthernet1', 'vxlan101']:
                subprocess.run(['bridge', 'vlan', 'add', 'dev', name, 'vid', '101', 'pvid', 'untagged'] if name == 'vxlan101' else
                               ['bridge', 'vlan', 'add', 'dev', name, 'vid', '101'], check=True)
            ip('link', 'set', 'vxlan101', 'up')
            subprocess.run(['vtysh', '-d', 'bgpd', '-c', 'configure terminal', '-c', 'router bgp 65000',
                            '-c', 'address-family l2vpn evpn', '-c', 'vni 101', '-c', 'rd 10.0.0.1:101',
                            '-c', 'route-target both 65000:101',
                            '-c', 'srv6 source 2001:db8::1 unicast 5f00:0:1:101:1:: multicast 5f00:0:1:101:2::'], check=True)
            wait_for(lambda: '101' in show('show evpn vni', 'zebra'))
            send(9, vni=101)
            send(6, vni=101)
            send(4)
            send(4, vni=101)
            def shared_mac(vni):
                return show(f'show evpn mac vni {vni} mac 02:00:00:ff:00:01', 'zebra')
            wait_for(lambda: ESI_TEXT in shared_mac(101))
            wait_for(lambda: ESI_TEXT in shared_mac(100))
            send(4, add=0)
            wait_for(lambda: ESI_TEXT not in shared_mac(100))
            assert ESI_TEXT in shared_mac(101), shared_mac(101)
            send(6, add=0)
            assert ESI_TEXT in show('show evpn es', 'zebra')
            client.close()
            client = None
            wait_for(lambda: ESI_TEXT not in show('show evpn es', 'zebra'))
            client = connect()
            send(9, vni=101)
            send(6, vni=101)
            send(4, vni=101)
            wait_for(lambda: ESI_TEXT in shared_mac(101))
            print('PASS: trunk bond shares one ESI across VLAN-based EVIs; MAC isolation, EVI withdrawal and replay', flush=True)

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
            for name in ['vxlan101', 'vxlan100', 'BondEthernet1', 'es1', 'br100']:
                subprocess.run(['ip', 'link', 'del', name], check=False)


if __name__ == '__main__':
    main()
