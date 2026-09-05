"""Anycast gateway protection; run in a fresh disposable VPP container.

    python3 test/anycast.py CONTAINER

Provisions borrowed infrastructure; do not run against a deployed lab.
"""
import re
import subprocess
import sys
import time

container = sys.argv[1]

GW_MAC = '02:00:ca:fe:00:ff'
EXTRA_MAC = 'aa:bb:cc:dd:ee:ff'
HOST_MAC = '00:00:00:00:00:22'
VIP = '172.16.10.1'


def cli(command, fails=False):
    result = subprocess.run(
        ['docker', 'exec', container, 'vppctl', command],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert ('failed:' in result) == fails, (command, result)
    return result


def l2fib_line(mac):
    out = cli('show l2fib verbose')
    mac_l = mac.lower()
    for line in out.splitlines():
        if mac_l in line.lower():
            return line
    return ''


def assert_on_bvi(mac, label):
    line = l2fib_line(mac)
    assert line, f'{label}: missing L2FIB for {mac}\n{cli("show l2fib verbose")}'
    assert 'bvi' in line.lower() or re.search(r'\bbvi\d+\b', line), (
        f'{label}: expected BVI FDB for {mac}, got: {line}'
    )
    assert 'vxlan' not in line.lower(), (
        f'{label}: gateway MAC must not point at VXLAN: {line}'
    )


def assert_on_vxlan(mac, label):
    line = l2fib_line(mac)
    assert line, f'{label}: missing L2FIB for {mac}'
    assert 'vxlan' in line.lower(), (
        f'{label}: expected VXLAN FDB for {mac}, got: {line}'
    )


# --- Provision IRB VLAN + anycast BVI MAC/IP ---
cli('create bridge-domain 10 learn 1 forward 1 uu-flood 0 flood 1 arp-term 1')
cli('bvi create instance 10')
cli('set interface l2 bridge bvi10 10 bvi')
cli(f'set interface mac address bvi10 {GW_MAC}')
cli('set interface state bvi10 up')
cli(f'l2fib add {GW_MAC} 10 bvi10 bvi')

cli('ip table add 1')
cli('create loopback interface instance 0')
cli('set interface ip address loop0 10.0.0.1/32')
cli('set interface state loop0 up')
cli('create loopback interface instance 10001')
cli('set interface ip table loop10001 1')
cli('set interface ip address loop10001 10.255.0.1/32')
cli('set interface state loop10001 up')
cli('create bridge-domain 10001 learn 0 forward 1 uu-flood 0 flood 0 arp-term 1')
cli('bvi create instance 10001')
cli('set interface l2 bridge bvi10001 10001 bvi')
cli('set interface ip table bvi10001 1')
cli('set interface unnumbered bvi10001 use loop10001')
cli('set interface state bvi10001 up')
cli('set interface ip table bvi10 1')
cli(f'set interface ip address bvi10 {VIP}/24')

cli('evpn evi add evi 10 vni 10010 bd 10 irb')
cli('evpn vtep add local 10.0.0.1 remote 10.0.0.2')
cli('evpn learn enable')
cli('evpn logging level debug')

show = cli('show evpn evi')
assert 'src bvi' in show, show
assert VIP in show, show
assert GW_MAC in show.lower() or '02:00:ca:fe:00:ff' in show.lower(), show

# Remote Type-2 for the anycast MAC must not steal the BVI FDB.
cli(f'evpn mac add evi 10 mac {GW_MAC} ip {VIP} remote 10.0.0.2')
assert_on_bvi(GW_MAC, 'after remote Type-2 of GW MAC')
neigh = cli('show ip neighbors')
# Local VIP neighbor / connected must not be replaced by remote static.
assert 'vxlan' not in neigh.lower()

# Host Type-2 still installs to VXLAN.
cli(f'evpn mac add evi 10 mac {HOST_MAC} ip 172.16.10.22 remote 10.0.0.2')
assert_on_vxlan(HOST_MAC, 'host Type-2')

# Extra static L2FIB → BVI (macvlan analog without Linux).
cli(f'l2fib add {EXTRA_MAC} 10 bvi10 bvi')
# Learn tick refreshes protected set (~2s).
time.sleep(3)
show = cli('show evpn evi')
assert 'src l2fib-bvi' in show or EXTRA_MAC in show.lower()
cli(f'evpn mac add evi 10 mac {EXTRA_MAC} remote 10.0.0.2')
assert_on_bvi(EXTRA_MAC, 'after remote Type-2 of extra GW MAC')

# Type-2 with VIP but a foreign MAC must not install a neigh for the VIP.
FOREIGN = '00:11:22:33:44:55'
cli(f'evpn mac add evi 10 mac {FOREIGN} ip {VIP} remote 10.0.0.2')
assert_on_vxlan(FOREIGN, 'foreign MAC still gets FDB')
neigh = cli('show ip neighbors')
# Static neighbor for VIP with foreign MAC should have been skipped.
assert not re.search(rf'{VIP}\s+S\s+{FOREIGN}', neigh), neigh

print('PASS: anycast BVI/VIP protected, extra l2fib-bvi protected, host Type-2 ok')
