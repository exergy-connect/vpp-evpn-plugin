"""IPv6 dual-stack / ipv4-nh-mode; run in a fresh disposable VPP container.

    python3 test/ipv6.py CONTAINER

Provisions borrowed infrastructure; do not run against a deployed lab.
"""
import re
import subprocess
import sys

container = sys.argv[1]

LOCAL4 = '10.0.0.1'
REMOTE4 = '10.0.0.2'
LOCAL6 = 'fd00:0:0:1::1'
REMOTE6 = 'fd00:0:0:1::2'
RMAC = '02:00:00:00:00:02'


def cli(command, fails=False):
    result = subprocess.run(
        ['docker', 'exec', container, 'vppctl', command],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert ('failed:' in result) == fails, (command, result)
    return result


def neigh6():
    out = cli('show ip6 neighbors')
    # e.g. fd00:a9fe::xxxx  S  02:00:00:00:00:02  bvi10001
    return dict(re.findall(
        r'(fd00:a9fe::[0-9a-f:]+)\s+S\s+([0-9a-f:]+)', out, re.I))


def neigh4_overlay():
    out = cli('show ip neighbors')
    return dict(re.findall(
        r'(169\.254\.\d+\.\d+)\s+S\s+([0-9a-f:]+)', out))


def assert_fd00_nh(label):
    n = neigh6()
    assert n, f'{label}: expected fd00:a9fe:: neighbor\n{cli("show ip6 neighbors")}'
    assert RMAC.lower() in {m.lower() for m in n.values()}, (label, n)
    return n


# --- Underlay + classic dual-stack L3 (IPv4 donor → auto → 169.254) ---
cli('create loopback interface instance 0')
cli(f'set interface ip address loop0 {LOCAL4}/32')
cli('set interface state loop0 up')
cli(f'evpn vtep add local {LOCAL4} remote {REMOTE4}')

cli('ip table add 1')
cli('ip6 table add 1')
cli('create loopback interface instance 10001')
cli('set interface ip table loop10001 1')
cli('set interface ip6 table loop10001 1')
cli('set interface ip address loop10001 10.255.0.1/32')
cli('set interface state loop10001 up')
cli('create bridge-domain 10001 learn 0 forward 1 uu-flood 0 flood 0 arp-term 1')
cli('bvi create instance 10001')
cli('set interface l2 bridge bvi10001 10001 bvi')
cli('set interface ip table bvi10001 1')
cli('set interface ip6 table bvi10001 1')
cli('set interface unnumbered bvi10001 use loop10001')
cli('set interface state bvi10001 up')

cli('evpn vrf add table 1 l3-vni 50000')
show = cli('show evpn vrf')
assert 'ipv4-nh-mode auto' in show, show
assert 'effective ipv4' in show, show

cli(f'evpn prefix add table 1 172.16.20.0/24 remote {REMOTE4} router-mac {RMAC}')
assert neigh4_overlay(), cli('show ip neighbors')
assert not neigh6(), cli('show ip6 neighbors')
cli('evpn prefix del table 1 172.16.20.0/24')

# Force ipv6 overlay for IPv4 prefixes on a dual-stack L3 BVI.
cli('evpn vrf del table 1')
cli('evpn vrf add table 1 l3-vni 50000 ipv4-nh-mode ipv6')
show = cli('show evpn vrf')
assert 'ipv4-nh-mode ipv6' in show, show
cli(f'evpn prefix add table 1 172.16.20.0/24 remote {REMOTE4} router-mac {RMAC}')
assert_fd00_nh('forced ipv6 for IPv4 prefix')
assert not neigh4_overlay(), cli('show ip neighbors')
fib = cli('show ip fib table 1')
assert 'fd00:a9fe:' in fib or 'fd00:a9fe::' in fib, fib
cli('evpn prefix del table 1 172.16.20.0/24')
cli('evpn vrf del table 1')
print('PASS: auto→169.254 with IPv4 on BVI; ipv4-nh-mode ipv6 forces fd00:a9fe::')

# --- IPv6 Type-5 (IPv6 prefix always fd00:a9fe) + IPv6 VTEPs ---
cli(f'set interface ip address loop0 {LOCAL6}/128')
cli(f'evpn vtep add local {LOCAL6} remote {REMOTE6}')
cli('evpn vrf add table 1 l3-vni 50000')
cli(f'evpn prefix add table 1 2001:db8:20::/64 remote {REMOTE6} router-mac {RMAC}')
assert_fd00_nh('IPv6 Type-5')
fib6 = cli('show ip6 fib table 1')
assert '2001:db8:20::' in fib6 or '2001:db8:20::/64' in fib6, fib6
assert 'fd00:a9fe:' in fib6, fib6
cli('evpn prefix del table 1 2001:db8:20::/64')
cli('evpn vrf del table 1')
print('PASS: IPv6 VTEP + IPv6 Type-5 via fd00:a9fe::')

# --- IPv6-only L3 BVI: auto → RFC 8950-style IPv4-over-IPv6 NH ---
cli('set interface ip address del loop10001 10.255.0.1/32')
# Drop IPv4 unnumbered copy from BVI.
cli('set interface unnumbered del bvi10001')
cli('set interface ip address loop10001 fd00:255::1/128')
cli('set ip6 enable bvi10001')
# Prefer enable without IPv4 on BVI; strip any leftover IPv4 from unnumbered.
addrs = cli('show interface address bvi10001')
if re.search(r'\b\d+\.\d+\.\d+\.\d+\b', addrs):
    for m in re.finditer(r'(\d+\.\d+\.\d+\.\d+/\d+)', addrs):
        cli(f'set interface ip address del bvi10001 {m.group(1)}')
addrs = cli('show interface address bvi10001')
assert not re.search(r'\b\d+\.\d+\.\d+\.\d+\b', addrs), addrs

cli('evpn vrf add table 1 l3-vni 50000')  # default auto
show = cli('show evpn vrf')
assert 'ipv4-nh-mode auto' in show, show
assert 'effective ipv6' in show, show
cli(f'evpn prefix add table 1 172.16.30.0/24 remote {REMOTE4} router-mac {RMAC}')
assert_fd00_nh('auto RFC 8950 IPv4 prefix')
assert not neigh4_overlay(), cli('show ip neighbors')
cli('evpn prefix del table 1 172.16.30.0/24')
cli('evpn vrf del table 1')
print('PASS: IPv6-only L3 BVI auto uses fd00:a9fe:: for IPv4 Type-5')
print('PASS: ipv6 dual-stack / ipv4-nh-mode')
