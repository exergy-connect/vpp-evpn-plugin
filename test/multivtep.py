"""Multi-VTEP Type-5 regression; run in a fresh disposable VPP container.

    python3 test/multivtep.py CONTAINER

Runs registration checks first to provision the borrowed infrastructure.
"""
from registration import cli
import re

cli('evpn vrf add table 1 l3-vni 50000')


def add(prefix, remote, mac):
    cli(f'evpn prefix add table 1 {prefix} remote {remote} router-mac {mac}')


def delete(prefix):
    cli(f'evpn prefix del table 1 {prefix}')


def neighbors():
    return dict(re.findall(r'(169\.254\.\d+\.\d+)\s+S\s+([0-9a-f:]+)',
                           cli('show ip neighbors')))


mac3 = '02:00:00:00:00:03'
mac4 = '02:00:00:00:00:04'
mac5 = '02:00:00:00:00:05'
for remote in ['10.0.0.3', '10.0.0.4', '10.1.0.3']:
    cli(f'evpn vtep add local 10.0.0.1 remote {remote}')
add('172.16.30.0/24', '10.0.0.3', mac3)
add('172.16.40.0/24', '10.0.0.4', mac4)
assert set(neighbors().values()) == {mac3, mac4}, neighbors()
# Same low 16 bits must probe past the occupied overlay address.
add('172.16.50.0/24', '10.1.0.3', mac5)
assert set(neighbors().values()) == {mac3, mac4, mac5}, neighbors()
# Several prefixes share one adjacency and one router-MAC entry.
add('172.16.31.0/24', '10.0.0.3', mac3)
before = neighbors()
add('172.16.31.0/24', '10.0.0.3', mac3)
assert neighbors() == before
assert 'ref 2' in cli('show evpn tunnel')
delete('172.16.30.0/24')
assert neighbors() == before
assert mac3 in cli('show l2fib verbose')
# Moving the surviving prefix must release only the old peer's state.
add('172.16.31.0/24', '10.0.0.4', mac4)
assert set(neighbors().values()) == {mac4, mac5}, neighbors()
assert mac3 not in cli('show l2fib verbose')
delete('172.16.31.0/24')
assert mac4 in cli('show l2fib verbose')
assert set(neighbors().values()) == {mac4, mac5}
delete('172.16.40.0/24')
delete('172.16.50.0/24')
assert not neighbors()
fdb = cli('show l2fib verbose')
assert all(mac not in fdb for mac in [mac3, mac4, mac5]), fdb
assert 'vni 50000' not in cli('show evpn tunnel')
cli('evpn vrf del table 1')
print('PASS: distinct VTEPs, hash collision, shared withdrawal, idempotence, move, cleanup')
