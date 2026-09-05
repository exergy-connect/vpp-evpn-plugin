"""Live netlink tunnel creation regression in a fresh disposable container.

    python3 test/netlink.py CONTAINER

Imports registration checks to provision the borrowed VPP infrastructure.
"""
import subprocess
import time

from registration import cli, container


def ip(*args):
    subprocess.run(['docker', 'exec', container, 'ip', *args], check=True)


def wait_for_prefix(present):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        output = cli('show evpn')
        if ('172.20.0.0/24' in output) == present:
            return
        time.sleep(0.05)
    raise AssertionError(output)


cli('evpn vrf add table 1 l3-vni 50000')
cli('evpn vtep add local 10.0.0.1 remote 10.0.0.3')
cli('evpn learn enable')
ip('link', 'add', 'evpn-test', 'type', 'dummy')
try:
    ip('link', 'set', 'evpn-test', 'up')
    ip('addr', 'add', '10.0.0.1/24', 'dev', 'evpn-test')
    ip('neigh', 'add', '10.0.0.3', 'lladdr', '02:00:00:00:00:03',
       'nud', 'permanent', 'dev', 'evpn-test')
    ip('route', 'add', 'table', '1', '172.20.0.0/24', 'via', '10.0.0.3',
       'dev', 'evpn-test', 'onlink', 'proto', 'bgp')
    wait_for_prefix(True)
    assert 'vni 50000' in cli('show evpn tunnel')
    ip('route', 'del', 'table', '1', '172.20.0.0/24')
    wait_for_prefix(False)
    assert 'vni 50000' not in cli('show evpn tunnel')
finally:
    ip('link', 'del', 'evpn-test')

print('PASS: live netlink route creates and withdraws a VXLAN tunnel')
