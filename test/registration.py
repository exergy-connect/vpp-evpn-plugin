"""Run against a fresh, disposable VPP container with the plugin loaded.

    python3 test/registration.py CONTAINER

This provisions test objects; do not run against a deployed lab.
"""
import subprocess
import sys

container = sys.argv[1]


def cli(command, fails=False):
    result = subprocess.run(
        ['docker', 'exec', container, 'vppctl', command],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert ('failed:' in result) == fails, (command, result)
    return result


cli('evpn evi add evi 10 vni 10010 bd 10 irb', fails=True)
cli('evpn vrf add table 1 l3-vni 50000', fails=True)
# Failed registration must not have created these objects.
cli('create bridge-domain 10')
cli('evpn evi add evi 10 vni 10010 bd 10 irb', fails=True)
cli('bvi create instance 10')
cli('set interface l2 bridge bvi10 10 bvi')
cli('set interface ip address bvi10 172.16.10.1/24')
cli('set interface state bvi10 up')
cli('evpn evi add evi 10 vni 10010 bd 10 irb router-mac 02:00:00:00:00:ff', fails=True)
before = cli('show bridge-domain 10 detail'), cli('show interface address')
cli('evpn evi add evi 10 vni 10010 bd 10 irb')
cli('evpn evi del evi 10')
assert before == (cli('show bridge-domain 10 detail'), cli('show interface address'))
cli('evpn evi add evi 10 vni 10010 bd 10 irb')
cli('evpn evi del evi 10')

cli('ip table add 1')
cli('evpn vrf add table 1 l3-vni 50000', fails=True)
cli('create bridge-domain 10001')
cli('evpn vrf add table 1 l3-vni 50000', fails=True)
cli('bvi create instance 10001')
cli('set interface l2 bridge bvi10001 10001 bvi')
cli('evpn vrf add table 1 l3-vni 50000', fails=True)
cli('create loopback interface instance 0')
cli('set interface ip address loop0 10.0.0.1/32')
cli('set interface state loop0 up')
cli('set interface ip table bvi10001 1')
cli('set interface unnumbered bvi10001 use loop0')
cli('set interface state bvi10001 up')
before = cli('show bridge-domain 10001 detail'), cli('show interface address'), cli('show ip fib')
cli('evpn vrf add table 1 l3-vni 50000')
cli('evpn vrf del table 1')
assert before == (cli('show bridge-domain 10001 detail'), cli('show interface address'), cli('show ip fib'))
cli('evpn vrf add table 1 l3-vni 50000')
cli('evpn vrf del table 1')
print('PASS: prerequisite validation, MAC/binding checks, IPv4-only VRF, unregister preservation, and re-registration')

# Remote children must be withdrawn before releasing borrowed infrastructure.
cli('evpn vtep add local 10.0.0.1 remote 10.0.0.2')
cli('evpn evi add evi 10 vni 10010 bd 10 irb')
cli('evpn imet add evi 10 remote 10.0.0.2')
cli('evpn evi del evi 10', fails=True)
cli('evpn imet del evi 10 remote 10.0.0.2')
cli('evpn evi del evi 10')
cli('evpn vrf add table 1 l3-vni 50000')
cli('evpn prefix add table 1 172.16.20.0/24 remote 10.0.0.2 router-mac 02:00:00:00:00:02')
cli('evpn vrf del table 1', fails=True)
cli('evpn prefix del table 1 172.16.20.0/24')
cli('evpn vrf del table 1')
print('PASS: outstanding IMET/prefix deletion guards and withdrawal')
