#!/usr/bin/env python3
"""Real bgpd -> Zebra SID manager -> VPP local endpoint lifecycle.
Run as root in a disposable privileged container with matching v5 binaries.
"""
import os
import subprocess
import tempfile
import time
from pathlib import Path

SIDS = ['5f00:0:1:100:1::', '5f00:0:1:100:2::']
SERVICE = f'srv6 source 2001:db8::1 unicast {SIDS[0]} multicast {SIDS[1]}'


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def wait_for(predicate, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        time.sleep(0.1)
    raise AssertionError('timed out waiting for SID lifecycle state')


def main():
    assert os.geteuid() == 0
    for args in [('add', 'br100', 'type', 'bridge'),
                 ('add', 'vxlan100', 'type', 'vxlan', 'id', '100', 'local',
                  '2001:db8::1', 'dstport', '4789', 'nolearning'),
                 ('set', 'vxlan100', 'master', 'br100'),
                 ('set', 'br100', 'up'), ('set', 'vxlan100', 'up')]:
        run('ip', 'link', *args)
    with tempfile.TemporaryDirectory(prefix='evpn-sid-') as directory:
        os.chmod(directory, 0o777)
        root = Path(directory)
        processes, logs = [], []
        def start(name, args):
            log = open(root / (name + '.log'), 'w+')
            logs.append(log)
            process = subprocess.Popen(args, stdout=log, stderr=log)
            processes.append(process)
            return process
        def vty(daemon, *cmds):
            return run('vtysh', '-d', daemon, *[arg for cmd in cmds for arg in ['-c', cmd]])
        def zebra_start():
            Path('/run/frr/zebra.vty').unlink(missing_ok=True)
            process = start(f'zebra-{len(processes)}', ['/usr/lib/frr/zebra', '-f', '/dev/null',
                            '-i', '/run/frr/zebra.pid', '-z', '/run/frr/zserv.api'])
            wait_for(lambda: 'Current configuration' in vty('zebra', 'show running-config'))
            vty('zebra', 'configure terminal', 'segment-routing', 'srv6', 'locators',
                'locator pe1', 'prefix 5f00:0:1::/48 block-len 32 node-len 16 func-bits 32')
            return process
        try:
            zebra = zebra_start()
            bgpd = start('bgpd', ['/usr/lib/frr/bgpd', '-f', '/dev/null', '-S', '-p', '0',
                                 '-i', '/run/frr/bgpd.pid', '-z', '/run/frr/zserv.api'])
            wait_for(lambda: 'Current configuration' in vty('bgpd', 'show running-config'))
            vty('bgpd', 'configure terminal', 'router bgp 65000', 'bgp router-id 10.0.0.1',
                'address-family l2vpn evpn', 'advertise-all-vni', 'vni 100',
                'rd 10.0.0.1:100', 'route-target both 65000:100', SERVICE)
            cli = root / 'vpp.sock'
            config = root / 'startup.conf'
            config.write_text(f'''unix {{ nodaemon nosyslog cli-listen {cli} }}
memory {{ main-heap-page-size 4k }}
buffers {{ buffers-per-numa 1024 page-size 4k }}
plugins {{ vat-path {directory} plugin default {{ disable }} plugin evpn_plugin.so {{ enable }} }}
''')
            start('vpp', ['vpp', '-c', str(config)])
            wait_for(lambda: cli.exists())
            def ctl(cmd):
                return run('vppctl', '-s', str(cli), *cmd.split())
            ctl('create bridge-domain 100')
            ctl('evpn evi add evi 100 vni 100 bd 100')
            ctl('evpn ' + SERVICE.replace('srv6 source', 'srv6 service add evi 100 bd 100 source'))
            assert 'Zebra pending/pending' in ctl('show evpn srv6')
            assert all(sid + '/128' not in ctl('show ip6 fib') for sid in SIDS)
            ctl('evpn zebra enable')
            def active():
                return 'Zebra active/active' in ctl('show evpn srv6')
            def sid_table():
                return vty('zebra', 'show segment-routing srv6 sid')
            wait_for(active)
            table = sid_table()
            assert all(sid in table for sid in SIDS) and 'VNI 100' in table and 'bgp' in table, table
            assert all(sid + '/128' in ctl('show ip6 fib') for sid in SIDS)
            print('PASS: real Zebra-owned DT2U/DT2M allocations activate both VPP /128 routes', flush=True)
            vty('bgpd', 'configure terminal', 'router bgp 65000', 'address-family l2vpn evpn',
                'vni 100', 'no srv6')
            wait_for(lambda: 'Zebra pending/pending' in ctl('show evpn srv6'))
            assert 'End.DT2' not in sid_table()
            assert all(sid + '/128' not in ctl('show ip6 fib') for sid in SIDS)
            print('PASS: removing BGP service configuration withdraws Zebra and VPP SIDs', flush=True)
            vty('bgpd', 'configure terminal', 'router bgp 65000', 'address-family l2vpn evpn',
                'vni 100', SERVICE)
            wait_for(active)
            zebra.terminate()
            zebra.wait(timeout=5)
            wait_for(lambda: 'Zebra pending/pending' in ctl('show evpn srv6'))
            assert all(sid + '/128' not in ctl('show ip6 fib') for sid in SIDS)
            zebra_start()
            wait_for(active, timeout=30)
            assert all(sid in sid_table() for sid in SIDS)
            print('PASS: Zebra restart clears VPP routes; ZAPI and provider replay restore ownership', flush=True)
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
            for process in reversed(processes):
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            for log in logs:
                log.seek(0)
                if any(p.returncode not in (0, -15) for p in processes):
                    print(log.read())
                log.close()
            for name in ['vxlan100', 'br100']:
                subprocess.run(['ip', 'link', 'del', name], check=False)


if __name__ == '__main__':
    main()
