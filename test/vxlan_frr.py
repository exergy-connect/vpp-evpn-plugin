#!/usr/bin/env python3
"""Real bgpd/Zebra/VPP -> Linux VXLAN interoperability, in disposable namespaces.

Requires matching built FRR+plugin, root, iproute2, ethtool, ping, and VPP af_packet.
No control messages or routes are injected: bgpd learns them over EVPN BGP.
"""
import os
import subprocess
import tempfile
import time
from pathlib import Path


def run(*args, check=True):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check).stdout


def wait_for(fn, timeout=30):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        result = fn()
        if result:
            return result
        time.sleep(.1)
    raise AssertionError('timed out waiting for FRR/VPP state')


def main():
    assert os.geteuid() == 0
    processes, logs = [], []
    namespaces = ['vx-pe1', 'vx-pe2', 'vx-h1', 'vx-h2']
    with tempfile.TemporaryDirectory(prefix='vxlan-frr-') as tmp:
        os.chmod(tmp, 0o777)
        def ns(name, *args, check=True):
            return run('ip', 'netns', 'exec', name, *args, check=check)
        def ip(name, *args):
            return ns(name, 'ip', *args)
        def spawn(name, args, logfile):
            log = open(logfile, 'w+')
            logs.append(log)
            p = subprocess.Popen(['ip', 'netns', 'exec', name, *args], stdout=log, stderr=log)
            processes.append(p)
            return p
        def show(n, text, daemon='zebra'):
            return ns('vx-pe'+str(n), 'vtysh', '--vty_socket', f'{tmp}/pe{n}', '-d', daemon, '-c', text)
        def ctl(text):
            out = ns('vx-pe1', 'vppctl', '-s', tmp+'/cli.sock', *text.split())
            assert not any(s in out.lower() for s in ['unknown input', 'failed', 'required']), (text, out)
            return out
        try:
            for name in namespaces:
                run('ip', 'netns', 'add', name)
                ip(name, 'link', 'set', 'lo', 'up')
            def pair(a, an, b, bn):
                run('ip', 'link', 'add', a, 'type', 'veth', 'peer', 'name', b)
                for name, space, rename in [(a, an, a), (b, bn, b)]:
                    run('ip', 'link', 'set', name, 'netns', space)
                    ip(space, 'link', 'set', rename, 'up')
            pair('mgmt1', 'vx-pe1', 'mgmt2', 'vx-pe2')
            pair('core1', 'vx-pe1', 'core2', 'vx-pe2')
            # Emulate a physical wire: AF_PACKET must receive completed UDP checksums.
            ns('vx-pe2', 'ethtool', '-K', 'core2', 'tx', 'off')
            for n in [1, 2]:
                pe = f'vx-pe{n}'
                pair(f'acc{n}', pe, f'host{n}', f'vx-h{n}')
                ip(pe, 'addr', 'add', f'198.51.100.{n}/24', 'dev', f'mgmt{n}')
                ip(pe, 'addr', 'add', f'192.0.2.{n}/32', 'dev', 'lo')
                if n == 2:
                    ip(pe, 'addr', 'add', '192.0.2.2/24', 'dev', 'core2')
                else:
                    ip(pe, 'route', 'add', '192.0.2.2/32', 'via', '198.51.100.2')
                ip(pe, 'link', 'add', 'br100', 'type', 'bridge')
                ip(pe, 'link', 'set', 'br100', 'up')
                ip(pe, 'link', 'add', 'vxlan100', 'type', 'vxlan', 'id', '100', 'local', f'192.0.2.{n}', 'dstport', '4789', 'nolearning')
                for name in [f'acc{n}', 'vxlan100']:
                    ip(pe, 'link', 'set', name, 'master', 'br100')
                    ip(pe, 'link', 'set', name, 'up')
                if n == 1:
                    # This VXLAN link is metadata only. Block kernel forwarding so
                    # successful pings prove the VPP dataplane carries the traffic.
                    ns(pe, 'tc', 'qdisc', 'add', 'dev', 'vxlan100', 'clsact')
                    for direction in ['ingress', 'egress']:
                        ns(pe, 'tc', 'filter', 'add', 'dev', 'vxlan100', direction,
                           'matchall', 'action', 'drop')
                ip(f'vx-h{n}', 'addr', 'add', f'10.10.0.{2*n}/24', 'dev', f'host{n}')
                directory = Path(tmp)/f'pe{n}'
                directory.mkdir(mode=0o777)
                directory.chmod(0o777)
                zconf = directory/'zebra.conf'
                zconf.write_text(f'hostname pe{n}\n')
                bconf = directory/'bgpd.conf'
                bconf.write_text(f'''hostname pe{n}
router bgp {65000+n}
 bgp router-id 192.0.2.{n}
 no bgp ebgp-requires-policy
 neighbor 198.51.100.{3-n} remote-as {65000+3-n}
 address-family l2vpn evpn
  neighbor 198.51.100.{3-n} activate
  advertise-all-vni
  vni 100
   rd 192.0.2.{n}:100
   route-target both 65000:100
  exit-vni
 exit-address-family
''')
                for daemon in ['zebra', 'bgpd']:
                    pidfile = directory/(daemon+'.pid')
                    pidfile.touch()
                    pidfile.chmod(0o666)
                    args = ['/usr/lib/frr/'+daemon, '-f', '/dev/null', '-i', '/run/frr/'+daemon+'.pid',
                            '--vty_socket', '/run/frr', '-z', '/run/frr/zserv.api']
                    # Keep standard FRR runtime paths inside a private mount namespace.
                    # Host AppArmor profiles can restrict bgpd to /run/frr/*.pid.
                    args = ['unshare', '--mount', '--propagation', 'private', 'sh', '-c',
                            'mount --bind "$1" /run/frr; shift; exec "$@"',
                            'frr-test', str(directory), *args]
                    spawn(pe, args, directory/(daemon+'.log'))
                    wait_for(lambda: (directory/(daemon+'.vty')).exists())
                    directory.chmod(0o777)
                    ns(pe, 'vtysh', '--vty_socket', str(directory), '-d', daemon, '-f', str(zconf if daemon == 'zebra' else bconf))
            if os.environ.get('EVPN_TEST_CAPTURE'):
                for n in [1, 2]:
                    spawn(f'vx-pe{n}', ['tcpdump', '-l', '-n', '-e', '-i', 'any', '-vv'], Path(tmp)/f'capture{n}.log')
            startup = Path(tmp)/'vpp.conf'
            startup.write_text(f'''unix {{ nodaemon nosyslog cli-listen {tmp}/cli.sock }}
memory {{ main-heap-page-size 4k }}
buffers {{ buffers-per-numa 1024 page-size 4k }}
plugins {{ plugin default {{ disable }} plugin evpn_plugin.so {{ enable }}
plugin af_packet_plugin.so {{ enable }} plugin vxlan_plugin.so {{ enable }} }}
''')
            spawn('vx-pe1', ['vpp', '-c', str(startup)], Path(tmp)/'vpp.log')
            wait_for(lambda: Path(tmp+'/cli.sock').exists())
            for name in ['core1', 'acc1']:
                ctl('create host-interface name '+name+' cksum-gso-disable')
                ctl('set interface state host-'+name+' up')
            ctl('set interface ip address host-core1 192.0.2.1/24')
            ctl('create bridge-domain 100')
            ctl('set interface l2 bridge host-acc1 100')
            ctl('evpn evi add evi 100 vni 100 bd 100')
            ctl('evpn vtep add local 192.0.2.1 remote 192.0.2.2')
            ctl('evpn learn enable')
            ctl('evpn zebra enable')
            wait_for(lambda: 'remote 192.0.2.2' in ctl('show evpn imet'))
            if os.environ.get('EVPN_TEST_CAPTURE'):
                ctl('trace add af-packet-input 100')
            # A normal ping creates local MAC ownership and checks bidirectional ARP/ICMP.
            result = ns('vx-h1', 'ping', '-c', '5', '-W', '2', '10.10.0.4', check=False)
            assert '0 received' not in result and '100% packet loss' not in result, result
            remote_mac = ip('vx-h2', '-o', 'link', 'show', 'host2').split('link/ether ')[1].split()[0]
            wait_for(lambda: remote_mac in ctl('show evpn mac'))
            assert '192.0.2.2' in ctl('show evpn mac')
            # Reconnect must withdraw and replay both Type-3 and Type-2 from real Zebra.
            ctl('evpn zebra disable')
            wait_for(lambda: remote_mac not in ctl('show evpn mac'))
            ctl('evpn zebra enable')
            wait_for(lambda: remote_mac in ctl('show evpn mac'))
            wait_for(lambda: '1 received' in ns('vx-h1', 'ping', '-c', '1', '-W', '1', '10.10.0.4', check=False))
            result = ns('vx-h1', 'ping', '-c', '3', '-W', '2', '10.10.0.4')
            assert '0% packet loss' in result, result
            def neighbor_shutdown(shutdown):
                args = ['vtysh', '--vty_socket', f'{tmp}/pe2', '-d', 'bgpd']
                for cmd in ['configure terminal', 'router bgp 65002',
                            ('' if shutdown else 'no ')+'neighbor 198.51.100.1 shutdown']:
                    args += ['-c', cmd]
                ns('vx-pe2', *args)
            neighbor_shutdown(True)
            wait_for(lambda: remote_mac not in ctl('show evpn mac') and
                     'remote 192.0.2.2' not in ctl('show evpn imet'))
            neighbor_shutdown(False)
            wait_for(lambda: remote_mac in ctl('show evpn mac') and
                     'remote 192.0.2.2' in ctl('show evpn imet'))
            wait_for(lambda: '1 received' in ns('vx-h1', 'ping', '-c', '1', '-W', '1', '10.10.0.4', check=False))
            print('PASS real FRR/VPP/Linux VXLAN: BGP Type-3/Type-2 installation and withdrawal, bidirectional ARP+ICMP, native tunnels, disconnect cleanup and replay')
        except Exception:
            for log in logs:
                log.flush()
                log.seek(0)
                print(log.name, log.read()[-4000:])
            try:
                print(ctl('show evpn'))
                print(ctl('show l2fib verbose'))
                if os.environ.get('EVPN_TEST_CAPTURE'):
                    print(ctl('show trace'))
                print(ctl('show errors'))
                print(ctl('show interface'))
                print(ns('vx-pe2', 'bridge', 'fdb', 'show'))
                print(show(1, 'show bgp l2vpn evpn route', 'bgpd'))
            except Exception:
                pass
            raise
        finally:
            for p in reversed(processes):
                p.terminate()
            for p in reversed(processes):
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()
            for name in reversed(namespaces):
                run('ip', 'netns', 'del', name, check=False)
            for log in logs:
                log.close()


if __name__ == '__main__':
    main()
