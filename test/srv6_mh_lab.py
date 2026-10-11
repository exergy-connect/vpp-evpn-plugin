#!/usr/bin/env python3
"""Check received EVPN MH routes and attachment failover in the running lab.
Run on its Docker host: python3 test/srv6_mh_lab.py [--failover]
For nested Docker, set EVPN_TEST_DOCKER='docker exec <devcontainer> docker'.
--failover briefly disables each PE's host-eth2, restoring it in finally.
"""
import argparse
import json
import os
import shlex
import subprocess
import time

ENGINE = shlex.split(os.environ.get('EVPN_TEST_DOCKER', 'docker'))
ESI = '00:01:00:00:00:00:00:00:00:01'


def run(node, *arguments):
    return subprocess.check_output(ENGINE + ['exec', node, *arguments], text=True)


def paths(kind):
    data = json.loads(run('pe3', 'vtysh', '-c',
                          'show bgp l2vpn evpn route type ' + kind + ' json'))
    def visit(value):
        if isinstance(value, dict):
            if 'routeType' in value:
                yield value
            for child in value.values():
                yield from visit(child)
        elif isinstance(value, list):
            for child in value:
                yield from visit(child)
    return list(visit(data))


def wait_for(predicate, timeout=20):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.25)
    raise AssertionError('route/state convergence timed out')


def per_es(path):
    return path.get('remoteSid') == '::' and path.get('srv6EndpointBehavior') == 24


def ping_both():
    for host, destination in [('ha', '172.16.100.6'), ('hb', '172.16.100.5')]:
        result = run(host, 'ping', '-c', '3', '-W', '2', destination)
        assert '0% packet loss' in result and 'DUP!' not in result, result
        print(result, end='', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--failover', action='store_true')
    args = parser.parse_args()
    wait_for(lambda: all('control ready' in run(n, 'vppctl', 'show', 'evpn', 'zebra')
                         for n in ['pe1', 'pe2', 'pe3']))
    wait_for(lambda: 'DF yes peers 1' in run('pe2', 'vppctl', 'show', 'evpn', 'es')
                     and 'DF no peers 1' in run('pe1', 'vppctl', 'show', 'evpn', 'es'))
    for peer in ['2001:db8::2', '2001:db8::3']:
        eads = [p for p in paths('ead') if p.get('peerId') == peer]
        assert len(eads) == 2 and all(p.get('valid') for p in eads), eads
        assert sum(per_es(p) for p in eads) == 1, eads
        assert any(p.get('peerId') == peer and p.get('valid') for p in paths('es'))
    ping_both()
    assert any(p.get('esi') == ESI and p.get('valid') for p in paths('macip'))
    print('PASS: both received Type-1/4 paths valid, zero-SID NHT, learned MAC ESI', flush=True)
    if args.failover:
        for node, peer in [('pe1', '2001:db8::2'), ('pe2', '2001:db8::3')]:
            try:
                run(node, 'vppctl', 'set', 'interface', 'state', 'host-eth2', 'down')
                def withdrawn():
                    return ('down' in run(node, 'vppctl', 'show', 'evpn', 'es')
                            and not any(p.get('peerId') == peer
                                        for kind in ['es'] for p in paths(kind))
                            and not any(p.get('peerId') == peer and per_es(p) for p in paths('ead')))
                wait_for(withdrawn)
                survivor = 'pe2' if node == 'pe1' else 'pe1'
                wait_for(lambda: 'DF yes peers 0' in run(survivor, 'vppctl', 'show', 'evpn', 'es'))
                # FRR's default retains per-EVI A-D routes while withdrawing
                # per-ES reachability and ES routes. Native MAC synchronization
                # may retain proxy Type-2 advertisements for surviving peers.
                # Validate the forwarding membership as well as withdrawal.
                nexthops = run('pe3', 'vtysh', '-c', 'show evpn es ' + ESI)
                assert peer not in nexthops, nexthops
                ping_both()
                print('PASS:', node, 'attachment-down route withdrawals and pings', flush=True)
            finally:
                run(node, 'vppctl', 'set', 'interface', 'state', 'host-eth2', 'up')
                wait_for(lambda: any(p.get('peerId') == peer and per_es(p) and p.get('valid')
                                     for p in paths('ead')))
                wait_for(lambda: 'DF yes peers 1' in run('pe2', 'vppctl', 'show', 'evpn', 'es')
                                 and 'DF no peers 1' in run('pe1', 'vppctl', 'show', 'evpn', 'es'))
                print('Recovered', node, flush=True)


if __name__ == '__main__':
    main()
