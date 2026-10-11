#!/usr/bin/env python3
"""Check DF and local-bias forwarding in the running srv6-evpn-mh lab.
Run as root on the Docker host (requires setns and raw sockets). Tests inject
experimental Ethernet frames from p1 to both PEs and count delivery at ha.
"""
import ctypes
import json
import os
import re
import socket
import struct
import subprocess
import uuid


def docker(*args):
    return subprocess.check_output(['docker', *args], text=True)


def netns(node):
    pid = json.loads(docker('inspect', node))[0]['State']['Pid']
    fd = os.open(f'/proc/{pid}/ns/net', os.O_RDONLY)
    try:
        if ctypes.CDLL(None, use_errno=True).setns(fd, 0):
            raise OSError(ctypes.get_errno(), 'setns')
    finally:
        os.close(fd)


def main():
    assert os.geteuid() == 0
    targets = []
    for node, interface, sid in [('pe1', 'eth1', '5f00:0:1:100:2::'),
                                 ('pe2', 'eth2', '5f00:0:2:100:2::')]:
        hardware = docker('exec', node, 'vppctl', 'show', 'hardware-interfaces', 'host-eth1')
        address = bytes.fromhex(re.search(r'([0-9a-f]{2}:){5}[0-9a-f]{2}', hardware).group().replace(':', ''))
        targets.append((interface, address, sid))
    state = [docker('exec', node, 'vppctl', 'show', 'evpn', 'es') for node in ['pe1', 'pe2']]
    assert sum('DF yes' in s for s in state) == 1, state
    df = next(i for i, s in enumerate(state) if 'DF yes' in s)
    netns('ha')
    receiver = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    receiver.bind(('bond1', 0))
    netns('p1')
    senders = []
    for interface, address, sid in targets:
        sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sender.bind((interface, 0))
        senders.append(sender)

    def check(name, indices, origin, expected, destination=b'\xff' * 6):
        receiver.setblocking(False)
        try:
            while receiver.recv(4096):
                pass
        except BlockingIOError:
            pass
        marker = uuid.uuid4().bytes
        inner = (destination + bytes.fromhex('0200aabbccdd88b5') + marker).ljust(60, b'\0')
        for i in indices:
            sender = senders[i]
            _, address, sid = targets[i]
            ip = struct.pack('!IHBB', 6 << 28, len(inner), 143, 64)
            ip += socket.inet_pton(socket.AF_INET6, origin) + socket.inet_pton(socket.AF_INET6, sid)
            sender.send(address + sender.getsockname()[4] + bytes.fromhex('86dd') + ip + inner)
        receiver.settimeout(0.5)
        copies = 0
        try:
            while True:
                if marker in receiver.recv(4096):
                    copies += 1
        except socket.timeout:
            pass
        assert copies == expected, (name, copies, expected, state)
        print('PASS:', name, 'copies', copies, flush=True)

    check('both-PE-broadcast-single-delivery', [0, 1], '2001:db8::4', 1)
    check('both-PE-unknown-unicast-single-delivery', [0, 1], '2001:db8::4', 1,
          bytes.fromhex('0200fffffffe'))
    check('non-DF-broadcast-blocked', [1 - df], '2001:db8::4', 0)
    check('DF-broadcast-delivered', [df], '2001:db8::4', 1)
    check('DF-same-ES-reflection-blocked', [df], '2001:db8::3' if df == 0 else '2001:db8::2', 0)
    receiver.close()
    for sender in senders:
        sender.close()


if __name__ == '__main__':
    main()
