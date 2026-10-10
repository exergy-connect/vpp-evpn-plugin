#!/usr/bin/env python3
"""Inject endpoint test frames via the Linux core router from the Docker host.

Requires root, a live two-PE lab, and known local/remote host MAC entries.
Frames use experimental EtherType 0x88b5 and never alter host addresses.
"""
import argparse
import ctypes
import os
import ipaddress
import re
import socket
import struct
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--core-peer-mac", required=True)
parser.add_argument("--local-mac", required=True)
parser.add_argument("--remote-mac", required=True)
parser.add_argument("--core-if", default="eth2")
parser.add_argument("--access-if", default="eth1")
parser.add_argument("--unicast", default="5f00:0:1:100:1::")
parser.add_argument("--multicast", default="5f00:0:1:100:2::")
parser.add_argument("--pe-container", default="pe1")
parser.add_argument("--pe-pid", type=int, required=True)
parser.add_argument("--ha-pid", type=int, required=True)
args = parser.parse_args()


def mac(value):
    return bytes.fromhex(value.replace(":", ""))


def counters():
    result = subprocess.check_output(["docker", "exec", args.pe_container, "vppctl", "show evpn srv6"], text=True)
    return sum(map(int, re.findall(r"refs \d+ packets (\d+)", result)))


def netns(pid):
    fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.setns(fd, 0) != 0:
            raise OSError(ctypes.get_errno(), "setns")
    finally:
        os.close(fd)


netns(args.ha_pid)
receive = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
receive.bind((args.access_if, 0))
netns(args.pe_pid)
send = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x86dd))
send.bind((args.core_if, 0))
outer_source = send.getsockname()[4]
source = ipaddress.IPv6Address("2001:db8:feed::1").packed


def check(name, destination, sid, expect, srh=None, length_error=False, ether_type=0x88b5):
    receive.setblocking(False)
    try:
        while receive.recv(4096):
            pass
    except BlockingIOError:
        pass
    marker = name.encode()
    inner = destination + mac("02:aa:bb:cc:dd:01") + struct.pack("!H", ether_type) + marker
    inner = inner.ljust(60, b"\0")
    payload = (srh or b"") + inner
    ip = struct.pack("!IHBB", 6 << 28, len(payload) + int(length_error), 43 if srh else 143, 64)
    ip += source + ipaddress.IPv6Address(sid).packed
    before = counters()
    send.send(mac(args.core_peer_mac) + outer_source + bytes.fromhex("86dd") + ip + payload)
    receive.settimeout(0.5)
    received = False
    try:
        while True:
            frame = receive.recv(4096)
            if marker in frame:
                received = True
                break
    except socket.timeout:
        pass
    assert received == expect, (name, "received", received, "expected", expect)
    # All traffic received from the core has SHG 1. It must never be sent
    # back through any remote MAC/IMET port (also SHG 1).
    assert counters() == before, (name, "split horizon violation")
    print(f"PASS {name}", flush=True)


check("dt2u-known", mac(args.local_mac), args.unicast, True)
check("dt2u-unknown", mac("02:ff:ff:ff:ff:ff"), args.unicast, False)
check("dt2u-multicast-rejected", b"\xff" * 6, args.unicast, False)
check("dt2u-remote-split-horizon", mac(args.remote_mac), args.unicast, False)
check("dt2m-broadcast-local-only", b"\xff" * 6, args.multicast, True)
srh = bytes([143, 2, 4, 0, 0, 0, 0, 0]) + ipaddress.IPv6Address(args.unicast).packed
check("dt2u-srh-ultimate", mac(args.local_mac), args.unicast, True, srh=srh)
check("srh-not-ultimate-rejected", mac(args.local_mac), args.unicast, False,
      srh=srh[:3] + b"\1" + srh[4:])
check("srh-bad-last-entry-rejected", mac(args.local_mac), args.unicast, False,
      srh=srh[:4] + b"\7" + srh[5:])
check("ipv6-length-mismatch-rejected", mac(args.local_mac), args.unicast, False, length_error=True)
check("non-ethernet-II-rejected", mac(args.local_mac), args.unicast, False, ether_type=100)
send.close()
receive.close()
