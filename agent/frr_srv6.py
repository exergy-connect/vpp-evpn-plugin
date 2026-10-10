#!/usr/bin/env python3
"""Event-driven link between the EVPN plugin and FRR's native SRv6 MAC-VRF.

FRR is the sole BGP speaker. Its Unix stream carries an ordered selected-RIB
snapshot on connect followed by route selection/withdrawal events. VPP's
existing binary API carries local MAC learning/deletion events. There are no
periodic RIB reads. Transport reconnects use bounded exponential backoff.
"""
import argparse
import ipaddress
import json
import logging
import os
import queue
import re
import socket
import subprocess
import threading

LOG = logging.getLogger("evpn-srv6")
MAC = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}")


class Adapter:
    def __init__(self, vpp, config):
        self.vpp = vpp
        self.asn = int(config["asn"])
        self.services = {int(s["evi"]): int(s["vni"]) for s in config["services"]}
        self.by_vni = {vni: evi for evi, vni in self.services.items()}
        self.events = queue.Queue()
        self.remote = {evi: ({}, set()) for evi in self.services}
        self.routes = {}
        self.snapshot = None
        self.local_macs = set()
        self.pending_local = {}
        self.connected = False
        self.stream = None
        self.stop = threading.Event()

    def cli(self, command):
        reply = self.vpp.api.cli_inband(cmd=command)
        if reply.retval or reply.reply.strip():
            raise RuntimeError(f"{command}: {reply}")

    @staticmethod
    def frr(*commands):
        argv = ["vtysh"]
        for command in commands:
            argv.extend(["-c", command])
        result = subprocess.run(argv, text=True, capture_output=True, check=True, timeout=10)
        if "%" in result.stdout or result.stderr.strip():
            raise RuntimeError(result.stdout + result.stderr)
        return result.stdout

    def event(self, name, event):
        if name == "evpn_mac_learn_event" and event.evi in self.services:
            self.events.put(("local", event))

    def read_routes(self, path):
        """Block on FRR events; retry only when the transport disconnects."""
        backoff = 0.25
        while not self.stop.is_set():
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
                    stream.connect("\0" + path[1:] if path.startswith("@") else path)
                    self.stream = stream
                    backoff = 0.25
                    with stream.makefile("rb") as reader:
                        while not self.stop.is_set():
                            line = reader.readline(4097)
                            if not line:
                                break
                            if len(line) > 4096 or not line.endswith(b"\n"):
                                raise ValueError("invalid FRR event frame")
                            self.events.put(("remote", json.loads(line)))
            except (OSError, ValueError):
                LOG.exception("FRR event stream unavailable")
            finally:
                self.stream = None
                self.events.put(("disconnect", None))
            # This is connection recovery, never a periodic RIB query.
            self.stop.wait(backoff)
            backoff = min(backoff * 2, 5)

    def flush_remote(self):
        for evi in self.services:
            self.cli(f"evpn srv6 flush evi {evi}")
            self.remote[evi] = ({}, set())
        self.routes.clear()

    def flush_local(self):
        for (evi, mac), add in list(self.pending_local.items()):
            self.frr("configure terminal", f"router bgp {self.asn}",
                     "address-family l2vpn evpn", f"vni {self.services[evi]}",
                     f"{'no ' if not add else ''}srv6 mac {mac}")
            del self.pending_local[evi, mac]

    def local(self, event):
        mac = str(event.mac).lower()
        if not MAC.fullmatch(mac) or int(mac[:2], 16) & 1:
            raise ValueError(f"invalid local plugin MAC: {mac}")
        key = (event.evi, mac)
        if event.is_add:
            self.local_macs.add(key)
        else:
            self.local_macs.discard(key)
        self.pending_local[key] = bool(event.is_add)
        if self.connected:
            self.flush_local()

    def apply(self, evi):
        macs = {key: sid for (vni, kind, key), sid in self.routes.items()
                if self.by_vni.get(vni) == evi and kind == 2}
        imet = {sid for (vni, kind, key), sid in self.routes.items()
                if self.by_vni.get(vni) == evi and kind == 3}
        oldmacs, oldimet = self.remote[evi]
        for sid in sorted(imet - oldimet):
            self.cli(f"evpn srv6 imet add evi {evi} sid {sid}")
            oldimet.add(sid)
        for mac, sid in sorted(macs.items()):
            if oldmacs.get(mac) != sid:
                self.cli(f"evpn srv6 mac add evi {evi} {mac} sid {sid}")
                oldmacs[mac] = sid
        for mac in sorted(oldmacs.keys() - macs.keys()):
            self.cli(f"evpn srv6 mac del evi {evi} {mac}")
            del oldmacs[mac]
        for sid in sorted(oldimet - imet):
            self.cli(f"evpn srv6 imet del evi {evi} sid {sid}")
            oldimet.remove(sid)

    def remote_event(self, event):
        kind = event["event"]
        if kind == "begin":
            self.connected = False
            self.snapshot = {}
        elif kind == "end":
            if self.snapshot is None:
                raise ValueError("FRR snapshot end without begin")
            self.routes = self.snapshot
            self.snapshot = None
            for evi in self.services:
                self.apply(evi)
            self.connected = True
            for key in self.local_macs:
                self.pending_local[key] = True
            self.flush_local()
        elif kind == "local-sync":
            if int(event["vni"]) in self.by_vni:
                reply = self.vpp.api.want_evpn_learn_events(enable_disable=True, pid=os.getpid())
                if reply.retval:
                    raise RuntimeError("local MAC replay subscription failed")
        elif kind == "route":
            vni, route_type = int(event["vni"]), int(event["type"])
            if vni not in self.by_vni or route_type not in (2, 3):
                return
            key = event["key"].lower()
            if route_type == 2 and (not MAC.fullmatch(key) or int(key[:2], 16) & 1):
                raise ValueError(f"invalid remote MAC: {key}")
            if route_type == 3:
                key = str(ipaddress.ip_address(key))
            routes = self.routes if self.snapshot is None else self.snapshot
            route_key = (vni, route_type, key)
            if event["add"]:
                sid = ipaddress.IPv6Address(event["sid"])
                if sid.is_unspecified or sid.is_multicast:
                    raise ValueError(f"invalid service SID: {sid}")
                routes[route_key] = str(sid)
            else:
                routes.pop(route_key, None)
            if self.snapshot is None:
                self.apply(self.by_vni[vni])
        else:
            raise ValueError(f"unknown FRR event: {kind}")

    def run(self, path):
        self.flush_remote()
        self.vpp.register_event_callback(self.event)
        reply = self.vpp.api.want_evpn_learn_events(enable_disable=True, pid=os.getpid())
        if reply.retval:
            raise RuntimeError(f"MAC event subscription failed: {reply.retval}")
        reader = threading.Thread(target=self.read_routes, args=(path,), daemon=True)
        reader.start()
        try:
            while True:
                kind, event = self.events.get()  # No timeout: block until an event.
                try:
                    if kind == "local":
                        self.local(event)
                    elif kind == "remote":
                        self.remote_event(event)
                    elif kind == "disconnect":
                        self.connected = False
                        self.snapshot = None
                        self.flush_remote()
                except Exception:
                    LOG.exception("event application failed; reconnecting for a fresh snapshot")
                    self.connected = False
                    self.snapshot = None
                    self.flush_remote()
                    if self.stream is not None:
                        try:
                            self.stream.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
        finally:
            self.stop.set()
            if self.stream is not None:
                self.stream.shutdown(socket.SHUT_RDWR)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--socket", default="/run/vpp/api.sock")
    parser.add_argument("--frr-socket", default="@frr-evpn-srv6")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    with open(args.config) as file:
        config = json.load(file)
    from vpp_papi import VPPApiClient
    vpp = VPPApiClient(use_socket=True, server_address=args.socket)
    vpp.connect("frr-srv6-evpn")
    try:
        Adapter(vpp, config).run(args.frr_socket)
    finally:
        vpp.disconnect()


if __name__ == "__main__":
    main()
