# Native SRv6 bridged EVPN

FRR is the BGP speaker. The existing EVPN plugin provides the Ethernet
MAC-VRF dataplane. Its native `evpn_frr.c` control client connects directly
to `bgpd`: no intermediary daemon, subprocesses, or CLI commands.

The matching FRR changes are on `feature/srv6-evpn-bridging`. Build both
working trees against the lab's VPP base image:

```sh
./docker/build-srv6-evpn.sh /path/to/frr xform/vpp:srv6-evpn
```

Run this command where the Docker daemon has
`xform/vpp:linux-cp-srv6-route-sync` available. The script copies tracked and
untracked source changes, excluding ignored build outputs. FRR and the
plugin must be built together; the published VXLAN plugin image lacks this
native SRv6 extension.

Provision a bridge domain and EVI, then its local endpoints:

```text
create bridge-domain 100 learn 1 forward 1 uu-flood 1 flood 1 arp-term 0
evpn evi add evi 100 vni 10100 bd 100
evpn srv6 service add evi 100 bd 100 source 2001:db8::2 unicast 5f00:0:1:100:1:: multicast 5f00:0:1:100:2::
evpn learn enable
```

Access ports join BD 100 with split-horizon group 0. Native remote and
receive ports use group 1. FRR's VNI configuration supplies the matching
local SIDs and the service's RD/RT:

```text
router bgp 65000
 address-family l2vpn evpn
  advertise-all-vni
  vni 10100
   rd 10.0.0.2:100
   route-target both 65000:100
   srv6 source 2001:db8::2 unicast 5f00:0:1:100:1:: multicast 5f00:0:1:100:2::
  exit-vni
 exit-address-family
```

The remote SID is learned from EVPN, never configured in the lab. Applicable
standards are summarized in the [README](README.md#native-srv6-bridged-evpn):
RFC 7432 Type-2 and Type-3, RFC 8986 End.DT2U / End.DT2M with IPv6 next
header 143 (raw Ethernet), and RFC 9252's BGP Prefix-SID L2 Service TLV.
Type 2 carries a full End.DT2U SID; Type 3 carries an End.DT2M SID. VNI
identifies the MAC-VRF; it is not sent as a VXLAN identifier. A single
segment is an IPv6 header whose destination is the service SID and whose
next header is 143. Decapsulation also accepts an ultimate-segment SRH
(next header 43, routing type 4). The core needs routes to the locators and
an MTU sufficient for the original Ethernet frame plus 40 bytes of IPv6.

Enable the native control connection after provisioning the service:

```text
evpn frr enable
show evpn frr
```

When FRR runs in a different network namespace, explicitly select it:

```text
evpn frr enable netns /run/netns/dataplane
```

`evpn frr disable` disconnects and clears remote forwarding entries. It
also causes FRR to withdraw local MAC advertisements owned by the connection.
Local learning remains enabled for other plugin users.

All steady-state updates are event driven:

- The existing in-process VPP MAC event publisher directly calls the native
  FRR client. Add/delete messages invoke FRR's EVPN local route functions;
  no binary API client or `vtysh` process is involved.
- FRR pushes an ordered snapshot followed by selected Type 2/3 updates and
  withdrawals over the abstract Unix socket `@frr-evpn-srv6`. Both endpoints
  use the versioned fixed-size binary protocol in `evpn_srv6_wire.h` (FRR's
  matching copy is `bgpd/bgp_evpn_srv6_wire.h`). Network-order fields and
  bounded queues handle partial reads/writes and reject incompatible peers.
  The socket is local to the network namespace; FRR accepts only root or its
  own UID using peer credentials.
- VPP's socket readiness callbacks wake a VLIB process, which calls the native
  dataplane functions directly. It waits for events without a connected-state
  timer. Transport failures alone use a reconnect backoff. Disconnect clears
  remote entries; reconnect gets a fresh snapshot and replays local FDB MACs.
- FRR requests MAC replay after local-service reconfiguration. VPP service
  changes trigger a fresh connection snapshot.
- SID changes replace remote MAC ports. IMET destinations are retained until
  the last selected route referencing their SID is withdrawn.

`show evpn srv6` shows endpoint, remote-port, and packet counters.
`evpn srv6 flush evi 100` clears remote state while retaining local endpoints.
Remote MAC ports never participate in flooding. DT2U unknown destinations
and multicast frames are dropped; DT2M floods local attachment circuits.
Both endpoints prevent forwarding received core frames back into the core.

Current scope: full SIDs, local ES/EVI and MAC ownership signaling, default
IPv6 FIB, and one plugin connection per bgpd. SID transposition, IRB, DF enforcement,
same-ES filtering, aliasing/ECMP, and host mobility into an existing static remote MAC entry
are not implemented. The L2/L3 service attributes currently share FRR's
service storage with a TLV-type discriminator; combined L2/L3 service TLVs on one route are outside
this implementation's scope.

Validation uses the compiled FRR and VPP binaries in the running lab:
local learning and deletion, remote withdrawal/recovery, control reconnect,
SID replacement, split horizon, and full-size host traffic. Existing endpoint
packet checks are in `test/srv6_packets.py`; Python is used only to inject test
packets, never as part of the control plane.

The native transport test in `test/srv6_control.c` checks snapshot framing,
fragmented/coalesced MAC updates, and incompatible-version disconnects against
a running bgpd. Compile and run it as described in its file header, with the
VPP control client temporarily disabled. Verify the two test MACs appear and
withdraw on the peer between the test's Enter prompts, then re-enable VPP.

## Local Ethernet Segment ownership

For a native service, register each bond/EVI attachment before enabling FRR:

```
evpn es add evi 100 interface BondEthernet1 esi 00:01:00:00:00:00:00:00:00:01 source 2001:db8::2 df-pref 10
evpn frr enable netns /run/netns/dataplane
show evpn es
```

Use the same ESI on both PEs, with each PE's own source address. Bond admin
and hardware link callbacks send operational changes without polling. VPP
sends ES/EVI registration before learned MAC replay. MAC moves retain their
attachment interface and ESI; late deletes from the former interface are ignored.
FRR originates Type-4 and Type-1 routes through its existing multihoming code,
and Type-2 routes with the owning ESI. ES-down withdraws attached local MACs;
control disconnect withdraws all client-owned MACs and ES/EVI associations.
ES removal uses `evpn es del evi 100 interface BondEthernet1`; remaining learned
MACs are replayed as single-homed. Trunk subinterfaces inherit their bond's ESI.

This uses version 2 of the 64-byte control protocol, so update FRR and VPP
together. xForm provisions the VPP ES directly for native SRv6 and omits the
Linux shadow ES configuration. The runtime packet regression is
`python3 test/srv6_mh_vpp.py` in a disposable privileged VPP container.
The FRR transport regression is `python3 test/srv6_mh_frr.py` in a disposable
container with the matching bgpd and vtysh installed.

The SRv6 per-ES A-D route carries a zero End.DT2M SID for local bias
([RFC 9252 section 6.1.1](https://www.rfc-editor.org/rfc/rfc9252.html#section-6.1.1)).
FRR tracks that route's PE next hop instead of attempting to resolve `::`.
Per-EVI A-D and MAC routes continue to track their nonzero service SIDs.
FRR's default retains per-EVI A-D on a down ES; per-ES A-D, Type-4 and
client-owned MAC reachability are withdrawn.

`python3 test/srv6_mh_lab.py --failover` validates received Type-1/4 paths,
including zero-SID reachability, MAC ESI ownership and pings through either
surviving attachment in `labs/srv6/evpn-mh.xp`. It briefly disables each
PE access member and restores it even when a check fails. With both members
up, duplicate BUM traffic remains possible until DF enforcement and same-ES
filtering are implemented.
