# Native SRv6 bridged EVPN

FRR's bgpd selects EVPN routes and exchanges ES/MAC state with Zebra over
its normal ZAPI interface. Zebra owns MAC synchronization, DF election and
FDB nexthop-group membership. The VPP plugin is a Zebra dataplane backend:
`evpn_zebra.c` applies programming operations and reports local learning and
bond state. It does not inspect a BGP RIB or elect a DF.

Build the plugin with FRR's `feature/srv6-evpn-bridging` branch:

```sh
./docker/build-srv6-evpn.sh /path/to/frr xform/vpp:srv6-evpn
```

The Docker daemon needs `xform/vpp:linux-cp-srv6-route-sync`. The build copies
working-tree sources, including uncommitted changes. FRR and VPP must use
matching copies of protocol version 7 (`evpn_srv6_wire.h` in the plugin and
`zebra/zebra_evpn_srv6_wire.h` in FRR). The SID-manager ZAPI context
also carries the VNI; rebuild the FRR daemons together.

## Provisioning

Provision the VPP bridge, EVI, access interfaces and endpoint expectations.
VPP leaves the local SID routes pending until Zebra authorizes them:

```text
create bridge-domain 100 learn 1 forward 1 uu-flood 1 flood 1 arp-term 0
evpn evi add evi 100 vni 10100 bd 100
evpn srv6 service add evi 100 bd 100 source 2001:db8::2 unicast 5f00:0:1:100:1:: multicast 5f00:0:1:100:2::
evpn es add evi 100 interface BondEthernet1 esi 00:01:00:00:00:00:00:00:00:01 source 2001:db8::2 df-pref 10
evpn learn enable
```

Zebra discovers EVPN interface topology through ordinary Linux bridge,
VXLAN and bond metadata, as in the existing VPP/VXLAN integration. xForm
creates these links in the control-plane namespace. The VXLAN link maps a
VNI to a bridge and IPv6 originator; the shadow bond maps the ES to its
access bridge. Actual LACP and Ethernet forwarding run in VPP. The provider
consumes native MAC/VTEP/bridge-port operations before kernel programming;
shared FDB nexthop objects are mirrored to VPP and remain available to kernel
VXLAN users. No VXLAN header is emitted by the SRv6 dataplane.

Interface identities are Linux ifindices on the control socket, resolved
against LCP/control link names in the selected namespace. `host-eth2` maps
to Linux `eth2`; `BondEthernet1` maps to the corresponding shadow bond.
VPP reports its actual bond admin/link state. Zebra uses that state for an
owned ES instead of the metadata link's carrier.

Configure FRR with matching VNI, source and SIDs:

```text
segment-routing
 srv6
  locators
   locator pe2
    prefix 5f00:0:1::/48 block-len 32 node-len 16 func-bits 32
!
evpn mh startup-delay 1
evpn mh redirect-off
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

BGP requests the configured End.DT2U and End.DT2M addresses through Zebra's
standard SID-manager ZAPI. Zebra reserves the explicit functions, records BGP
ownership and the VNI context, and programs the VPP endpoints. The 32-bit
function spans the EVI and behavior hextets; these full service SIDs must not
use a uSID locator that interprets the behavior hextet as an argument.
`show segment-routing srv6 sid` lists both allocations with their behavior,
VNI, BGP owner, locator and explicit allocation type. BGP exports service
routes only after both allocations succeed. Configuration removal, locator
removal and BGP disconnect release ownership and withdraw VPP local routes;
reconnect replays allocations. VPP checks Zebra's endpoints against its local
service expectations and clears authorization on provider disconnect.

`redirect-off` selects native Zebra MAC reprogramming on attachment failure;
VPP does not implement bridge-port backup nexthop redirection.
Enable the connection after FRR and interface metadata are ready:

```text
evpn zebra enable netns /run/netns/dataplane
show evpn zebra
show evpn es
show evpn srv6
```

Omit `netns` when Zebra shares VPP's namespace. `evpn zebra disable` clears
remote forwarding and withdraws client-owned local state. Local learning and local service configuration survive reconnects; Zebra
replays endpoint authorization before the local SID routes become active.

## Control and forwarding

The SRv6-specific BGP extension sends full service SID metadata through ZAPI
before the existing MAC/VTEP or A-D programming. Everything else uses native
FRR EVPN processing. The Zebra provider consumes immutable dataplane contexts:

- MAC operations specify local Linux attachment, direct remote SID, or FDB
  nexthop-group ID. Native Zebra sync-MAC handling resolves same-ES MACs to
  local attachments; VPP preserves existing dynamic local FDB entries.
- VTEP operations control IMET replication destinations. SID metadata is
  keyed by VNI and PE; changes replace the encapsulation destination.
- FDB nexthop and group operations supply the IDs and membership selected
  by Zebra. VPP uses a stable Ethernet source/destination hash over that
  membership for known-unicast forwarding. Unready groups drop traffic.
- Bridge-port operations supply the native DF result and split-horizon PE
  filters. VPP preserves the outer IPv6 originator through DT2M replication
  and filters ES access egress, including VLAN subinterfaces. Non-DF BUM
  and same-ES BUM drop; DT2U known unicast remains eligible.

The abstract Unix socket is `@zebra-evpn-srv6`, restricted to root or Zebra's
UID. Fixed-size messages tolerate partial reads/writes. Main-thread local
notifications call native Zebra EVPN APIs; dataplane-thread output uses a
bounded queue and an eventfd. Connection epochs discard stale contexts.
Overflow disconnects for replay. VPP's VLIB process applies updates under
its worker barrier; only disconnected transports use a retry timer.

Reconnect registers services, then ES state, then learned MAC ownership.
Zebra re-enqueues existing nexthops, groups, bridge filters, remote MACs,
sync MACs and VTEPs. DF state resets on disconnect and remains closed until
Zebra programs a new result.

Full service SIDs use RFC 9252 L2 Service TLVs and RFC 8986 End.DT2U/DT2M.
The wire packet is IPv6 next-header 143 with raw Ethernet payload; an
ultimate-segment SRH is also accepted. VNI identifies the MAC-VRF and is
not transmitted. The core needs locator reachability and 40 bytes of extra
MTU. Receive and remote ports use split-horizon group 1, access ports group
0. Remote MAC ports never flood; only IMET ports replicate BUM.

The per-ES A-D zero DT2M SID uses PE-nexthop reachability for local bias
(RFC 9252 section 6.1.1). Per-EVI A-D and MAC routes track nonzero service
SIDs. Native FRR retains per-EVI A-D on a down ES by default.

Current scope is bridged services, full SIDs, default IPv6 FIB, native
all-active nexthop groups and DF/local-bias filtering. SID transposition,
IRB, ESI SID arguments and service carving remain outside this backend.
Linux control metadata uses one VLAN-aware bridge for access and trunk ports.
Each VNI has a VXLAN metadata interface whose PVID identifies its VLAN; service
registration carries that VXLAN ifindex. These metadata interfaces do not carry
VXLAN traffic. A trunk bond uses one ESI with per-VNI ES membership, DF state,
and split-horizon filtering. Local MAC events identify the parent bond and VNI;
synchronized MACs resolve to the VPP subinterface in that VNI's bridge domain.

## Validation

Run in disposable privileged containers with matching binaries:

```sh
python3 test/srv6_mh_vpp.py  # real Ethernet/SRv6 packets, NHGs, DF/filtering
python3 test/srv6_mh_frr.py  # real Zebra + bgpd, native local ownership/ZAPI
python3 test/srv6_sid_lifecycle.py  # real bgpd + Zebra + VPP, SID ownership/restart
```

On the lab Docker host:

```sh
python3 test/srv6_mh_packets.py  # count BUM copies and same-ES reflection
python3 test/srv6_mh_lab.py --failover  # native routes, pings, each attachment
```

`show errors` exposes non-DF and same-ES drop counters. Zebra's `show evpn es
detail`, `show evpn mac vni <vni>` and `show evpn next-hops` expose the control
state that VPP applies.

`show sr localsids` includes EVPN service receive traffic in every containing
LocalSID prefix in the same IPv6 table, even when a service /128 route bypasses
that prefix's behavior. Good/bad counters reflect service decapsulation
validation; byte counts include the outer IPv6 header. Later L2 forwarding or
split-horizon drops do not change that classification. Native
`clear sr localsid counters` resets these aggregates. For example,
`5f00:0:1:100:1::` contributes to `5f00:0:1::/48` and
`5f00:0:1:100::/64`, but not `5f00:0:1::/64`.

## IOS XR SRv6 EVPN interoperability

FRR accepts End.DT2U/End.DT2M and uDT2U/uDT2M (behavior codes 67/68).
For EVPN RT2 and per-EVI RT1, it reconstructs the service SID using the
high transposition-length bits of the raw 24-bit NLRI label. For RT3 it uses
the PMSI label instead. The IPv6 BGP next hop identifies the remote PE even
when XR advertises an IPv4 originating router address in its IMET NLRI.
Zebra sends the reconstructed destination to VPP; VPP needs no uSID shifting
when sending directly to a remote service endpoint.

FRR advertises a 16-bit Arg.FE2 reservation on its multicast SID and no
argument on its unicast SID. Unused address bits are not an argument.
The current VPP local endpoint supports local-bias split horizon; nonzero
remote ESI-filtering arguments and local uDT2U/uDT2M termination are outside
this implementation.

The Ethernet IPv6 next header defaults to RFC 8986 value 143. VPP also accepts
legacy XR value 65 on receive. For a peer that requires 65, select it for
outgoing traffic on the service:

```text
evpn srv6 next-header 65 evi 100
```

The setting applies to all remote destinations in that EVI, and can also be
provided as `next-header 65` when creating the service. `show evpn srv6`
displays the setting. Use 143 for mixed domains unless every peer accepts 65.
The setting is configuration and must be replayed when VPP restarts.

Checks: FRR's `test_evpn_srv6_sid` covers full SID, 16/24-bit and non-byte-aligned
transposition, and invalid structures. `test_attr_parse` covers XR behaviors
and L2 versus L3 transposition bounds. `test/srv6_mh_vpp.py` exercises actual
Ethernet decapsulation with next headers 143/65, rejects unsupported protocols,
and checks 65 on transmit along with MAC/NHG replacement and split horizon.

On the XRd 26.2.1 control-plane lab, the corrected BGP routes and reconstructed
multicast destination were verified. HA's encapsulated ARP requests arrive
on PE3's core interface, but PE3 does not emit them on HB's access interface;
end-to-end forwarding is not validated by those control-plane checks.


### Multihoming hash policy

Each SRv6 EVI defaults to `layer3+4`: remote Zebra nexthop-group member
selection includes inner IP addresses and transport ports (plus the IPv6 flow
label). UET, MRC, and Falcon UDP source-port entropy can therefore select
different remote PEs within one transport connection. Fragmented IPv4 packets
(MF or a nonzero offset) and IPv6 packets with a Fragment header exclude ports
and flow labels, including fragment zero. Their address/protocol hash is shared
by all fragments for both remote PE selection and outer ECMP. IPv6 Fragment
headers are detected after Hop-by-Hop, Routing, Destination Options, and AH
headers.

Configure a service at runtime with:

```text
evpn srv6 hash-policy layer3+4 evi 100
evpn srv6 hash-policy layer2+3 evi 100
evpn srv6 hash-policy layer2 evi 100
show evpn srv6
```

`layer2` uses inner MAC addresses and EtherType. `layer2+3` additionally uses
inner IPv4/IPv6 addresses, excluding ports and flow labels. These are field
selection policies with Linux bond naming, not Linux's exact hash algorithm.
The setting is per EVI and appears in `show evpn srv6`; re-created services
start with the default. Invalid policies and missing services are rejected.

Independently of remote PE selection, encapsulation derives the outer IPv6
flow label from the inner packet hash, exposing transport entropy to underlay
ECMP. Choosing an L2 member policy does not disable underlay path diversity.

In xForm, set `evpn.hash_policy: layer2+3` (or `layer2` / `layer3+4`) on the
node or topology. The default is `layer3+4`.
