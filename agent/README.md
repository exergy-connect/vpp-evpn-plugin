# Native SRv6 bridged EVPN

FRR is the BGP speaker. The existing EVPN plugin provides the Ethernet
MAC-VRF dataplane; `frr_srv6.py` connects its local MAC events to FRR and
installs FRR's selected remote routes in VPP.

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

The remote SID is learned from EVPN, never configured in the lab. Type 2
carries a full End.DT2U SID; Type 3 carries an End.DT2M SID, using the L2
Service TLV in the BGP Prefix-SID attribute. VNI identifies the MAC-VRF;
it is not sent as a VXLAN identifier. IPv6 encapsulation uses Next Header
143 directly, with no SRH needed for a single segment. Decapsulation also
accepts an ultimate-segment SRH. The core needs routes to the locators and
an MTU sufficient for the original Ethernet frame plus 40 bytes of IPv6.

Agent configuration:

```json
{"asn": 65000, "services": [{"evi": 100, "vni": 10100}]}
```

Run the agent in the same network namespace as FRR:

```sh
ip netns exec dataplane python3 /usr/local/lib/evpn/frr_srv6.py \
  --config /etc/vpp/config/evpn-srv6.json
```

All steady-state updates are event driven:

- VPP's existing binary API emits local MAC add/delete events. On subscription,
  the plugin replays current learned MACs, including after an agent restart.
  FRR requests a fresh replay when local service configuration is reapplied.
- FRR pushes an ordered snapshot followed by selected Type 2/3 updates and
  withdrawals on the abstract Unix socket `@frr-evpn-srv6`. The socket is local
  to the network namespace; FRR accepts only root or its own UID using peer
  credentials. The normal FRR AppArmor network rule permits it.
- The adapter blocks on an event queue. It runs no periodic RIB queries.
  Disconnects flush remote forwarding entries; reconnects obtain a new
  snapshot. Exponential backoff applies only to failed transport connections.
- SID changes replace remote MAC ports. Flood destinations are reference-counted
  by their IMET routes, so one withdrawal cannot remove another route's SID.

`show evpn srv6` shows endpoint, remote-port, and packet counters.
`evpn srv6 flush evi 100` clears remote state while retaining local endpoints.
Remote MAC ports never participate in flooding. DT2U unknown destinations
and multicast frames are dropped; DT2M floods local attachment circuits.
Both endpoints prevent forwarding received core frames back into the core.

Current scope: full SIDs, one single-homed bridge service in the lab, default
IPv6 FIB, and one agent per bgpd. SID transposition, IRB, multihoming/ESI
filtering, ECMP, and host mobility into an existing static remote MAC entry
are not implemented. The L2/L3 service attributes currently share FRR's
service storage with a TLV-type discriminator; combined L2/L3 service TLVs on one route are outside
this implementation's scope.

Validation:

```sh
python3 test/test_frr_srv6.py
```

`test/srv6_packets.py` runs on the privileged Docker host against the deployed
lab. Supply the PE/HA container PIDs and the core/local/remote MAC addresses;
it tests known/unknown unicast, BUM, split horizon, SRH validation, IPv6 length
checks, and Ethernet-II validation without changing host addresses.

Validated in `srv6-evpn`: HA↔HB ping, including 1500-byte IP packets;
EVPN session withdrawal/recovery; adapter restart snapshots; advertised
unicast SID replacement; and local-service removal/reconfiguration with
MAC replay. Core capture shows IPv6 Next Header 143 and a 1514-byte Ethernet
payload for the full-size ping. An idle adapter trace recorded no CLI
executions. Focused checks passed: 23 FRR attribute-parser cases, six adapter
unit tests, three lab-template tests, and ten endpoint packet cases.
