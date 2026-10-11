# Expected object wiring after smoke.cli on leaf1
#
# L2 path (same VLAN east-west):
#   host-access --BD10-- vxlan(vni=10010 → 10.0.0.2)
#   L2FIB: 00:00:00:00:00:22 → that vxlan (static)
#
# L3 path (symmetric IRB):
#   BVI10 (table 1) → FIB 172.16.20.0/24 via 169.254.x.y (default ipv4-nh-mode auto)
#   neigh 169.254.x.y → remote rMAC on bvi{10001} (unnumbered to loop10001 in table 1)
#   L2FIB(bd=10001): rMAC → vxlan(vni=5042 → 10.0.0.2)
#   traceroute sources the unique tenant /32 on loop10001 (e.g. 10.255.0.1).
#   For peer source-validation, LCP that loopback into the Linux tenant VRF
#   and advertise its /32 as Type-5 (see README.md, Provisioning). Smoke
#   alone does not configure BGP export.
#
# Anycast (test/anycast.py):
#   Shared BVI MAC + VIP(+IPv6) stay on the BVI; remote Type-2 for that MAC is ignored.
#   Extra static L2FIB → BVI MACs are inferred into the protected set.
#
# IPv6 (test/ipv6.py):
#   IPv6 Type-5 and ipv4-nh-mode ipv6 / auto-on-IPv6-only-BVI use fd00:a9fe:: NH.
#
# Native SRv6 bridged EVPN:
#   srv6_control.c — native FRR transport integration checks (see file header).
#   test/srv6_packets.py — endpoint packet checks against the running lab;
#     run on its privileged Docker host with PE/HA PIDs and host/core MACs.
#   See SRV6.md for provisioning, build, and current scope.

# Local SRv6 Ethernet Segment ownership:
#   srv6_mh_vpp.py — actual Ethernet learning and VPP socket messages, ES
#     down/up, reconnect ordering and bond removal in a disposable container.
#   srv6_mh_frr.py — compiled bgpd Type-1/2/4 origination, ESI/SRv6
#     attributes, stale deletes, ES-down and disconnect cleanup.
#   srv6_mh_lab.py --failover — received zero-SID A-D validity and live
#     attachment failover/pings; run on the lab Docker host.
