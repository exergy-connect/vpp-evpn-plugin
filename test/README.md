# Expected object wiring after smoke.cli on leaf1
#
# L2 path (same VLAN east-west):
#   host-access --BD10-- vxlan(vni=10010 → 10.0.0.2)
#   L2FIB: 00:00:00:00:00:22 → that vxlan (static)
#
# L3 path (symmetric IRB):
#   BVI10 (table 1) → FIB 172.16.20.0/24 via 169.254.x.y
#   neigh 169.254.x.y → remote rMAC on bvi{10001} (unnumbered to loop10001 in table 1)
#   L2FIB(bd=10001): rMAC → vxlan(vni=5042 → 10.0.0.2)
#   traceroute sources the unique tenant /32 on loop10001 (e.g. 10.255.0.1).
#   For peer source-validation, LCP that loopback into the Linux tenant VRF
#   and advertise its /32 as Type-5 (see README.md, Provisioning). Smoke
#   alone does not configure BGP export.
#
# Anycast (test/anycast.py):
#   Shared BVI MAC + VIP stay on the BVI; remote Type-2 for that MAC is ignored.
#   Extra static L2FIB → BVI MACs are inferred into the protected set.
