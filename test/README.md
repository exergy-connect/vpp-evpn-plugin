# Expected object wiring after smoke.cli on leaf1
#
# L2 path (same VLAN east-west):
#   host-access --BD10-- vxlan(vni=10010 → 10.0.0.2)
#   L2FIB: 00:00:00:00:00:22 → that vxlan (static)
#
# L3 path (symmetric IRB):
#   BVI10 (table 1) → FIB 172.16.20.0/24 via 169.254.x.y
#   neigh 169.254.x.y → remote rMAC on bvi{10001} (unnumbered to loop0)
#   L2FIB(bd=10001): rMAC → vxlan(vni=5042 → 10.0.0.2)
#   traceroute sources the loopback, not a 169.254 on the L3 BVI
