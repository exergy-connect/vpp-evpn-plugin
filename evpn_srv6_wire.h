/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 * Direct bgpd/VPP SRv6 Ethernet control protocol, version 1.
 * Fixed-size frames; integers in network byte order, addresses as wire bytes.
 * Keep the copies in FRR and the VPP EVPN plugin identical.
 * FRR sends BEGIN, selected ROUTEs, END, then ROUTE/SYNC deltas.
 * VPP sends LOCAL MAC adds/deletes. Connection loss removes client-owned
 * local advertisements in FRR and remote forwarding entries in VPP.
 */
#ifndef EVPN_SRV6_WIRE_H
#define EVPN_SRV6_WIRE_H
#include <stdint.h>
#define EVPN_SRV6_SOCKET "frr-evpn-srv6"
#define EVPN_SRV6_MAGIC 0x45565036U
#define EVPN_SRV6_VERSION 1
#define EVPN_SRV6_QUEUE_LIMIT (1024 * 1024)
enum evpn_srv6_op {
  EVPN_SRV6_BEGIN = 1,
  EVPN_SRV6_END,
  EVPN_SRV6_ROUTE,
  EVPN_SRV6_LOCAL,
  EVPN_SRV6_SYNC,
};
struct evpn_srv6_msg {
  uint32_t magic;
  uint8_t version;
  uint8_t op;
  uint8_t type; /* EVPN route type: 2 = MAC, 3 = IMET */
  uint8_t add;
  uint32_t vni;
  uint8_t key[16]; /* MAC in first six bytes, or IPv6 / IPv4-mapped IMET IP */
  uint8_t sid[16];
  uint8_t reserved[4];
};
_Static_assert(sizeof(struct evpn_srv6_msg) == 48, "SRv6 control frame size");
#endif
