/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 * Zebra/VPP dataplane SRv6 Ethernet control protocol, version 5.
 * Fixed-size frames; integers in network byte order, addresses as wire bytes.
 * Keep the copies in FRR and the VPP EVPN plugin identical.
 * Zebra sends dataplane programming and SRv6 encapsulation metadata.
 * VPP registers services, then reports ES state and LOCAL MAC ownership.
 * Disconnect withdraws client-owned local state and clears VPP remote state.
 */
#ifndef EVPN_SRV6_WIRE_H
#define EVPN_SRV6_WIRE_H
#include <stdint.h>
#define EVPN_SRV6_SOCKET "zebra-evpn-srv6"
#define EVPN_SRV6_MAGIC 0x45565036U
#define EVPN_SRV6_VERSION 5
#define EVPN_SRV6_QUEUE_LIMIT (1024 * 1024)
enum evpn_srv6_op {
  EVPN_SRV6_BEGIN = 1,
  EVPN_SRV6_END,
  EVPN_SRV6_ROUTE,
  EVPN_SRV6_LOCAL,
  EVPN_SRV6_SYNC,
  EVPN_SRV6_DF = 7, /* reset peer set (flag 2), or commit DF (flag 1) */
  EVPN_SRV6_PEER, /* IPv6 originator in sid, scoped by Linux bridge-port ifindex */
  EVPN_SRV6_SERVICE = 9, /* Register VNI (Linux bridge index in sw_if_index) */
  EVPN_SRV6_SID, /* PE originator in key, service SID in sid, type 2/3 */
  EVPN_SRV6_NH, /* Zebra FDB NH id in sw_if_index, PE address in sid */
  EVPN_SRV6_NHG, /* reset=2, member=1 (vni=member id), commit=0 */
  EVPN_SRV6_LOCAL_SID = 13, /* Zebra-owned local DT2U/DT2M endpoint */
  EVPN_SRV6_ES = 6, /* VPP local ES/EVI association and operational state */
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
  uint32_t sw_if_index; /* Linux attachment ifindex, or Zebra FDB NH/NHG id */
  uint8_t esi[10];
  uint16_t df_pref;
  uint8_t flags;
  uint8_t reserved[3];
};
_Static_assert(sizeof(struct evpn_srv6_msg) == 64, "SRv6 control frame size");
#define EVPN_SRV6_ES_OPER_UP 1
#endif
