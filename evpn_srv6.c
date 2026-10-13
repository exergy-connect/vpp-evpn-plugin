/* Native SRv6 Ethernet MAC-VRF dataplane.
 * ELAN: End.DT2U MAC lookup, End.DT2M ingress replication.
 * Zebra programs MAC destinations and EVPN-MH nexthop groups.
 * Copyright (c) 2026. Licensed under the Apache License, Version 2.0.
 */
#include "evpn.h"
#include <vnet/dpo/dpo.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/l2/l2_output.h>
#include <vnet/srv6/sr.h>

/* EVPN route types and Zebra NHG update flags retain their wire values. */
enum
{
  EVPN_SRV6_ROUTE_MAC = 2,
  EVPN_SRV6_ROUTE_IMET = 3,
};
enum
{
  EVPN_SRV6_NHG_COMMIT = 0,
  EVPN_SRV6_NHG_MEMBER = 1,
  EVPN_SRV6_NHG_RESET = 2,
  EVPN_SRV6_NHG_MAX_MEMBERS = 64,
};
enum
{
  EVPN_SRV6_MODE_UNICAST,
  EVPN_SRV6_MODE_MULTICAST,
  EVPN_SRV6_MODE_COUNT,
  EVPN_SRV6_DPO_MODE_BITS = 1,
  EVPN_SRV6_DPO_MODE_MASK = (1 << EVPN_SRV6_DPO_MODE_BITS) - 1,
};
enum
{
  EVPN_SRV6_DELETE,
  EVPN_SRV6_ADD,
};
enum
{
  EVPN_SRV6_PORT_TRANSMIT,
  EVPN_SRV6_PORT_RECEIVE,
};
enum
{
  EVPN_SRV6_INPUT_NEXT_L2,
  EVPN_SRV6_INPUT_NEXT_DROP,
  EVPN_SRV6_INPUT_NEXT_COUNT,
};
typedef enum
{
  EVPN_SRV6_COMMAND_NONE,
  EVPN_SRV6_COMMAND_SERVICE,
  EVPN_SRV6_COMMAND_IMET,
  EVPN_SRV6_COMMAND_MAC,
  EVPN_SRV6_COMMAND_FLUSH,
  EVPN_SRV6_COMMAND_NEXT_HEADER,
} evpn_srv6_command_kind_t;
enum
{
  EVPN_SRV6_SHG_CORE = 1,
  EVPN_SRV6_SHG_NONE = 0,
  EVPN_SRV6_DEFAULT_MTU = 1600,
  EVPN_SRV6_DEFAULT_HOP_LIMIT = 64,
  EVPN_SRV6_IP_VERSION = 6,
  EVPN_SRV6_IP_VERSION_SHIFT = 28,
  EVPN_SRV6_SRH_ROUTING_TYPE = 4,
  EVPN_SRV6_SRH_UNIT_BYTES = 8,
  EVPN_SRV6_SRH_NEXT_HEADER = 0,
  EVPN_SRV6_SRH_LENGTH = 1,
  EVPN_SRV6_SRH_TYPE = 2,
  EVPN_SRV6_SRH_SEGMENTS_LEFT = 3,
  EVPN_SRV6_SRH_LAST_ENTRY = 4,
  EVPN_SRV6_MAC_GROUP_BIT = 0x01,
  EVPN_SRV6_MAC_LOCAL_BIT = 0x02,
  EVPN_SRV6_MIN_ETHERTYPE = 0x0600,
};
#define EVPN_SRV6_FNV1A_OFFSET_BASIS 2166136261u
#define EVPN_SRV6_FNV1A_PRIME        16777619u

/* Keep native SRv6 state separate from the existing VXLAN object pools. */
typedef struct
{
  u32 evi, bd_index, fib_index;
  ip6_address_t source, unicast, multicast;
  u32 rx[EVPN_SRV6_MODE_COUNT];
  u8 active[EVPN_SRV6_MODE_COUNT];
  u8 next_header; /* 143 (RFC 8986), or legacy XR Ethernet value 65. */
  u64 decap[EVPN_SRV6_MODE_COUNT];
} evpn_srv6_service_t;
typedef struct
{
  u32 service, hw_if_index, sw_if_index, refs;
  u32 lookup_next, drop_next, nhg_id;
  ip6_address_t sid;
  u8 multicast, receive;
  u64 encap;
} evpn_srv6_port_t;
typedef struct
{
  u32 service, port, sw_if_index;
  u8 owned;
  mac_address_t mac;
} evpn_srv6_mac_t;
static evpn_srv6_service_t *services;
static evpn_srv6_port_t *ports;
static evpn_srv6_mac_t *macs;
/* These are dataplane objects, keyed by Zebra's IDs. Zebra owns membership. */
typedef struct
{
  u32 id;
  ip6_address_t peer;
  u32 *members;
  u8 group, ready;
} srv6_nh_t;
typedef struct
{
  u32 evi;
  ip6_address_t peer, sid[EVPN_SRV6_MODE_COUNT];
  u8 imet;
} srv6_peer_t;
static srv6_nh_t *nexthops;
static srv6_peer_t *peer_sids;
static srv6_nh_t *
nh_find (u32 id)
{
  srv6_nh_t *n;
  vec_foreach (n, nexthops)
    if (n->id == id)
      return n;
  return 0;
}
static srv6_peer_t *
peer_find (u32 evi, const ip6_address_t *peer)
{
  srv6_peer_t *p;
  vec_foreach (p, peer_sids)
    if (p->evi == evi && !memcmp (&p->peer, peer, 16))
      return p;
  return 0;
}
int
evpn_srv6_nh_update (u32 id, ip6_address_t *peer, u8 group, u8 add, u8 flags, u32 member)
{
  if (!id || flags > EVPN_SRV6_NHG_RESET)
    return -1;
  srv6_nh_t *n = nh_find (id);
  if (!add)
    {
      if (n)
        {
          vec_free (n->members);
          vec_del1 (nexthops, n - nexthops);
        }
      return 0;
    }
  if (!n)
    {
      vec_add2 (nexthops, n, 1);
      clib_memset (n, 0, sizeof (*n));
      n->id = id;
    }
  n->group = group;
  if (!group)
    {
      n->peer = *peer;
      n->ready = !ip6_address_is_zero (peer);
    }
  else if (flags == EVPN_SRV6_NHG_RESET)
    {
      n->ready = 0;
      vec_reset_length (n->members);
    }
  else if (flags == EVPN_SRV6_NHG_MEMBER)
    {
      if (!member || vec_len (n->members) >= EVPN_SRV6_NHG_MAX_MEMBERS)
        return -1;
      vec_add1 (n->members, member);
    }
  else if (flags == EVPN_SRV6_NHG_COMMIT)
    n->ready = vec_len (n->members) != 0;
  return 0;
}
void
evpn_srv6_control_reset (void)
{
  srv6_nh_t *n;
  vec_foreach (n, nexthops)
    vec_free (n->members);
  vec_free (nexthops);
  vec_free (peer_sids);
}
int
evpn_srv6_peer_sid (u32 evi, ip6_address_t *peer, ip6_address_t *sid, u8 type)
{
  if ((type != EVPN_SRV6_ROUTE_MAC && type != EVPN_SRV6_ROUTE_IMET) || ip6_address_is_zero (peer) ||
      ip6_address_is_multicast (peer) || ip6_address_is_zero (sid) ||
      ip6_address_is_multicast (sid))
    return -1;
  srv6_peer_t *p = peer_find (evi, peer);
  if (!p)
    {
      vec_add2 (peer_sids, p, 1);
      clib_memset (p, 0, sizeof (*p));
      p->evi = evi;
      p->peer = *peer;
    }
  if (type == EVPN_SRV6_ROUTE_IMET && p->imet &&
      memcmp (&p->sid[EVPN_SRV6_MODE_MULTICAST], sid, 16))
    {
      evpn_srv6_imet (evi, &p->sid[EVPN_SRV6_MODE_MULTICAST], EVPN_SRV6_DELETE);
      if (evpn_srv6_imet (evi, sid, EVPN_SRV6_ADD))
        return -1;
    }
  p->sid[type == EVPN_SRV6_ROUTE_IMET ? EVPN_SRV6_MODE_MULTICAST : EVPN_SRV6_MODE_UNICAST] = *sid;
  return 0;
}
int
evpn_srv6_vtep (u32 evi, ip6_address_t *peer, ip6_address_t *sid, u8 add)
{
  srv6_peer_t *p = peer_find (evi, peer);
  if (add)
    {
      if (evpn_srv6_peer_sid (evi, peer, sid, EVPN_SRV6_ROUTE_IMET))
        return -1;
      p = peer_find (evi, peer);
      if (evpn_srv6_imet (evi, sid, EVPN_SRV6_ADD))
        return -1;
      p->imet = 1;
    }
  else if (p && p->imet)
    {
      evpn_srv6_imet (evi, &p->sid[EVPN_SRV6_MODE_MULTICAST], EVPN_SRV6_DELETE);
      p->imet = 0;
    }
  return 0;
}
/* Stable Ethernet hash selects among the group supplied by Zebra. */
static const ip6_address_t *
nhg_sid (u32 evi, u32 id, const ethernet_header_t *eth)
{
  srv6_nh_t *n = nh_find (id);
  if (!n || !n->ready)
    return 0;
  if (n->group)
    {
      u32 hash = EVPN_SRV6_FNV1A_OFFSET_BASIS;
      const u8 *bytes = (const u8 *) eth;
      for (u32 i = 0; i < sizeof (eth->dst_address) + sizeof (eth->src_address); i++)
        hash = (hash ^ bytes[i]) * EVPN_SRV6_FNV1A_PRIME;
      n = nh_find (n->members[hash % vec_len (n->members)]);
      if (!n || n->group || !n->ready)
        return 0;
    }
  srv6_peer_t *p = peer_find (evi, &n->peer);
  return p && !ip6_address_is_zero (&p->sid[EVPN_SRV6_MODE_UNICAST]) ?
           &p->sid[EVPN_SRV6_MODE_UNICAST] :
           0;
}
static dpo_type_t srv6_dpo;
static fib_source_t srv6_fib_source;
extern vnet_device_class_t evpn_srv6_device_class;

static u32
service_find (u32 evi)
{
  evpn_srv6_service_t *s;
  pool_foreach (s, services)
    if (s->evi == evi)
      return s - services;
  return ~0;
}
static u8 *
format_srv6_port (u8 *s, va_list *args)
{
  u32 index = va_arg (*args, u32);
  return format (s, "evpn-srv6%u", index);
}
static uword
srv6_tx (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u32 next, swi = vnet_buffer (b)->sw_if_index[VLIB_TX];
      vnet_hw_interface_t *hi = vnet_get_sup_hw_interface (evpn_main.vnet_main, swi);
      evpn_srv6_port_t *p = pool_elt_at_index (ports, hi->dev_instance);
      next = p->drop_next;
      if (!p->receive)
        {
          evpn_srv6_service_t *s = pool_elt_at_index (services, p->service);
          u32 length = vlib_buffer_length_in_chain (vm, b);
          const ip6_address_t *sid = &p->sid;
          if (p->nhg_id)
            sid = length >= sizeof (ethernet_header_t) ?
                    nhg_sid (s->evi, p->nhg_id, vlib_buffer_get_current (b)) :
                    0;
          if (sid && length <= UINT16_MAX &&
              b->current_data >= -(VLIB_BUFFER_PRE_DATA_SIZE - (int) sizeof (ip6_header_t)))
            {
              vlib_buffer_advance (b, -(int) sizeof (ip6_header_t));
              ip6_header_t *ip = vlib_buffer_get_current (b);
              clib_memset (ip, 0, sizeof (*ip));
              ip->ip_version_traffic_class_and_flow_label =
                clib_host_to_net_u32 ((u32) EVPN_SRV6_IP_VERSION << EVPN_SRV6_IP_VERSION_SHIFT);
              ip->payload_length = clib_host_to_net_u16 (length);
              ip->protocol = s->next_header ? s->next_header : IP_PROTOCOL_IP6_ETHERNET;
              ip->hop_limit = EVPN_SRV6_DEFAULT_HOP_LIMIT;
              ip->src_address = s->source;
              ip->dst_address = *sid;
              vnet_buffer (b)->sw_if_index[VLIB_RX] = p->sw_if_index;
              vnet_buffer (b)->sw_if_index[VLIB_TX] = s->fib_index;
              b->flags &= ~(VNET_BUFFER_F_OFFLOAD | VNET_BUFFER_F_L4_CHECKSUM_COMPUTED |
                            VNET_BUFFER_F_L4_CHECKSUM_CORRECT);
              p->encap++;
              next = p->lookup_next;
            }
        }
      vlib_set_next_frame_buffer (vm, node, next, from[i]);
    }
  return frame->n_vectors;
}
VNET_DEVICE_CLASS (evpn_srv6_device_class) = {
  .name = "EVPN SRv6 Ethernet",
  .format_device_name = format_srv6_port,
  .tx_function = srv6_tx,
};

static int
port_add (u32 service, const ip6_address_t *sid, u8 multicast, u8 receive, u32 *index)
{
  evpn_srv6_port_t *p;
  pool_get_zero (ports, p);
  u32 pi = p - ports;
  p->service = service;
  p->sid = *sid;
  p->multicast = multicast;
  p->receive = receive;
  u8 address[sizeof (mac_address_t)] = {
    EVPN_SRV6_MAC_LOCAL_BIT, 0, 0, 0, (pi >> 8) & 255, pi & 255
  };
  vnet_eth_interface_registration_t r = {
    .dev_class_index = evpn_srv6_device_class.index,
    .dev_instance = pi,
    .address = address,
    .max_frame_size = EVPN_SRV6_DEFAULT_MTU,
    .frame_overhead = sizeof (ethernet_header_t),
  };
  p->hw_if_index = vnet_eth_register_interface (evpn_main.vnet_main, &r);
  p->sw_if_index = vnet_get_hw_interface (evpn_main.vnet_main, p->hw_if_index)->sw_if_index;
  vnet_hw_interface_t *hi = vnet_get_hw_interface (evpn_main.vnet_main, p->hw_if_index);
  u32 tx = hi->tx_node_index;
  p->lookup_next = vlib_node_add_named_next (evpn_main.vlib_main, tx, "ip6-lookup");
  p->drop_next = vlib_node_add_named_next (evpn_main.vlib_main, tx, "error-drop");
  vnet_hw_interface_set_flags (evpn_main.vnet_main, p->hw_if_index, VNET_HW_INTERFACE_FLAG_LINK_UP);
  vnet_sw_interface_set_flags (evpn_main.vnet_main, p->sw_if_index,
                               VNET_SW_INTERFACE_FLAG_ADMIN_UP);
  evpn_srv6_service_t *s = pool_elt_at_index (services, service);
  int rv =
    set_int_l2_mode (evpn_main.vlib_main, evpn_main.vnet_main, MODE_L2_BRIDGE, p->sw_if_index,
                     s->bd_index, L2_BD_PORT_TYPE_NORMAL, EVPN_SRV6_SHG_CORE, ~0);
  if (rv)
    {
      vnet_delete_hw_interface (evpn_main.vnet_main, p->hw_if_index);
      pool_put (ports, p);
      return rv;
    }
  l2_input_config_t *c = l2input_intf_config (p->sw_if_index);
  c->feature_bitmap &= ~L2INPUT_FEAT_LEARN;
  if (receive && multicast)
    {
      c->feature_bitmap &= ~L2INPUT_FEAT_FWD;
      c->feature_bitmap |= L2INPUT_FEAT_UU_FLOOD | L2INPUT_FEAT_FLOOD;
    }
  else if (receive)
    c->feature_bitmap &= ~(L2INPUT_FEAT_UU_FLOOD | L2INPUT_FEAT_FLOOD);
  /* Only IMET ports participate in ingress replication. Known-unicast and
   * receive ports still have L2 output config, but never receive flood copies.
   */
  if (receive || !multicast)
    {
      bd_remove_member (bd_get (s->bd_index), p->sw_if_index);
      vnet_get_sw_interface (evpn_main.vnet_main, p->sw_if_index)->flood_class =
        VNET_FLOOD_CLASS_NO_FLOOD;
    }
  *index = pi;
  return 0;
}
static void
port_del (u32 pi)
{
  evpn_srv6_port_t *p = pool_elt_at_index (ports, pi);
  set_int_l2_mode (evpn_main.vlib_main, evpn_main.vnet_main, MODE_L3, p->sw_if_index, 0,
                   L2_BD_PORT_TYPE_NORMAL, EVPN_SRV6_SHG_NONE, ~0);
  vnet_delete_hw_interface (evpn_main.vnet_main, p->hw_if_index);
  pool_put (ports, p);
}
static u32
port_find (u32 si, const ip6_address_t *sid, u8 multicast)
{
  evpn_srv6_port_t *p;
  pool_foreach (p, ports)
    if (!p->receive && p->service == si && !p->nhg_id && p->multicast == multicast &&
        !memcmp (&p->sid, sid, 16))
      return p - ports;
  return ~0;
}

/* Service /128 DPOs bypass the covering native LocalSID behaviors. Account
 * their input against every containing LocalSID prefix in the same table.
 * Use native counters so clear sr localsid counters also clears aggregates.
 * Resolve live objects rather than retaining indices across SID deletion. */
static void
srv6_count_locators (vlib_main_t *vm, u32 fib_index, const ip6_address_t *dst,
                     u32 bytes, u8 good)
{
  ip6_sr_localsid_t *ls;
  pool_foreach (ls, sr_main.localsids)
    {
      ip6_address_t mask;
      if (ls->fib_table != fib_table_get_table_id (fib_index, FIB_PROTOCOL_IP6))
        continue;
      ip6_address_mask_from_width (&mask, ls->localsid_prefix_len);
      if (ip6_address_is_equal_masked (dst, &ls->localsid, &mask))
        vlib_increment_combined_counter (
          good ? &sr_main.sr_ls_valid_counters : &sr_main.sr_ls_invalid_counters,
          vm->thread_index, ls - sr_main.localsids, 1, bytes);
    }
}

VLIB_NODE_FN (evpn_srv6_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u32 dpo = vnet_buffer (b)->ip.adj_index[VLIB_TX], si = dpo >> EVPN_SRV6_DPO_MODE_BITS,
          mode = dpo & EVPN_SRV6_DPO_MODE_MASK, next = EVPN_SRV6_INPUT_NEXT_DROP;
      if (!pool_is_free_index (services, si) && b->current_length >= sizeof (ip6_header_t))
        {
          evpn_srv6_service_t *s = pool_elt_at_index (services, si);
          ip6_header_t *ip = vlib_buffer_get_current (b);
          ip6_address_t destination = ip->dst_address;
          u32 packet_bytes = vlib_buffer_length_in_chain (vm, b);
          u32 offset = sizeof (ip6_header_t), proto = ip->protocol;
          if (proto == IP_PROTOCOL_IPV6_ROUTE &&
              b->current_length >= sizeof (ip6_header_t) + EVPN_SRV6_SRH_UNIT_BYTES)
            {
              u8 *srh = (u8 *) (ip + 1);
              u32 len = (srh[EVPN_SRV6_SRH_LENGTH] + 1) * EVPN_SRV6_SRH_UNIT_BYTES;
              /* Routing type 4, ultimate segment only. No SID argument in this
               * v1. */
              if (srh[EVPN_SRV6_SRH_TYPE] == EVPN_SRV6_SRH_ROUTING_TYPE &&
                  srh[EVPN_SRV6_SRH_SEGMENTS_LEFT] == 0 &&
                  len >= EVPN_SRV6_SRH_UNIT_BYTES +
                           sizeof (ip6_address_t) * ((u32) srh[EVPN_SRV6_SRH_LAST_ENTRY] + 1) &&
                  b->current_length >= sizeof (ip6_header_t) + len)
                {
                  proto = srh[EVPN_SRV6_SRH_NEXT_HEADER];
                  offset += len;
                }
            }
          if ((proto == IP_PROTOCOL_IP6_ETHERNET || proto == 65) &&
              b->current_length >= offset + sizeof (ethernet_header_t) && ip->hop_limit > 0 &&
              (clib_net_to_host_u32 (ip->ip_version_traffic_class_and_flow_label) >>
               EVPN_SRV6_IP_VERSION_SHIFT) == EVPN_SRV6_IP_VERSION &&
              clib_net_to_host_u16 (ip->payload_length) + sizeof (ip6_header_t) ==
                vlib_buffer_length_in_chain (vm, b))
            {
              ethernet_header_t *eth = (void *) ((u8 *) ip + offset);
              if (clib_net_to_host_u16 (eth->type) >= EVPN_SRV6_MIN_ETHERTYPE &&
                  (mode || !(eth->dst_address[0] & EVPN_SRV6_MAC_GROUP_BIT)))
                {
                  /* Reserved plugin metadata survives L2 flood clones. Only
                   * native receive interfaces may consume this originator. */
                  clib_memcpy (vnet_buffer2 (b)->unused, &ip->src_address, 16);
                  vlib_buffer_advance (b, offset);
                  evpn_srv6_port_t *p = pool_elt_at_index (ports, s->rx[mode]);
                  vnet_buffer (b)->sw_if_index[VLIB_RX] = p->sw_if_index;
                  vnet_buffer (b)->sw_if_index[VLIB_TX] = ~0;
                  vnet_update_l2_len (b);
                  s->decap[mode]++;
                  next = EVPN_SRV6_INPUT_NEXT_L2;
                }
            }
          srv6_count_locators (vm, s->fib_index, &destination, packet_bytes,
                               next == EVPN_SRV6_INPUT_NEXT_L2);
        }
      vlib_set_next_frame_buffer (vm, node, next, from[i]);
    }
  return frame->n_vectors;
}
VLIB_REGISTER_NODE (evpn_srv6_input_node) = {
  .name = "evpn-srv6-input",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = EVPN_SRV6_INPUT_NEXT_COUNT,
  .next_nodes = { [EVPN_SRV6_INPUT_NEXT_L2] = "l2-input",
                  [EVPN_SRV6_INPUT_NEXT_DROP] = "error-drop" },
};
static void
srv6_dpo_lock (dpo_id_t *dpo)
{
}
static void
srv6_dpo_unlock (dpo_id_t *dpo)
{
}
static u8 *
format_dpo (u8 *s, va_list *args)
{
  u32 index = va_arg (*args, u32);
  va_arg (*args, u32);
  return format (s, "EVPN End.DT2%s service-index %u", index & EVPN_SRV6_DPO_MODE_MASK ? "M" : "U",
                 index >> EVPN_SRV6_DPO_MODE_BITS);
}
static const dpo_vft_t srv6_dpo_vft = { .dv_lock = srv6_dpo_lock,
                                        .dv_unlock = srv6_dpo_unlock,
                                        .dv_format = format_dpo };
static const char *const srv6_ip6_nodes[] = { "evpn-srv6-input", NULL };
static const char *const *const srv6_nodes[DPO_PROTO_NUM] = { [DPO_PROTO_IP6] = srv6_ip6_nodes };
static void
sid_route (evpn_srv6_service_t *s, u32 index, u8 mode, u8 add)
{
  fib_prefix_t prefix = { .fp_proto = FIB_PROTOCOL_IP6,
                          .fp_len = 128,
                          .fp_addr.ip6 = mode ? s->multicast : s->unicast };
  if (add)
    {
      dpo_id_t dpo = DPO_INVALID;
      dpo_set (&dpo, srv6_dpo, DPO_PROTO_IP6, (index << EVPN_SRV6_DPO_MODE_BITS) | mode);
      fib_table_entry_special_dpo_add (s->fib_index, &prefix, srv6_fib_source,
                                       FIB_ENTRY_FLAG_EXCLUSIVE, &dpo);
      dpo_reset (&dpo);
    }
  else
    fib_table_entry_special_remove (s->fib_index, &prefix, srv6_fib_source);
}
int
evpn_srv6_service_add (u32 evi, u32 bd_id, ip6_address_t *source, ip6_address_t *u,
                       ip6_address_t *m)
{
  if (service_find (evi) != ~0)
    return VNET_API_ERROR_VALUE_EXIST;
  uword *bd = hash_get (bd_main.bd_index_by_bd_id, bd_id);
  uword *ei = hash_get (evpn_main.evi_by_id, evi);
  if (!ei || !bd || pool_elt_at_index (evpn_main.evis, ei[0])->bd_index != bd[0] ||
      pool_elt_at_index (evpn_main.evis, ei[0])->irb || !memcmp (u, m, 16) ||
      ip6_address_is_zero (source) || ip6_address_is_zero (u) || ip6_address_is_zero (m) ||
      ip6_address_is_multicast (source) || ip6_address_is_multicast (u) ||
      ip6_address_is_multicast (m))
    return VNET_API_ERROR_INVALID_VALUE;
  evpn_srv6_service_t *existing;
  pool_foreach (existing, services)
    if (!memcmp (u, &existing->unicast, 16) || !memcmp (u, &existing->multicast, 16) ||
        !memcmp (m, &existing->unicast, 16) || !memcmp (m, &existing->multicast, 16))
      return VNET_API_ERROR_VALUE_EXIST;
  evpn_srv6_service_t *s;
  pool_get_zero (services, s);
  u32 index = s - services;
  s->evi = evi;
  s->bd_index = bd[0];
  s->source = *source;
  s->unicast = *u;
  s->multicast = *m;
  s->fib_index = fib_table_find (FIB_PROTOCOL_IP6, 0);
  s->rx[EVPN_SRV6_MODE_UNICAST] = s->rx[EVPN_SRV6_MODE_MULTICAST] = ~0;
  int rv = port_add (index, u, EVPN_SRV6_MODE_UNICAST, EVPN_SRV6_PORT_RECEIVE,
                     &s->rx[EVPN_SRV6_MODE_UNICAST]);
  if (!rv)
    rv = port_add (index, m, EVPN_SRV6_MODE_MULTICAST, EVPN_SRV6_PORT_RECEIVE,
                   &s->rx[EVPN_SRV6_MODE_MULTICAST]);
  if (rv)
    {
      if (s->rx[EVPN_SRV6_MODE_UNICAST] != ~0)
        port_del (s->rx[EVPN_SRV6_MODE_UNICAST]);
      pool_put (services, s);
      return rv;
    }
  /* Local /128 routes are activated only by Zebra SID-manager programming. */
  evpn_zebra_resync ();
  return 0;
}
int
evpn_srv6_local_sid (u32 evi, const ip6_address_t *source, const ip6_address_t *sid, u8 type,
                     u8 add)
{
  u32 si = service_find (evi);
  if (si == ~0 || (type != EVPN_SRV6_ROUTE_MAC && type != EVPN_SRV6_ROUTE_IMET))
    return -1;
  evpn_srv6_service_t *s = pool_elt_at_index (services, si);
  u8 mode = type == EVPN_SRV6_ROUTE_IMET ? EVPN_SRV6_MODE_MULTICAST : EVPN_SRV6_MODE_UNICAST;
  if (memcmp (source, &s->source, 16) || memcmp (sid, mode ? &s->multicast : &s->unicast, 16))
    return -1;
  if (s->active[mode] != add)
    {
      sid_route (s, si, mode, add);
      s->active[mode] = add;
    }
  return 0;
}
void
evpn_srv6_local_sid_reset (void)
{
  evpn_srv6_service_t *s;
  pool_foreach (s, services)
    for (u8 mode = 0; mode < EVPN_SRV6_MODE_COUNT; mode++)
      if (s->active[mode])
        {
          sid_route (s, s - services, mode, EVPN_SRV6_DELETE);
          s->active[mode] = 0;
        }
}
int
evpn_srv6_service_del (u32 evi)
{
  u32 si = service_find (evi);
  if (si == ~0)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  evpn_srv6_port_t *p;
  pool_foreach (p, ports)
    if (p->service == si && !p->receive)
      return VNET_API_ERROR_INSTANCE_IN_USE;
  evpn_srv6_service_t *s = pool_elt_at_index (services, si);
  sid_route (s, si, EVPN_SRV6_MODE_UNICAST, EVPN_SRV6_DELETE);
  sid_route (s, si, EVPN_SRV6_MODE_MULTICAST, EVPN_SRV6_DELETE);
  port_del (s->rx[EVPN_SRV6_MODE_UNICAST]);
  port_del (s->rx[EVPN_SRV6_MODE_MULTICAST]);
  pool_put (services, s);
  evpn_zebra_resync ();
  return 0;
}
int
evpn_srv6_imet (u32 evi, ip6_address_t *sid, u8 add)
{
  u32 si = service_find (evi);
  if (si == ~0)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  if (ip6_address_is_zero (sid) || ip6_address_is_multicast (sid))
    return VNET_API_ERROR_INVALID_VALUE;
  u32 pi = port_find (si, sid, EVPN_SRV6_MODE_MULTICAST);
  if (add)
    {
      if (pi != ~0)
        return 0;
      return port_add (si, sid, EVPN_SRV6_MODE_MULTICAST, EVPN_SRV6_PORT_TRANSMIT, &pi);
    }
  if (pi != ~0)
    port_del (pi);
  return 0;
}
static int
mac_update (u32 evi, mac_address_t *mac, ip6_address_t *sid, u32 local, u32 nhg, u8 add)
{
  u32 si = service_find (evi);
  if (si == ~0)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  if ((mac->bytes[0] & EVPN_SRV6_MAC_GROUP_BIT) ||
      (add && local == ~0 && !nhg && (ip6_address_is_zero (sid) || ip6_address_is_multicast (sid))))
    return VNET_API_ERROR_INVALID_VALUE;
  evpn_srv6_mac_t *entry = 0, *candidate;
  pool_foreach (candidate, macs)
    if (candidate->service == si && !memcmp (&candidate->mac, mac, 6))
      {
        entry = candidate;
        break;
      }
  u32 old = entry ? entry->port : ~0, pi = ~0;
  evpn_srv6_service_t *s = pool_elt_at_index (services, si);
  if (add)
    {
      pi = ~0;
      if (local == ~0 && nhg)
        {
          evpn_srv6_port_t *p;
          pool_foreach (p, ports)
            if (!p->receive && p->service == si && p->nhg_id == nhg)
              {
                pi = p - ports;
                break;
              }
        }
      else if (local == ~0)
        pi = port_find (si, sid, EVPN_SRV6_MODE_UNICAST);
      if (local == ~0 && pi == ~0)
        {
          int rv = port_add (si, sid, EVPN_SRV6_MODE_UNICAST, EVPN_SRV6_PORT_TRANSMIT, &pi);
          if (rv)
            return rv;
          pool_elt_at_index (ports, pi)->nhg_id = nhg;
        }
      u32 target = local == ~0 ? pool_elt_at_index (ports, pi)->sw_if_index : local;
      if (entry && old == pi && entry->sw_if_index == target)
        return 0;
      /* Preserve an existing locally learned entry and its ownership events. */
      BVT (clib_bihash_kv) kv = { .key = l2fib_make_key (mac->bytes, s->bd_index), .value = ~0ULL };
      /* Use the library hash variant, matching the running VPP build. */
      BV (clib_bihash_search) (&l2fib_main.mac_table, &kv, &kv);
      l2fib_entry_result_t current = { .raw = kv.value };
      u8 owned = !(local != ~0 && current.raw != ~0ULL && current.fields.sw_if_index == target &&
                   !l2fib_entry_result_is_set_STATIC (&current));
      if (owned)
        l2fib_add_entry (mac->bytes, s->bd_index, target, L2FIB_ENTRY_RESULT_FLAG_STATIC);
      if (pi != ~0)
        pool_elt_at_index (ports, pi)->refs++;
      if (!entry)
        pool_get_zero (macs, entry);
      entry->service = si;
      entry->mac = *mac;
      entry->port = pi;
      entry->sw_if_index = target;
      entry->owned = owned;
    }
  else if (entry)
    {
      if (entry->owned)
        l2fib_del_entry (mac->bytes, s->bd_index, entry->sw_if_index);
      pool_put (macs, entry);
    }
  if (old != ~0)
    {
      evpn_srv6_port_t *p = pool_elt_at_index (ports, old);
      if (--p->refs == 0)
        port_del (old);
    }
  return 0;
}
int
evpn_srv6_mac (u32 evi, mac_address_t *mac, ip6_address_t *sid, u8 add)
{
  return mac_update (evi, mac, sid, ~0, 0, add);
}
int
evpn_srv6_mac_local (u32 evi, mac_address_t *mac, ip6_address_t *sid, u32 sw_if_index)
{
  return mac_update (evi, mac, sid, sw_if_index, 0, EVPN_SRV6_ADD);
}
int
evpn_srv6_mac_nhg (u32 evi, mac_address_t *mac, u32 id)
{
  ip6_address_t unused = {};
  return id ? mac_update (evi, mac, &unused, ~0, id, EVPN_SRV6_ADD) : -1;
}
int
evpn_srv6_service_exists (u32 evi)
{
  return service_find (evi) != ~0;
}

/* Reset remote state on control disconnect. Local endpoints remain. */
int
evpn_srv6_flush (u32 evi)
{
  u32 si = service_find (evi), *indices = 0, pi;
  if (si == ~0)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  evpn_srv6_mac_t *entry;
  pool_foreach (entry, macs)
    if (entry->service == si)
      vec_add1 (indices, entry - macs);
  for (u32 i = 0; i < vec_len (indices); i++)
    {
      entry = pool_elt_at_index (macs, indices[i]);
      mac_address_t mac = entry->mac;
      ip6_address_t unused = {};
      evpn_srv6_mac (evi, &mac, &unused, EVPN_SRV6_DELETE);
    }
  vec_reset_length (indices);
  evpn_srv6_port_t *port;
  pool_foreach (port, ports)
    if (port->service == si && !port->receive)
      vec_add1 (indices, port - ports);
  vec_foreach_index (pi, indices)
    port_del (indices[pi]);
  vec_free (indices);
  return 0;
}
static clib_error_t *
srv6_command (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 evi = ~0, bd = ~0, next_header = IP_PROTOCOL_IP6_ETHERNET;
  u8 add = EVPN_SRV6_ADD;
  evpn_srv6_command_kind_t kind = EVPN_SRV6_COMMAND_NONE;
  ip6_address_t source = {}, u = {}, m = {}, sid = {};
  mac_address_t mac = {};
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "service"))
        kind = EVPN_SRV6_COMMAND_SERVICE;
      else if (unformat (input, "imet"))
        kind = EVPN_SRV6_COMMAND_IMET;
      else if (unformat (input, "mac"))
        kind = EVPN_SRV6_COMMAND_MAC;
      else if (unformat (input, "flush"))
        kind = EVPN_SRV6_COMMAND_FLUSH;
      else if (unformat (input, "add"))
        add = EVPN_SRV6_ADD;
      else if (unformat (input, "del"))
        add = EVPN_SRV6_DELETE;
      else if (unformat (input, "evi %u", &evi))
        {
        }
      else if (unformat (input, "next-header %u", &next_header))
        {
          if (kind == EVPN_SRV6_COMMAND_NONE)
            kind = EVPN_SRV6_COMMAND_NEXT_HEADER;
        }
      else if (unformat (input, "bd %u", &bd))
        {
        }
      else if (unformat (input, "source %U", unformat_ip6_address, &source))
        {
        }
      else if (unformat (input, "unicast %U", unformat_ip6_address, &u))
        {
        }
      else if (unformat (input, "multicast %U", unformat_ip6_address, &m))
        {
        }
      else if (unformat (input, "sid %U", unformat_ip6_address, &sid))
        {
        }
      else if (unformat (input, "%U", unformat_mac_address_t, &mac))
        {
        }
      else
        return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }
  if (evi == ~0 || kind == EVPN_SRV6_COMMAND_NONE)
    return clib_error_return (0, "service|imet|mac|flush and evi required");
  if (next_header != IP_PROTOCOL_IP6_ETHERNET && next_header != 65)
    return clib_error_return (0, "Ethernet next-header must be 143 or 65");
  if (kind == EVPN_SRV6_COMMAND_NEXT_HEADER)
    {
      u32 si = service_find (evi);
      if (si == ~0)
        return clib_error_return (0, "SRv6 service does not exist");
      pool_elt_at_index (services, si)->next_header = next_header;
      return 0;
    }
  int rv =
    kind == EVPN_SRV6_COMMAND_SERVICE ?
      (add ? evpn_srv6_service_add (evi, bd, &source, &u, &m) : evpn_srv6_service_del (evi)) :
    kind == EVPN_SRV6_COMMAND_IMET ? evpn_srv6_imet (evi, &sid, add) :
    kind == EVPN_SRV6_COMMAND_MAC  ? evpn_srv6_mac (evi, &mac, &sid, add) :
                                     evpn_srv6_flush (evi);
  if (!rv && add && kind == EVPN_SRV6_COMMAND_SERVICE)
    pool_elt_at_index (services, service_find (evi))->next_header = next_header;
  return rv ? clib_error_return (0, "evpn srv6 failed: %d", rv) : 0;
}
VLIB_CLI_COMMAND (evpn_srv6_command, static) = {
  .path = "evpn srv6",
  .function = srv6_command,
  .short_help = "evpn srv6 service add evi <id> bd <id> source <ip6> unicast <sid> "
                "multicast <sid> [next-header 143|65] | service del evi <id> | imet add|del evi <id> sid "
                "<sid> | mac add|del evi <id> <mac> [sid <sid>] | flush evi <id> | next-header 143|65 evi <id>"
};
static clib_error_t *
show_srv6 (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  evpn_srv6_service_t *s;
  evpn_srv6_port_t *p;
  pool_foreach (s, services)
    {
      vlib_cli_output (
        vm, "evi %u source %U End.DT2U %U packets %llu End.DT2M %U packets %llu Zebra %s/%s next-header %u",
        s->evi, format_ip6_address, &s->source, format_ip6_address, &s->unicast,
        s->decap[EVPN_SRV6_MODE_UNICAST], format_ip6_address, &s->multicast,
        s->decap[EVPN_SRV6_MODE_MULTICAST],
        s->active[EVPN_SRV6_MODE_UNICAST] ? "active" : "pending",
        s->active[EVPN_SRV6_MODE_MULTICAST] ? "active" : "pending",
        s->next_header ? s->next_header : IP_PROTOCOL_IP6_ETHERNET);
    }
  pool_foreach (p, ports)
    if (!p->receive)
      vlib_cli_output (vm, "  evi %u %s sid %U sw_if_index %u refs %u packets %llu nhg %u",
                       pool_elt_at_index (services, p->service)->evi, p->multicast ? "IMET" : "MAC",
                       format_ip6_address, &p->sid, p->sw_if_index, p->refs, p->encap, p->nhg_id);
  return 0;
}
VLIB_CLI_COMMAND (show_evpn_srv6_command, static) = { .path = "show evpn srv6",
                                                      .function = show_srv6,
                                                      .short_help = "show evpn srv6" };
static clib_error_t *
srv6_init (vlib_main_t *vm)
{
  srv6_dpo = dpo_register_new_type (&srv6_dpo_vft, srv6_nodes);
  srv6_fib_source = fib_source_allocate ("evpn-srv6", FIB_SOURCE_PRIORITY_HI, FIB_SOURCE_BH_SIMPLE);
  return 0;
}
VLIB_INIT_FUNCTION (srv6_init);

/* Identify core BUM without trusting metadata on ordinary ingress ports. */
u8
evpn_srv6_bum_origin (vlib_buffer_t *b, ip6_address_t *origin)
{
  u32 swi = vnet_buffer (b)->sw_if_index[VLIB_RX];
  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (evpn_main.vnet_main, swi);
  if (hw->dev_class_index != evpn_srv6_device_class.index)
    return 0;
  evpn_srv6_port_t *p = pool_elt_at_index (ports, hw->dev_instance);
  if (!p->receive || !p->multicast)
    return 0;
  clib_memcpy (origin, vnet_buffer2 (b)->unused, 16);
  return 1;
}
