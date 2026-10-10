/* Native SRv6 Ethernet MAC-VRF dataplane. No UDP or GRE encapsulation.
 * Single-homed ELAN: End.DT2U MAC lookup, End.DT2M ingress replication.
 * Remote SIDs are installed/withdrawn by the FRR adapter after EVPN selection.
 * Copyright (c) 2026. Licensed under the Apache License, Version 2.0.
 */
#include "evpn.h"
#include <vnet/dpo/dpo.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/l2/l2_output.h>

/* Keep native SRv6 state separate from the existing VXLAN object pools. */
typedef struct
{
  u32 evi, bd_index, fib_index;
  ip6_address_t source, unicast, multicast;
  u32 rx[2];
  u64 decap[2];
} evpn_srv6_service_t;
typedef struct
{
  u32 service, hw_if_index, sw_if_index, refs;
  u32 lookup_next, drop_next;
  ip6_address_t sid;
  u8 multicast, receive;
  u64 encap;
} evpn_srv6_port_t;
typedef struct
{
  u32 service, port;
  mac_address_t mac;
} evpn_srv6_mac_t;
static evpn_srv6_service_t *services;
static evpn_srv6_port_t *ports;
static evpn_srv6_mac_t *macs;
static dpo_type_t srv6_dpo;
static fib_source_t srv6_fib_source;
extern vnet_device_class_t evpn_srv6_device_class;

static u32
service_find (u32 evi)
{
  evpn_srv6_service_t *s;
  pool_foreach (s, services) if (s->evi == evi) return s - services;
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
      vnet_hw_interface_t *hi
          = vnet_get_sup_hw_interface (evpn_main.vnet_main, swi);
      evpn_srv6_port_t *p = pool_elt_at_index (ports, hi->dev_instance);
      next = p->drop_next;
      if (!p->receive)
        {
          evpn_srv6_service_t *s = pool_elt_at_index (services, p->service);
          u32 length = vlib_buffer_length_in_chain (vm, b);
          if (length <= 65535
              && b->current_data >= -(VLIB_BUFFER_PRE_DATA_SIZE - 40))
            {
              vlib_buffer_advance (b, -40);
              ip6_header_t *ip = vlib_buffer_get_current (b);
              clib_memset (ip, 0, sizeof (*ip));
              ip->ip_version_traffic_class_and_flow_label
                  = clib_host_to_net_u32 (6u << 28);
              ip->payload_length = clib_host_to_net_u16 (length);
              ip->protocol = 143; /* RFC 8986 Ethernet payload */
              ip->hop_limit = 64;
              ip->src_address = s->source;
              ip->dst_address = p->sid;
              vnet_buffer (b)->sw_if_index[VLIB_RX] = p->sw_if_index;
              vnet_buffer (b)->sw_if_index[VLIB_TX] = s->fib_index;
              b->flags &= ~(VNET_BUFFER_F_OFFLOAD
                            | VNET_BUFFER_F_L4_CHECKSUM_COMPUTED
                            | VNET_BUFFER_F_L4_CHECKSUM_CORRECT);
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
port_add (u32 service, const ip6_address_t *sid, u8 multicast, u8 receive,
          u32 *index)
{
  evpn_srv6_port_t *p;
  pool_get_zero (ports, p);
  u32 pi = p - ports;
  p->service = service;
  p->sid = *sid;
  p->multicast = multicast;
  p->receive = receive;
  u8 address[6] = { 2, 0, 0, 0, (pi >> 8) & 255, pi & 255 };
  vnet_eth_interface_registration_t r = {
    .dev_class_index = evpn_srv6_device_class.index,
    .dev_instance = pi,
    .address = address,
    .max_frame_size = 1600,
    .frame_overhead = 14,
  };
  p->hw_if_index = vnet_eth_register_interface (evpn_main.vnet_main, &r);
  p->sw_if_index = vnet_get_hw_interface (evpn_main.vnet_main, p->hw_if_index)
                       ->sw_if_index;
  vnet_hw_interface_t *hi
      = vnet_get_hw_interface (evpn_main.vnet_main, p->hw_if_index);
  u32 tx = hi->tx_node_index;
  p->lookup_next
      = vlib_node_add_named_next (evpn_main.vlib_main, tx, "ip6-lookup");
  p->drop_next
      = vlib_node_add_named_next (evpn_main.vlib_main, tx, "error-drop");
  vnet_hw_interface_set_flags (evpn_main.vnet_main, p->hw_if_index,
                               VNET_HW_INTERFACE_FLAG_LINK_UP);
  vnet_sw_interface_set_flags (evpn_main.vnet_main, p->sw_if_index,
                               VNET_SW_INTERFACE_FLAG_ADMIN_UP);
  evpn_srv6_service_t *s = pool_elt_at_index (services, service);
  int rv = set_int_l2_mode (evpn_main.vlib_main, evpn_main.vnet_main,
                            MODE_L2_BRIDGE, p->sw_if_index, s->bd_index,
                            L2_BD_PORT_TYPE_NORMAL, 1, ~0);
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
      vnet_get_sw_interface (evpn_main.vnet_main, p->sw_if_index)->flood_class
          = VNET_FLOOD_CLASS_NO_FLOOD;
    }
  *index = pi;
  return 0;
}
static void
port_del (u32 pi)
{
  evpn_srv6_port_t *p = pool_elt_at_index (ports, pi);
  set_int_l2_mode (evpn_main.vlib_main, evpn_main.vnet_main, MODE_L3,
                   p->sw_if_index, 0, L2_BD_PORT_TYPE_NORMAL, 0, ~0);
  vnet_delete_hw_interface (evpn_main.vnet_main, p->hw_if_index);
  pool_put (ports, p);
}
static u32
port_find (u32 si, const ip6_address_t *sid, u8 multicast)
{
  evpn_srv6_port_t *p;
  pool_foreach (p, ports) if (!p->receive && p->service == si
                              && p->multicast == multicast
                              && !memcmp (&p->sid, sid, 16)) return p
      - ports;
  return ~0;
}

VLIB_NODE_FN (evpn_srv6_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u32 dpo = vnet_buffer (b)->ip.adj_index[VLIB_TX], si = dpo >> 1,
          mode = dpo & 1, next = 1;
      if (!pool_is_free_index (services, si) && b->current_length >= 40)
        {
          evpn_srv6_service_t *s = pool_elt_at_index (services, si);
          ip6_header_t *ip = vlib_buffer_get_current (b);
          u32 offset = 40, proto = ip->protocol;
          if (proto == 43 && b->current_length >= 48)
            {
              u8 *srh = (u8 *)(ip + 1);
              u32 len = (srh[1] + 1) * 8;
              /* Routing type 4, ultimate segment only. No SID argument in this
               * v1. */
              if (srh[2] == 4 && srh[3] == 0
                  && len >= 8 + 16 * ((u32)srh[4] + 1)
                  && b->current_length >= 40 + len)
                {
                  proto = srh[0];
                  offset += len;
                }
            }
          if (proto == 143 && b->current_length >= offset + 14
              && ip->hop_limit > 0
              && (clib_net_to_host_u32 (
                      ip->ip_version_traffic_class_and_flow_label)
                  >> 28)
                     == 6
              && clib_net_to_host_u16 (ip->payload_length) + 40
                     == vlib_buffer_length_in_chain (vm, b))
            {
              ethernet_header_t *eth = (void *)((u8 *)ip + offset);
              if (clib_net_to_host_u16 (eth->type) >= 1536
                  && (mode || !(eth->dst_address[0] & 1)))
                {
                  vlib_buffer_advance (b, offset);
                  evpn_srv6_port_t *p = pool_elt_at_index (ports, s->rx[mode]);
                  vnet_buffer (b)->sw_if_index[VLIB_RX] = p->sw_if_index;
                  vnet_buffer (b)->sw_if_index[VLIB_TX] = ~0;
                  vnet_update_l2_len (b);
                  s->decap[mode]++;
                  next = 0;
                }
            }
        }
      vlib_set_next_frame_buffer (vm, node, next, from[i]);
    }
  return frame->n_vectors;
}
VLIB_REGISTER_NODE (evpn_srv6_input_node) = {
  .name = "evpn-srv6-input",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = 2,
  .next_nodes = { [0] = "l2-input", [1] = "error-drop" },
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
  return format (s, "EVPN End.DT2%s service-index %u", index & 1 ? "M" : "U",
                 index >> 1);
}
static const dpo_vft_t srv6_dpo_vft = { .dv_lock = srv6_dpo_lock,
                                        .dv_unlock = srv6_dpo_unlock,
                                        .dv_format = format_dpo };
static const char *const srv6_ip6_nodes[] = { "evpn-srv6-input", NULL };
static const char *const *const srv6_nodes[DPO_PROTO_NUM]
    = { [DPO_PROTO_IP6] = srv6_ip6_nodes };
static void
sid_route (evpn_srv6_service_t *s, u32 index, u8 mode, u8 add)
{
  fib_prefix_t prefix = { .fp_proto = FIB_PROTOCOL_IP6,
                          .fp_len = 128,
                          .fp_addr.ip6 = mode ? s->multicast : s->unicast };
  if (add)
    {
      dpo_id_t dpo = DPO_INVALID;
      dpo_set (&dpo, srv6_dpo, DPO_PROTO_IP6, (index << 1) | mode);
      fib_table_entry_special_dpo_add (s->fib_index, &prefix, srv6_fib_source,
                                       FIB_ENTRY_FLAG_EXCLUSIVE, &dpo);
      dpo_reset (&dpo);
    }
  else
    fib_table_entry_special_remove (s->fib_index, &prefix, srv6_fib_source);
}
int
evpn_srv6_service_add (u32 evi, u32 bd_id, ip6_address_t *source,
                       ip6_address_t *u, ip6_address_t *m)
{
  if (service_find (evi) != ~0)
    return VNET_API_ERROR_VALUE_EXIST;
  uword *bd = hash_get (bd_main.bd_index_by_bd_id, bd_id);
  if (!bd || !memcmp (u, m, 16) || ip6_address_is_zero (source)
      || ip6_address_is_zero (u) || ip6_address_is_zero (m)
      || ip6_address_is_multicast (source) || ip6_address_is_multicast (u)
      || ip6_address_is_multicast (m))
    return VNET_API_ERROR_INVALID_VALUE;
  evpn_srv6_service_t *existing;
  pool_foreach (
      existing,
      services) if (!memcmp (u, &existing->unicast, 16)
                    || !memcmp (u, &existing->multicast, 16)
                    || !memcmp (m, &existing->unicast, 16)
                    || !memcmp (m, &existing->multicast,
                                16)) return VNET_API_ERROR_VALUE_EXIST;
  evpn_srv6_service_t *s;
  pool_get_zero (services, s);
  u32 index = s - services;
  s->evi = evi;
  s->bd_index = bd[0];
  s->source = *source;
  s->unicast = *u;
  s->multicast = *m;
  s->fib_index = fib_table_find (FIB_PROTOCOL_IP6, 0);
  s->rx[0] = s->rx[1] = ~0;
  int rv = port_add (index, u, 0, 1, &s->rx[0]);
  if (!rv)
    rv = port_add (index, m, 1, 1, &s->rx[1]);
  if (rv)
    {
      if (s->rx[0] != ~0)
        port_del (s->rx[0]);
      pool_put (services, s);
      return rv;
    }
  sid_route (s, index, 0, 1);
  sid_route (s, index, 1, 1);
  return 0;
}
int
evpn_srv6_service_del (u32 evi)
{
  u32 si = service_find (evi);
  if (si == ~0)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  evpn_srv6_port_t *p;
  pool_foreach (
      p, ports) if (p->service == si
                    && !p->receive) return VNET_API_ERROR_INSTANCE_IN_USE;
  evpn_srv6_service_t *s = pool_elt_at_index (services, si);
  sid_route (s, si, 0, 0);
  sid_route (s, si, 1, 0);
  port_del (s->rx[0]);
  port_del (s->rx[1]);
  pool_put (services, s);
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
  u32 pi = port_find (si, sid, 1);
  if (add)
    {
      if (pi != ~0)
        return 0;
      return port_add (si, sid, 1, 0, &pi);
    }
  if (pi != ~0)
    port_del (pi);
  return 0;
}
int
evpn_srv6_mac (u32 evi, mac_address_t *mac, ip6_address_t *sid, u8 add)
{
  u32 si = service_find (evi);
  if (si == ~0)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  if ((mac->bytes[0] & 1)
      || (add && (ip6_address_is_zero (sid) || ip6_address_is_multicast (sid))))
    return VNET_API_ERROR_INVALID_VALUE;
  evpn_srv6_mac_t *entry = 0, *candidate;
  pool_foreach (candidate, macs) if (candidate->service == si
                                     && !memcmp (&candidate->mac, mac, 6))
  {
    entry = candidate;
    break;
  }
  u32 old = entry ? entry->port : ~0, pi = ~0;
  evpn_srv6_service_t *s = pool_elt_at_index (services, si);
  if (add)
    {
      pi = port_find (si, sid, 0);
      if (pi == ~0)
        {
          int rv = port_add (si, sid, 0, 0, &pi);
          if (rv)
            return rv;
        }
      if (old == pi)
        return 0;
      l2fib_add_entry (mac->bytes, s->bd_index,
                       pool_elt_at_index (ports, pi)->sw_if_index,
                       L2FIB_ENTRY_RESULT_FLAG_STATIC);
      pool_elt_at_index (ports, pi)->refs++;
      if (!entry)
        pool_get_zero (macs, entry);
      entry->service = si;
      entry->mac = *mac;
      entry->port = pi;
    }
  else if (entry)
    {
      l2fib_del_entry (mac->bytes, s->bd_index,
                       pool_elt_at_index (ports, old)->sw_if_index);
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
/* Reset remote state on agent startup/disconnect. Local endpoints remain. */
static int
srv6_flush (u32 evi)
{
  u32 si = service_find (evi), *indices = 0, pi;
  if (si == ~0)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  evpn_srv6_mac_t *entry;
  pool_foreach (entry, macs) if (entry->service == si)
      vec_add1 (indices, entry - macs);
  for (u32 i = 0; i < vec_len (indices); i++)
    {
      entry = pool_elt_at_index (macs, indices[i]);
      mac_address_t mac = entry->mac;
      ip6_address_t unused = {};
      evpn_srv6_mac (evi, &mac, &unused, 0);
    }
  vec_reset_length (indices);
  evpn_srv6_port_t *port;
  pool_foreach (port, ports) if (port->service == si && !port->receive)
      vec_add1 (indices, port - ports);
  vec_foreach_index (pi, indices) port_del (indices[pi]);
  vec_free (indices);
  return 0;
}
static clib_error_t *
srv6_command (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 evi = ~0, bd = ~0;
  u8 add = 1, kind = 0;
  ip6_address_t source = {}, u = {}, m = {}, sid = {};
  mac_address_t mac = {};
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "service"))
        kind = 1;
      else if (unformat (input, "imet"))
        kind = 2;
      else if (unformat (input, "mac"))
        kind = 3;
      else if (unformat (input, "flush"))
        kind = 4;
      else if (unformat (input, "add"))
        add = 1;
      else if (unformat (input, "del"))
        add = 0;
      else if (unformat (input, "evi %u", &evi))
        {
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
        return clib_error_return (0, "unknown input `%U'",
                                  format_unformat_error, input);
    }
  if (evi == ~0 || kind == 0)
    return clib_error_return (0, "service|imet|mac|flush and evi required");
  int rv = kind == 1   ? (add ? evpn_srv6_service_add (evi, bd, &source, &u, &m)
                              : evpn_srv6_service_del (evi))
           : kind == 2 ? evpn_srv6_imet (evi, &sid, add)
           : kind == 3 ? evpn_srv6_mac (evi, &mac, &sid, add)
                       : srv6_flush (evi);
  return rv ? clib_error_return (0, "evpn srv6 failed: %d", rv) : 0;
}
VLIB_CLI_COMMAND (evpn_srv6_command, static)
    = { .path = "evpn srv6",
        .function = srv6_command,
        .short_help
        = "evpn srv6 service add evi <id> bd <id> source <ip6> unicast <sid> "
          "multicast <sid> | service del evi <id> | imet add|del evi <id> sid "
          "<sid> | mac add|del evi <id> <mac> [sid <sid>] | flush evi <id>" };
static clib_error_t *
show_srv6 (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  evpn_srv6_service_t *s;
  evpn_srv6_port_t *p;
  pool_foreach (s, services)
  {
    vlib_cli_output (
        vm,
        "evi %u source %U End.DT2U %U packets %llu End.DT2M %U packets %llu",
        s->evi, format_ip6_address, &s->source, format_ip6_address, &s->unicast,
        s->decap[0], format_ip6_address, &s->multicast, s->decap[1]);
  }
  pool_foreach (p, ports) if (!p->receive) vlib_cli_output (
      vm, "  evi %u %s sid %U sw_if_index %u refs %u packets %llu",
      pool_elt_at_index (services, p->service)->evi,
      p->multicast ? "IMET" : "MAC", format_ip6_address, &p->sid,
      p->sw_if_index, p->refs, p->encap);
  return 0;
}
VLIB_CLI_COMMAND (show_evpn_srv6_command, static)
    = { .path = "show evpn srv6",
        .function = show_srv6,
        .short_help = "show evpn srv6" };
static clib_error_t *
srv6_init (vlib_main_t *vm)
{
  srv6_dpo = dpo_register_new_type (&srv6_dpo_vft, srv6_nodes);
  srv6_fib_source = fib_source_allocate ("evpn-srv6", FIB_SOURCE_PRIORITY_HI,
                                         FIB_SOURCE_BH_SIMPLE);
  return 0;
}
VLIB_INIT_FUNCTION (srv6_init);
