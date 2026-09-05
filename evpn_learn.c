/*
 * Copyright (c) 2026
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * Local MAC / prefix origination for a control-plane agent.
 *
 * Scans L2FIB on EVI bridge-domains for dynamically learned MACs (skip
 * static / VXLAN / BVI) and watches IRB interface addresses for Type-5
 * candidates. Events go out via binary-API notifications.
 */
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/l2/l2_fib.h>
#include <vnet/fib/fib_table.h>
#include <string.h>

#include "evpn.h"

static u64
evpn_learn_mac_key (u32 evi, const u8 * mac)
{
  u64 k = ((u64) evi << 48);
  k |= ((u64) mac[0] << 40) | ((u64) mac[1] << 32) | ((u64) mac[2] << 24) |
    ((u64) mac[3] << 16) | ((u64) mac[4] << 8) | (u64) mac[5];
  return k;
}

void
evpn_publish_mac_learn (u32 evi, mac_address_t * mac, u32 sw_if_index,
			u8 is_add)
{
  evpn_main_t *em = &evpn_main;
  u64 key = evpn_learn_mac_key (evi, mac->bytes);

  if (is_add)
    {
      if (hash_get (em->learned_mac_seen, key))
	return;
      hash_set (em->learned_mac_seen, key, 1);
    }
  else
    {
      if (!hash_get (em->learned_mac_seen, key))
	return;
      hash_unset (em->learned_mac_seen, key);
    }

  evpn_send_mac_learn_event (evi, mac, sw_if_index, is_add);
}

void
evpn_publish_prefix_learn (u32 table_id, fib_prefix_t * pfx,
			   mac_address_t * router_mac, u8 is_add)
{
  evpn_main_t *em = &evpn_main;
  uword key;

  key = table_id;
  if (pfx->fp_proto == FIB_PROTOCOL_IP4)
    key ^= pfx->fp_addr.ip4.as_u32 ^ ((uword) pfx->fp_len << 8);
  else
    key ^= hash_memory (pfx->fp_addr.ip6.as_u8, 16, pfx->fp_len);

  if (is_add)
    {
      if (hash_get (em->learned_pfx_seen, key))
	return;
      hash_set (em->learned_pfx_seen, key, 1);
    }
  else
    {
      if (!hash_get (em->learned_pfx_seen, key))
	return;
      hash_unset (em->learned_pfx_seen, key);
    }

  evpn_send_prefix_learn_event (table_id, pfx, router_mac, is_add);
}

static int
evpn_sw_is_vxlan (u32 sw_if_index)
{
  vnet_hw_interface_t *hi =
    vnet_get_sup_hw_interface (evpn_main.vnet_main, sw_if_index);
  if (!hi || !hi->name)
    return 0;
  return (strncmp ((char *) hi->name, "vxlan", 5) == 0);
}

static int
evpn_sw_is_bvi (u32 sw_if_index)
{
  vnet_hw_interface_t *hi =
    vnet_get_sup_hw_interface (evpn_main.vnet_main, sw_if_index);
  if (!hi || !hi->name)
    return 0;
  return (strncmp ((char *) hi->name, "bvi", 3) == 0);
}

static void
evpn_learn_scan_evi (evpn_evi_t * e)
{
  l2fib_entry_key_t *keys = 0;
  l2fib_entry_result_t *results = 0;
  u32 i;

  l2fib_table_dump (e->bd_index, &keys, &results);

  for (i = 0; i < vec_len (keys); i++)
    {
      l2fib_entry_key_t *k = keys + i;
      l2fib_entry_result_t *r = results + i;
      mac_address_t mac;
      u32 swi;

      if (l2fib_entry_result_is_set_STATIC (r))
	continue;

      swi = r->fields.sw_if_index;
      if (swi == ~0 || evpn_sw_is_vxlan (swi) || evpn_sw_is_bvi (swi))
	continue;

      mac_address_from_bytes (&mac, k->fields.mac);
      evpn_publish_mac_learn (e->evi, &mac, swi, 1 /* is_add */);
    }

  vec_free (keys);
  vec_free (results);
}

static void
evpn_learn_scan_vrf_connected (evpn_vrf_t * v)
{
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr.ip4.as_u32 = clib_host_to_net_u32 (0xa9fe0001),
  };
  evpn_publish_prefix_learn (v->table_id, &pfx, &v->router_mac, 1);
}

static void
evpn_ip4_address_cb (ip4_main_t * im, uword opaque, u32 sw_if_index,
		     ip4_address_t * address, u32 address_length,
		     u32 if_address_index, u32 is_del)
{
  evpn_main_t *em = &evpn_main;
  evpn_evi_t *e;
  evpn_vrf_t *v;
  fib_prefix_t pfx;
  u32 table_id = ~0;
  mac_address_t rmac;
  u8 found = 0;

  if (!em->learn_enabled)
    return;

  pool_foreach (e, em->evis)
  {
    if (e->bvi_sw_if_index == sw_if_index)
      {
	mac_address_copy (&rmac, &e->bvi_mac);
	found = 1;
	break;
      }
  }
  if (!found)
    {
      pool_foreach (v, em->vrfs)
      {
	if (v->bvi_sw_if_index == sw_if_index)
	  {
	    mac_address_copy (&rmac, &v->router_mac);
	    table_id = v->table_id;
	    found = 1;
	    break;
	  }
      }
    }
  if (!found)
    return;

  if (table_id == ~0)
    {
      u32 fib_index = vec_elt (im->fib_index_by_sw_if_index, sw_if_index);
      fib_table_t *ft = fib_table_get (fib_index, FIB_PROTOCOL_IP4);
      if (ft)
	table_id = ft->ft_table_id;
    }
  if (table_id == ~0)
    return;

  pfx.fp_proto = FIB_PROTOCOL_IP4;
  pfx.fp_len = address_length;
  pfx.fp_addr.ip4 = *address;
  evpn_publish_prefix_learn (table_id, &pfx, &rmac, is_del ? 0 : 1);
}

static uword
evpn_learn_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
		    vlib_frame_t * f)
{
  evpn_main_t *em = &evpn_main;
  f64 timeout = 2.0;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      vlib_process_get_events (vm, 0);

      if (!em->learn_enabled)
	continue;

      {
	evpn_evi_t *e;
	evpn_vrf_t *v;
	pool_foreach (e, em->evis)
	{
	  evpn_learn_scan_evi (e);
	}
	pool_foreach (v, em->vrfs)
	{
	  evpn_learn_scan_vrf_connected (v);
	}
      }
    }
  return 0;
}

VLIB_REGISTER_NODE (evpn_learn_process_node) = {
  .function = evpn_learn_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "evpn-learn-process",
};

int
evpn_learn_enable (u8 enable)
{
  evpn_main_t *em = &evpn_main;
  static u8 addr_cb_registered;

  em->learn_enabled = enable;

  if (enable && !addr_cb_registered)
    {
      ip4_add_del_interface_address_callback_t cb = {
	.function = evpn_ip4_address_cb,
	.function_opaque = 0,
      };
      vec_add1 (ip4_main.add_del_interface_address_callbacks, cb);
      addr_cb_registered = 1;
    }

  if (enable)
    vlib_process_signal_event (em->vlib_main,
			       evpn_learn_process_node.index, 0, 0);

  return 0;
}
