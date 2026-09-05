/*
 * Copyright (c) 2026
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * EVPN object CRUD — composes existing VPP BD/BVI/VXLAN/L2FIB/FIB objects.
 */
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/l2/l2_bvi.h>
#include <vnet/ip-neighbor/ip_neighbor.h>
#include <vnet/ip/ip4_packet.h>

#include "evpn.h"

evpn_main_t evpn_main;

/* VXLAN tunnel create/delete via CLI: vnet_vxlan_add_del_tunnel is not
 * __clib_export'd from vxlan_plugin.so, so we cannot dlsym it. Creating
 * with an explicit instance gives a stable ifname vxlan_tunnel<N>. */
static u32 evpn_vxlan_instance_seed = 1000;

static u32
evpn_find_sw_if_by_name (vnet_main_t * vnm, u32 instance)
{
  u8 *name = format (0, "vxlan_tunnel%u", instance);
  uword *p;
  u32 hw_if_index, swi = ~0;
  vnet_hw_interface_t *hi;

  p = hash_get_mem (vnm->interface_main.hw_interface_by_name, name);
  if (p)
    {
      hw_if_index = p[0];
      hi = vnet_get_hw_interface (vnm, hw_if_index);
      if (hi)
	swi = hi->sw_if_index;
    }
  vec_free (name);
  return swi;
}

static int
evpn_vxlan_add (ip46_address_t * src, ip46_address_t * dst, u32 vni,
		u8 is_ip6, u32 encap_fib_index, u32 * sw_if_indexp,
		u32 * instancep)
{
  evpn_main_t *em = &evpn_main;
  u8 *cmd = 0;
  int rv;
  u32 instance = evpn_vxlan_instance_seed++;
  unformat_input_t input;
  u32 swi = ~0;
  u32 table_id;

  table_id = fib_table_get_table_id (encap_fib_index,
				     is_ip6 ? FIB_PROTOCOL_IP6 :
				     FIB_PROTOCOL_IP4);
  if (table_id == ~0)
    table_id = 0;

  if (is_ip6)
    cmd =
      format (0,
	      "create vxlan tunnel src %U dst %U vni %u instance %u encap-vrf-id %u",
	      format_ip6_address, &src->ip6, format_ip6_address, &dst->ip6,
	      vni, instance, table_id);
  else
    cmd =
      format (0,
	      "create vxlan tunnel src %U dst %U vni %u instance %u encap-vrf-id %u",
	      format_ip4_address, &src->ip4, format_ip4_address, &dst->ip4,
	      vni, instance, table_id);

  unformat_init_vector (&input, cmd);
  rv = vlib_cli_input (em->vlib_main, &input, 0, 0);
  unformat_free (&input);
  if (rv)
    return VNET_API_ERROR_INVALID_VALUE;

  swi = evpn_find_sw_if_by_name (em->vnet_main, instance);
  if (swi == ~0)
    return VNET_API_ERROR_INVALID_INTERFACE;

  *sw_if_indexp = swi;
  *instancep = instance;
  return 0;
}

static int
evpn_vxlan_del (ip46_address_t * src, ip46_address_t * dst, u32 vni,
		u8 is_ip6)
{
  evpn_main_t *em = &evpn_main;
  u8 *cmd = 0;
  int rv;
  unformat_input_t input;

  if (is_ip6)
    cmd = format (0, "create vxlan tunnel src %U dst %U vni %u del",
		  format_ip6_address, &src->ip6, format_ip6_address,
		  &dst->ip6, vni);
  else
    cmd = format (0, "create vxlan tunnel src %U dst %U vni %u del",
		  format_ip4_address, &src->ip4, format_ip4_address,
		  &dst->ip4, vni);

  unformat_init_vector (&input, cmd);
  rv = vlib_cli_input (em->vlib_main, &input, 0, 0);
  unformat_free (&input);
  return rv ? VNET_API_ERROR_INVALID_VALUE : 0;
}

static u64
evpn_mac_key (u32 evi, const mac_address_t * mac)
{
  u64 k = ((u64) evi << 48);
  k |= ((u64) mac->bytes[0] << 40) | ((u64) mac->bytes[1] << 32) |
    ((u64) mac->bytes[2] << 24) | ((u64) mac->bytes[3] << 16) |
    ((u64) mac->bytes[4] << 8) | (u64) mac->bytes[5];
  return k;
}

static uword
evpn_ip46_hash (ip46_address_t * a, u8 is_ip6)
{
  if (is_ip6)
    return hash_memory (a->ip6.as_u8, 16, 0);
  return (uword) a->ip4.as_u32;
}

static uword
evpn_vtep_key (ip46_address_t * local, ip46_address_t * remote, u8 is_ip6)
{
  return evpn_ip46_hash (local, is_ip6) ^
    (evpn_ip46_hash (remote, is_ip6) << 1);
}

static uword
evpn_tunnel_key (ip46_address_t * src, ip46_address_t * dst, u32 vni,
		 u8 is_ip6)
{
  return evpn_ip46_hash (src, is_ip6) ^ (evpn_ip46_hash (dst, is_ip6) << 1) ^
    vni;
}

static uword
evpn_imet_key (u32 evi, ip46_address_t * remote, u8 is_ip6)
{
  return ((uword) evi << 16) ^ evpn_ip46_hash (remote, is_ip6);
}

static uword
evpn_prefix_key (u32 table_id, fib_prefix_t * pfx)
{
  uword k = table_id;
  if (pfx->fp_proto == FIB_PROTOCOL_IP4)
    k ^= pfx->fp_addr.ip4.as_u32 ^ ((uword) pfx->fp_len << 8);
  else
    k ^= hash_memory (pfx->fp_addr.ip6.as_u8, 16, pfx->fp_len);
  return k;
}

static ip4_address_t
evpn_overlay_nh_from_vtep (ip46_address_t * remote, u8 is_ip6)
{
  ip4_address_t nh;
  u32 h;
  if (is_ip6)
    h = remote->ip6.as_u32[0] ^ remote->ip6.as_u32[3];
  else
    h = remote->ip4.as_u32;
  /* 169.254.x.y with x.y from hash; avoid .0 and .255 */
  nh.as_u32 =
    clib_host_to_net_u32 (EVPN_OVERLAY_NH_BASE |
			  (0x0000fffe & (h ? h : 1)));
  if ((nh.as_u8[3] == 0) || (nh.as_u8[3] == 255))
    nh.as_u8[3] = 1;
  return nh;
}

static void
evpn_feature_init (evpn_main_t * em)
{
  if (em->evi_by_id)
    return;
  em->evi_by_id = hash_create (0, sizeof (uword));
  em->vrf_by_table = hash_create (0, sizeof (uword));
  em->vtep_by_key = hash_create (0, sizeof (uword));
  em->tunnel_by_key = hash_create (0, sizeof (uword));
  em->mac_by_key = hash_create (0, sizeof (uword));
  em->imet_by_key = hash_create (0, sizeof (uword));
  em->prefix_by_key = hash_create (0, sizeof (uword));
  em->learned_mac_seen = hash_create (0, sizeof (uword));
  em->learned_pfx_seen = hash_create (0, sizeof (uword));
  em->fib_src =
    fib_source_allocate ("evpn", FIB_SOURCE_PRIORITY_HI,
			 FIB_SOURCE_BH_API);
}

int
evpn_tunnel_acquire (ip46_address_t * src, ip46_address_t * dst, u32 vni,
		     u8 is_ip6, u32 encap_fib_index, u32 * tunnel_index,
		     u32 * sw_if_index)
{
  evpn_main_t *em = &evpn_main;
  uword key = evpn_tunnel_key (src, dst, vni, is_ip6);
  uword *p;
  evpn_tunnel_t *t;
  int rv;
  u32 swi = ~0;

  evpn_feature_init (em);

  p = hash_get (em->tunnel_by_key, key);
  if (p)
    {
      t = pool_elt_at_index (em->tunnels, p[0]);
      t->refcnt++;
      *tunnel_index = p[0];
      *sw_if_index = t->sw_if_index;
      return 0;
    }

  {
    u32 instance = 0;
    rv = evpn_vxlan_add (src, dst, vni, is_ip6, encap_fib_index, &swi,
			 &instance);
    if (rv)
      return rv;

    pool_get (em->tunnels, t);
    clib_memset (t, 0, sizeof (*t));
    t->src = *src;
    t->dst = *dst;
    t->vni = vni;
    t->encap_fib_index = encap_fib_index;
    t->is_ip6 = is_ip6;
    t->sw_if_index = swi;
    t->instance = instance;
    t->refcnt = 1;
    hash_set (em->tunnel_by_key, key, t - em->tunnels);

    vnet_sw_interface_set_flags (em->vnet_main, swi,
				 VNET_SW_INTERFACE_FLAG_ADMIN_UP);

    *tunnel_index = t - em->tunnels;
    *sw_if_index = swi;
    return 0;
  }
}

void
evpn_tunnel_release (u32 tunnel_index)
{
  evpn_main_t *em = &evpn_main;
  evpn_tunnel_t *t;
  uword key;

  if (pool_is_free_index (em->tunnels, tunnel_index))
    return;
  t = pool_elt_at_index (em->tunnels, tunnel_index);
  if (t->refcnt == 0)
    return;
  if (--t->refcnt > 0)
    return;

  evpn_vxlan_del (&t->src, &t->dst, t->vni, t->is_ip6);

  key = evpn_tunnel_key (&t->src, &t->dst, t->vni, t->is_ip6);
  hash_unset (em->tunnel_by_key, key);
  pool_put (em->tunnels, t);
}

int
evpn_evi_add (u32 evi, u32 vni, u32 bd_id, u8 irb,
	      mac_address_t * router_mac_opt)
{
  evpn_main_t *em = &evpn_main;
  bd_main_t *bdm = &bd_main;
  evpn_evi_t *e;
  uword *p;
  u32 bd_index;
  l2_bridge_domain_add_del_args_t bd_args;

  evpn_feature_init (em);

  p = hash_get (em->evi_by_id, evi);
  if (p)
    return VNET_API_ERROR_VALUE_EXIST;

  clib_memset (&bd_args, 0, sizeof (bd_args));
  bd_args.bd_id = bd_id;
  bd_args.is_add = 1;
  bd_args.flood = 1;
  bd_args.uu_flood = 1;
  bd_args.forward = 1;
  bd_args.learn = 1;
  bd_args.arp_term = 0;
  bd_args.arp_ufwd = 0;
  bd_add_del (&bd_args);

  bd_index = bd_find_or_add_bd_index (bdm, bd_id);

  pool_get (em->evis, e);
  clib_memset (e, 0, sizeof (*e));
  e->evi = evi;
  e->vni = vni;
  e->bd_id = bd_id;
  e->bd_index = bd_index;
  e->irb = irb;
  e->bvi_sw_if_index = ~0;

  if (irb)
    {
      mac_address_t mac;
      u32 swi = ~0;
      int rv;

      if (router_mac_opt && !mac_address_is_zero (router_mac_opt))
	mac_address_copy (&mac, router_mac_opt);
      else
	mac_address_set_zero (&mac);

      rv = l2_bvi_create (bd_id, &mac, &swi);
      if (rv)
	{
	  pool_put (em->evis, e);
	  return rv;
	}

      set_int_l2_mode (em->vlib_main, em->vnet_main, MODE_L2_BRIDGE, swi,
		       bd_index, L2_BD_PORT_TYPE_BVI, 0, 0);
      vnet_sw_interface_set_flags (em->vnet_main, swi,
				   VNET_SW_INTERFACE_FLAG_ADMIN_UP);

      e->bvi_sw_if_index = swi;
      {
	vnet_hw_interface_t *hi =
	  vnet_get_sup_hw_interface (em->vnet_main, swi);
	mac_address_from_bytes (&e->bvi_mac, hi->hw_address);
      }

      /* Advertise local BVI MAC for Type-2 origination */
      evpn_publish_mac_learn (evi, &e->bvi_mac, swi, 1 /* is_add */);
    }

  hash_set (em->evi_by_id, evi, e - em->evis);
  return 0;
}

int
evpn_evi_del (u32 evi)
{
  evpn_main_t *em = &evpn_main;
  uword *p;
  evpn_evi_t *e;
  l2_bridge_domain_add_del_args_t bd_args;

  p = hash_get (em->evi_by_id, evi);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  e = pool_elt_at_index (em->evis, p[0]);

  if (e->bvi_sw_if_index != ~0)
    {
      evpn_publish_mac_learn (evi, &e->bvi_mac, e->bvi_sw_if_index, 0);
      set_int_l2_mode (em->vlib_main, em->vnet_main, MODE_L3,
		       e->bvi_sw_if_index, 0, L2_BD_PORT_TYPE_NORMAL, 0, 0);
      l2_bvi_delete (e->bvi_sw_if_index);
    }

  clib_memset (&bd_args, 0, sizeof (bd_args));
  bd_args.bd_id = e->bd_id;
  bd_args.is_add = 0;
  bd_add_del (&bd_args);

  hash_unset (em->evi_by_id, evi);
  pool_put (em->evis, e);
  return 0;
}

int
evpn_vrf_add (u32 table_id, u32 l3_vni, mac_address_t * router_mac_opt)
{
  evpn_main_t *em = &evpn_main;
  bd_main_t *bdm = &bd_main;
  evpn_vrf_t *v;
  uword *p;
  u32 bd_id, bd_index, swi = ~0;
  mac_address_t mac;
  l2_bridge_domain_add_del_args_t bd_args;
  int rv;

  evpn_feature_init (em);

  p = hash_get (em->vrf_by_table, table_id);
  if (p)
    return VNET_API_ERROR_VALUE_EXIST;

  /* Create tenant IP tables */
  ip_table_create (FIB_PROTOCOL_IP4, table_id, 0 /* is_api */, 0,
		   (u8 *) "evpn");
  ip_table_create (FIB_PROTOCOL_IP6, table_id, 0 /* is_api */, 0,
		   (u8 *) "evpn");

  bd_id = EVPN_L3_BD_BASE + table_id;
  clib_memset (&bd_args, 0, sizeof (bd_args));
  bd_args.bd_id = bd_id;
  bd_args.is_add = 1;
  bd_args.flood = 1;
  bd_args.uu_flood = 1;
  bd_args.forward = 1;
  bd_args.learn = 0;		/* remote rMACs are static */
  bd_add_del (&bd_args);
  bd_index = bd_find_or_add_bd_index (bdm, bd_id);

  if (router_mac_opt && !mac_address_is_zero (router_mac_opt))
    mac_address_copy (&mac, router_mac_opt);
  else
    mac_address_set_zero (&mac);

  rv = l2_bvi_create (bd_id, &mac, &swi);
  if (rv)
    return rv;

  set_int_l2_mode (em->vlib_main, em->vnet_main, MODE_L2_BRIDGE, swi,
		   bd_index, L2_BD_PORT_TYPE_BVI, 0, 0);

  /* Bind L3 BVI into tenant table and give it a host-only address so
   * IPv4 input is enabled (same trick as the lab stub). */
  ip_table_bind (FIB_PROTOCOL_IP4, swi, table_id);
  ip_table_bind (FIB_PROTOCOL_IP6, swi, table_id);
  {
    ip4_address_t host = { .as_u32 = clib_host_to_net_u32 (0xa9fe0001) };
    ip4_add_del_interface_address (em->vlib_main, swi, &host, 32,
				   0 /* is_del */);
  }
  vnet_sw_interface_set_flags (em->vnet_main, swi,
			       VNET_SW_INTERFACE_FLAG_ADMIN_UP);

  pool_get (em->vrfs, v);
  clib_memset (v, 0, sizeof (*v));
  v->table_id = table_id;
  v->fib_index4 =
    fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4, table_id,
				      em->fib_src);
  v->fib_index6 =
    fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP6, table_id,
				      em->fib_src);
  v->l3_vni = l3_vni;
  v->bd_id = bd_id;
  v->bd_index = bd_index;
  v->bvi_sw_if_index = swi;
  {
    vnet_hw_interface_t *hi = vnet_get_sup_hw_interface (em->vnet_main, swi);
    mac_address_from_bytes (&v->router_mac, hi->hw_address);
  }

  hash_set (em->vrf_by_table, table_id, v - em->vrfs);

  /* Local router-mac + connected prefixes are Type-5 candidates */
  {
    fib_prefix_t pfx = {
      .fp_proto = FIB_PROTOCOL_IP4,
      .fp_len = 32,
      .fp_addr.ip4.as_u32 = clib_host_to_net_u32 (0xa9fe0001),
    };
    evpn_publish_prefix_learn (table_id, &pfx, &v->router_mac, 1);
  }

  return 0;
}

int
evpn_vrf_del (u32 table_id)
{
  evpn_main_t *em = &evpn_main;
  uword *p;
  evpn_vrf_t *v;
  l2_bridge_domain_add_del_args_t bd_args;

  p = hash_get (em->vrf_by_table, table_id);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  v = pool_elt_at_index (em->vrfs, p[0]);

  set_int_l2_mode (em->vlib_main, em->vnet_main, MODE_L3, v->bvi_sw_if_index,
		   0, L2_BD_PORT_TYPE_NORMAL, 0, 0);
  l2_bvi_delete (v->bvi_sw_if_index);

  clib_memset (&bd_args, 0, sizeof (bd_args));
  bd_args.bd_id = v->bd_id;
  bd_args.is_add = 0;
  bd_add_del (&bd_args);

  fib_table_unlock (v->fib_index4, FIB_PROTOCOL_IP4, em->fib_src);
  fib_table_unlock (v->fib_index6, FIB_PROTOCOL_IP6, em->fib_src);

  hash_unset (em->vrf_by_table, table_id);
  pool_put (em->vrfs, v);
  return 0;
}

int
evpn_vtep_add (ip46_address_t * local, ip46_address_t * remote,
	       u32 encap_table_id, u8 is_ip6)
{
  evpn_main_t *em = &evpn_main;
  evpn_vtep_t *vt;
  uword key, *p;

  evpn_feature_init (em);

  key = evpn_vtep_key (local, remote, is_ip6);
  p = hash_get (em->vtep_by_key, key);
  if (p)
    return VNET_API_ERROR_VALUE_EXIST;

  pool_get (em->vteps, vt);
  clib_memset (vt, 0, sizeof (*vt));
  vt->local = *local;
  vt->remote = *remote;
  vt->encap_table_id = encap_table_id;
  vt->is_ip6 = is_ip6;
  hash_set (em->vtep_by_key, key, vt - em->vteps);

  if (!em->have_default_local)
    {
      em->default_local = *local;
      em->default_local_is_ip6 = is_ip6;
      em->default_encap_table_id = encap_table_id;
      em->have_default_local = 1;
    }
  return 0;
}

int
evpn_vtep_del (ip46_address_t * local, ip46_address_t * remote, u8 is_ip6)
{
  evpn_main_t *em = &evpn_main;
  uword key = evpn_vtep_key (local, remote, is_ip6);
  uword *p = hash_get (em->vtep_by_key, key);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  pool_put_index (em->vteps, p[0]);
  hash_unset (em->vtep_by_key, key);
  return 0;
}

static int
evpn_resolve_local_vtep (ip46_address_t * remote, u8 is_ip6,
			 ip46_address_t * local_out, u32 * encap_fib_out)
{
  evpn_main_t *em = &evpn_main;
  evpn_vtep_t *vt;

  pool_foreach (vt, em->vteps)
  {
    if (vt->is_ip6 != is_ip6)
      continue;
    if (ip46_address_cmp (&vt->remote, remote) == 0)
      {
	*local_out = vt->local;
	*encap_fib_out =
	  fib_table_find (is_ip6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4,
			  vt->encap_table_id);
	if (*encap_fib_out == ~0)
	  *encap_fib_out = 0;
	return 0;
      }
  }

  if (em->have_default_local && em->default_local_is_ip6 == is_ip6)
    {
      *local_out = em->default_local;
      *encap_fib_out =
	fib_table_find (is_ip6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4,
			em->default_encap_table_id);
      if (*encap_fib_out == ~0)
	*encap_fib_out = 0;
      return 0;
    }
  return VNET_API_ERROR_NO_SUCH_ENTRY;
}

int
evpn_mac_add (u32 evi, mac_address_t * mac, ip46_address_t * ip_opt,
	      u8 has_ip, u8 is_ip6, ip46_address_t * remote)
{
  evpn_main_t *em = &evpn_main;
  uword *p, mkey;
  evpn_evi_t *e;
  evpn_mac_t *m;
  ip46_address_t local;
  u32 encap_fib = 0, tidx = ~0, swi = ~0;
  int rv;

  evpn_feature_init (em);

  p = hash_get (em->evi_by_id, evi);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  e = pool_elt_at_index (em->evis, p[0]);

  mkey = evpn_mac_key (evi, mac);
  if (hash_get (em->mac_by_key, mkey))
    return VNET_API_ERROR_VALUE_EXIST;

  rv = evpn_resolve_local_vtep (remote, is_ip6, &local, &encap_fib);
  if (rv)
    return rv;

  rv =
    evpn_tunnel_acquire (&local, remote, e->vni, is_ip6, encap_fib, &tidx,
			 &swi);
  if (rv)
    return rv;

  /* Attach tunnel to EVI BD if not already (set_int_l2_mode is idempotent
   * enough for our purposes). */
  set_int_l2_mode (em->vlib_main, em->vnet_main, MODE_L2_BRIDGE, swi,
		   e->bd_index, L2_BD_PORT_TYPE_NORMAL, 0, 0);

  l2fib_add_entry (mac->bytes, e->bd_index, swi,
		   L2FIB_ENTRY_RESULT_FLAG_STATIC);

  if (has_ip && ip_opt && e->bvi_sw_if_index != ~0)
    {
      ip_address_t ipa;
      u32 stats = ~0;
      if (is_ip6)
	{
	  ip_address_set (&ipa, &ip_opt->ip6, AF_IP6);
	}
      else
	{
	  ip_address_set (&ipa, &ip_opt->ip4, AF_IP4);
	}
      ip_neighbor_add (&ipa, mac, e->bvi_sw_if_index,
		       IP_NEIGHBOR_FLAG_STATIC, &stats);
    }

  pool_get (em->macs, m);
  clib_memset (m, 0, sizeof (*m));
  m->evi = evi;
  mac_address_copy (&m->mac, mac);
  m->has_ip = has_ip;
  m->is_ip6 = is_ip6;
  if (has_ip && ip_opt)
    m->ip = *ip_opt;
  m->remote = *remote;
  m->tunnel_index = tidx;
  hash_set (em->mac_by_key, mkey, m - em->macs);
  return 0;
}

int
evpn_mac_del (u32 evi, mac_address_t * mac)
{
  evpn_main_t *em = &evpn_main;
  uword mkey = evpn_mac_key (evi, mac);
  uword *p = hash_get (em->mac_by_key, mkey);
  evpn_mac_t *m;
  evpn_evi_t *e;
  uword *ep;

  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  m = pool_elt_at_index (em->macs, p[0]);

  ep = hash_get (em->evi_by_id, evi);
  if (ep)
    {
      e = pool_elt_at_index (em->evis, ep[0]);
      l2fib_del_entry (mac->bytes, e->bd_index, ~0);
      if (m->has_ip && e->bvi_sw_if_index != ~0)
	{
	  ip_address_t ipa;
	  if (m->is_ip6)
	    ip_address_set (&ipa, &m->ip.ip6, AF_IP6);
	  else
	    ip_address_set (&ipa, &m->ip.ip4, AF_IP4);
	  ip_neighbor_del (&ipa, e->bvi_sw_if_index);
	}
    }

  evpn_tunnel_release (m->tunnel_index);
  hash_unset (em->mac_by_key, mkey);
  pool_put (em->macs, m);
  return 0;
}

int
evpn_imet_add (u32 evi, ip46_address_t * remote)
{
  evpn_main_t *em = &evpn_main;
  uword *p, key;
  evpn_evi_t *e;
  evpn_imet_t *im;
  ip46_address_t local;
  u32 encap_fib = 0, tidx = ~0, swi = ~0;
  u8 is_ip6 = !ip46_address_is_ip4 (remote);
  int rv;

  evpn_feature_init (em);

  p = hash_get (em->evi_by_id, evi);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  e = pool_elt_at_index (em->evis, p[0]);

  key = evpn_imet_key (evi, remote, is_ip6);
  if (hash_get (em->imet_by_key, key))
    return VNET_API_ERROR_VALUE_EXIST;

  rv = evpn_resolve_local_vtep (remote, is_ip6, &local, &encap_fib);
  if (rv)
    return rv;

  rv =
    evpn_tunnel_acquire (&local, remote, e->vni, is_ip6, encap_fib, &tidx,
			 &swi);
  if (rv)
    return rv;

  /* Member of BD → participates in flood list (BUM / Type-3). */
  set_int_l2_mode (em->vlib_main, em->vnet_main, MODE_L2_BRIDGE, swi,
		   e->bd_index, L2_BD_PORT_TYPE_NORMAL, 0, 0);

  pool_get (em->imets, im);
  clib_memset (im, 0, sizeof (*im));
  im->evi = evi;
  im->remote = *remote;
  im->tunnel_index = tidx;
  hash_set (em->imet_by_key, key, im - em->imets);
  return 0;
}

int
evpn_imet_del (u32 evi, ip46_address_t * remote)
{
  evpn_main_t *em = &evpn_main;
  u8 is_ip6 = !ip46_address_is_ip4 (remote);
  uword key = evpn_imet_key (evi, remote, is_ip6);
  uword *p = hash_get (em->imet_by_key, key);
  evpn_imet_t *im;

  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  im = pool_elt_at_index (em->imets, p[0]);
  evpn_tunnel_release (im->tunnel_index);
  hash_unset (em->imet_by_key, key);
  pool_put (em->imets, im);
  return 0;
}

int
evpn_prefix_add (u32 table_id, fib_prefix_t * pfx, ip46_address_t * remote,
		 mac_address_t * router_mac)
{
  evpn_main_t *em = &evpn_main;
  uword *p, key;
  evpn_vrf_t *v;
  evpn_prefix_t *pr;
  ip46_address_t local;
  u32 encap_fib = 0, tidx = ~0, swi = ~0;
  u8 is_ip6 = (pfx->fp_proto == FIB_PROTOCOL_IP6);
  ip4_address_t overlay_nh;
  int rv;

  evpn_feature_init (em);

  p = hash_get (em->vrf_by_table, table_id);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  v = pool_elt_at_index (em->vrfs, p[0]);

  key = evpn_prefix_key (table_id, pfx);
  if (hash_get (em->prefix_by_key, key))
    return VNET_API_ERROR_VALUE_EXIST;

  rv = evpn_resolve_local_vtep (remote, is_ip6 || !ip46_address_is_ip4 (remote),
				&local, &encap_fib);
  if (rv)
    {
      /* Prefer underlay AF of the remote VTEP */
      is_ip6 = !ip46_address_is_ip4 (remote);
      rv = evpn_resolve_local_vtep (remote, is_ip6, &local, &encap_fib);
      if (rv)
	return rv;
    }

  /* L3-VNI tunnel attached to L3 BD */
  rv =
    evpn_tunnel_acquire (&local, remote, v->l3_vni, is_ip6, encap_fib, &tidx,
			 &swi);
  if (rv)
    return rv;

  set_int_l2_mode (em->vlib_main, em->vnet_main, MODE_L2_BRIDGE, swi,
		   v->bd_index, L2_BD_PORT_TYPE_NORMAL, 0, 0);

  /* Remote router MAC → L2FIB on L3-VNI BD */
  l2fib_add_entry (router_mac->bytes, v->bd_index, swi,
		   L2FIB_ENTRY_RESULT_FLAG_STATIC);

  overlay_nh = evpn_overlay_nh_from_vtep (remote, is_ip6);

  /* Neighbor on L3 BVI: overlay-nh → remote router-mac */
  {
    ip_address_t ipa;
    u32 stats = ~0;
    ip_address_set (&ipa, &overlay_nh, AF_IP4);
    ip_neighbor_add (&ipa, router_mac, v->bvi_sw_if_index,
		     IP_NEIGHBOR_FLAG_STATIC, &stats);
  }

  /* FIB: prefix via overlay-nh out L3 BVI */
  {
    ip46_address_t nh46 = { };
    nh46.ip4 = overlay_nh;
    fib_table_entry_path_add (pfx->fp_proto == FIB_PROTOCOL_IP4 ?
			      v->fib_index4 : v->fib_index6,
			      pfx, em->fib_src, FIB_ENTRY_FLAG_NONE,
			      DPO_PROTO_IP4, &nh46, v->bvi_sw_if_index,
			      ~0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);
  }

  pool_get (em->prefixes, pr);
  clib_memset (pr, 0, sizeof (*pr));
  pr->table_id = table_id;
  pr->prefix = *pfx;
  pr->remote = *remote;
  mac_address_copy (&pr->router_mac, router_mac);
  pr->overlay_nh4 = overlay_nh;
  pr->tunnel_index = tidx;
  pr->vrf_index = v - em->vrfs;
  hash_set (em->prefix_by_key, key, pr - em->prefixes);
  return 0;
}

int
evpn_prefix_del (u32 table_id, fib_prefix_t * pfx)
{
  evpn_main_t *em = &evpn_main;
  uword key = evpn_prefix_key (table_id, pfx);
  uword *p = hash_get (em->prefix_by_key, key);
  evpn_prefix_t *pr;
  evpn_vrf_t *v;

  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  pr = pool_elt_at_index (em->prefixes, p[0]);
  v = pool_elt_at_index (em->vrfs, pr->vrf_index);

  fib_table_entry_delete (pfx->fp_proto == FIB_PROTOCOL_IP4 ?
			  v->fib_index4 : v->fib_index6, pfx, em->fib_src);

  {
    ip_address_t ipa;
    ip_address_set (&ipa, &pr->overlay_nh4, AF_IP4);
    ip_neighbor_del (&ipa, v->bvi_sw_if_index);
  }

  l2fib_del_entry (pr->router_mac.bytes, v->bd_index, ~0);
  evpn_tunnel_release (pr->tunnel_index);

  hash_unset (em->prefix_by_key, key);
  pool_put (em->prefixes, pr);
  return 0;
}

u8 *
format_evpn_evi (u8 * s, va_list * args)
{
  evpn_evi_t *e = va_arg (*args, evpn_evi_t *);
  s = format (s, "evi %u vni %u bd %u irb %u bvi %u mac %U",
	      e->evi, e->vni, e->bd_id, e->irb, e->bvi_sw_if_index,
	      format_mac_address, e->bvi_mac.bytes);
  return s;
}

u8 *
format_evpn_vrf (u8 * s, va_list * args)
{
  evpn_vrf_t *v = va_arg (*args, evpn_vrf_t *);
  s = format (s, "table %u l3-vni %u bd %u bvi %u rmac %U",
	      v->table_id, v->l3_vni, v->bd_id, v->bvi_sw_if_index,
	      format_mac_address, v->router_mac.bytes);
  return s;
}

u8 *
format_evpn_tunnel (u8 * s, va_list * args)
{
  evpn_tunnel_t *t = va_arg (*args, evpn_tunnel_t *);
  s = format (s, "[%u] src %U dst %U vni %u sw_if %u ref %u",
	      t - evpn_main.tunnels,
	      format_ip46_address, &t->src, IP46_TYPE_ANY,
	      format_ip46_address, &t->dst, IP46_TYPE_ANY,
	      t->vni, t->sw_if_index, t->refcnt);
  return s;
}
