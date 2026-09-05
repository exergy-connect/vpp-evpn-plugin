/*
 * Copyright (c) 2026
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * Binary API handlers for the EVPN plugin.
 */
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/ethernet/ethernet_types_api.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/format_fns.h>

#include "evpn.h"

#include <evpn/evpn.api_enum.h>
#include <evpn/evpn.api_types.h>

#define REPLY_MSG_ID_BASE (evpn_main.msg_id_base)
#include <vlibapi/api_helper_macros.h>

typedef struct
{
  u32 client_index;
  u32 pid;
} evpn_learn_client_t;

static evpn_learn_client_t *evpn_learn_clients;

void
evpn_send_mac_learn_event (u32 evi, mac_address_t * mac, u32 sw_if_index,
			   u8 is_add)
{
  evpn_learn_client_t *c;
  vl_api_evpn_mac_learn_event_t *mp;
  vl_api_registration_t *reg;

  vec_foreach (c, evpn_learn_clients)
  {
    reg = vl_api_client_index_to_registration (c->client_index);
    if (!reg)
      continue;
    mp = vl_msg_api_alloc (sizeof (*mp));
    clib_memset (mp, 0, sizeof (*mp));
    mp->_vl_msg_id =
      htons (VL_API_EVPN_MAC_LEARN_EVENT + evpn_main.msg_id_base);
    mp->client_index = htonl (c->client_index);
    mp->pid = htonl (c->pid);
    mp->evi = htonl (evi);
    mac_address_encode (mac, mp->mac);
    mp->sw_if_index = htonl (sw_if_index);
    mp->is_add = is_add;
    vl_api_send_msg (reg, (u8 *) mp);
  }
}

void
evpn_send_prefix_learn_event (u32 table_id, fib_prefix_t * pfx,
			      mac_address_t * router_mac, u8 is_add)
{
  evpn_learn_client_t *c;
  vl_api_evpn_prefix_learn_event_t *mp;
  vl_api_registration_t *reg;

  vec_foreach (c, evpn_learn_clients)
  {
    reg = vl_api_client_index_to_registration (c->client_index);
    if (!reg)
      continue;
    mp = vl_msg_api_alloc (sizeof (*mp));
    clib_memset (mp, 0, sizeof (*mp));
    mp->_vl_msg_id =
      htons (VL_API_EVPN_PREFIX_LEARN_EVENT + evpn_main.msg_id_base);
    mp->client_index = htonl (c->client_index);
    mp->pid = htonl (c->pid);
    mp->table_id = htonl (table_id);
    ip_prefix_encode (pfx, &mp->prefix);
    mac_address_encode (router_mac, mp->router_mac);
    mp->is_add = is_add;
    vl_api_send_msg (reg, (u8 *) mp);
  }
}

static void
vl_api_evpn_plugin_get_version_t_handler (vl_api_evpn_plugin_get_version_t *
					  mp)
{
  vl_api_evpn_plugin_get_version_reply_t *rmp;
  int rv = 0;

  REPLY_MACRO2 (VL_API_EVPN_PLUGIN_GET_VERSION_REPLY, ({
		  rmp->major = htonl (EVPN_PLUGIN_VERSION_MAJOR);
		  rmp->minor = htonl (EVPN_PLUGIN_VERSION_MINOR);
		}));
}

static void
vl_api_evpn_evi_add_del_t_handler (vl_api_evpn_evi_add_del_t * mp)
{
  vl_api_evpn_evi_add_del_reply_t *rmp;
  mac_address_t mac;
  int rv;

  mac_address_decode (mp->router_mac, &mac);
  if (mp->is_add)
    rv = evpn_evi_add (ntohl (mp->evi), ntohl (mp->vni), ntohl (mp->bd_id),
		       mp->irb, mac_address_is_zero (&mac) ? 0 : &mac);
  else
    rv = evpn_evi_del (ntohl (mp->evi));

  REPLY_MACRO (VL_API_EVPN_EVI_ADD_DEL_REPLY);
}

static void
vl_api_evpn_vrf_add_del_t_handler (vl_api_evpn_vrf_add_del_t * mp)
{
  vl_api_evpn_vrf_add_del_reply_t *rmp;
  mac_address_t mac;
  int rv;

  mac_address_decode (mp->router_mac, &mac);
  if (mp->is_add)
    rv = evpn_vrf_add (ntohl (mp->table_id), ntohl (mp->l3_vni),
		       mac_address_is_zero (&mac) ? 0 : &mac);
  else
    rv = evpn_vrf_del (ntohl (mp->table_id));

  REPLY_MACRO (VL_API_EVPN_VRF_ADD_DEL_REPLY);
}

static void
vl_api_evpn_vtep_add_del_t_handler (vl_api_evpn_vtep_add_del_t * mp)
{
  vl_api_evpn_vtep_add_del_reply_t *rmp;
  ip46_address_t local = { }, remote = { };
  u8 is_ip6;
  int rv;

  is_ip6 = ip_address_decode (&mp->local, &local) == IP46_TYPE_IP6;
  ip_address_decode (&mp->remote, &remote);

  if (mp->is_add)
    rv =
      evpn_vtep_add (&local, &remote, ntohl (mp->encap_table_id),
		     ntohs (mp->dst_port), is_ip6);
  else
    rv = evpn_vtep_del (&local, &remote, is_ip6);

  REPLY_MACRO (VL_API_EVPN_VTEP_ADD_DEL_REPLY);
}

static void
vl_api_evpn_mac_add_del_t_handler (vl_api_evpn_mac_add_del_t * mp)
{
  vl_api_evpn_mac_add_del_reply_t *rmp;
  mac_address_t mac;
  ip46_address_t ip = { }, remote = { };
  u8 is_ip6 = 0;
  int rv;

  mac_address_decode (mp->mac, &mac);
  ip_address_decode (&mp->remote, &remote);
  if (mp->has_ip)
    is_ip6 = ip_address_decode (&mp->ip, &ip) == IP46_TYPE_IP6;
  else if (!ip46_address_is_ip4 (&remote))
    is_ip6 = 1;

  if (mp->is_add)
    rv =
      evpn_mac_add (ntohl (mp->evi), &mac, mp->has_ip ? &ip : 0, mp->has_ip,
		    is_ip6, &remote);
  else
    rv = evpn_mac_del (ntohl (mp->evi), &mac);

  REPLY_MACRO (VL_API_EVPN_MAC_ADD_DEL_REPLY);
}

static void
vl_api_evpn_imet_add_del_t_handler (vl_api_evpn_imet_add_del_t * mp)
{
  vl_api_evpn_imet_add_del_reply_t *rmp;
  ip46_address_t remote = { };
  int rv;

  ip_address_decode (&mp->remote, &remote);
  if (mp->is_add)
    rv = evpn_imet_add (ntohl (mp->evi), &remote);
  else
    rv = evpn_imet_del (ntohl (mp->evi), &remote);

  REPLY_MACRO (VL_API_EVPN_IMET_ADD_DEL_REPLY);
}

static void
vl_api_evpn_prefix_add_del_t_handler (vl_api_evpn_prefix_add_del_t * mp)
{
  vl_api_evpn_prefix_add_del_reply_t *rmp;
  fib_prefix_t pfx;
  ip46_address_t remote = { };
  mac_address_t rmac;
  int rv;

  ip_prefix_decode (&mp->prefix, &pfx);
  ip_address_decode (&mp->remote, &remote);
  mac_address_decode (mp->router_mac, &rmac);

  if (mp->is_add)
    rv = evpn_prefix_add (ntohl (mp->table_id), &pfx, &remote, &rmac);
  else
    rv = evpn_prefix_del (ntohl (mp->table_id), &pfx);

  REPLY_MACRO (VL_API_EVPN_PREFIX_ADD_DEL_REPLY);
}

static void
vl_api_evpn_learn_enable_disable_t_handler (vl_api_evpn_learn_enable_disable_t
					    * mp)
{
  vl_api_evpn_learn_enable_disable_reply_t *rmp;
  int rv = evpn_learn_enable (mp->enable);
  REPLY_MACRO (VL_API_EVPN_LEARN_ENABLE_DISABLE_REPLY);
}

static void
vl_api_want_evpn_learn_events_t_handler (vl_api_want_evpn_learn_events_t * mp)
{
  vl_api_want_evpn_learn_events_reply_t *rmp;
  evpn_learn_client_t *c;
  u32 client = mp->client_index;
  u32 pid = ntohl (mp->pid);
  int rv = 0;
  u32 i;

  if (mp->enable_disable)
    {
      vec_foreach_index (i, evpn_learn_clients)
      {
	if (evpn_learn_clients[i].client_index == client)
	  {
	    evpn_learn_clients[i].pid = pid;
	    goto done;
	  }
      }
      vec_add2 (evpn_learn_clients, c, 1);
      c->client_index = client;
      c->pid = pid;
    }
  else
    {
      vec_foreach_index (i, evpn_learn_clients)
      {
	if (evpn_learn_clients[i].client_index == client)
	  {
	    vec_del1 (evpn_learn_clients, i);
	    break;
	  }
      }
    }

done:
  REPLY_MACRO (VL_API_WANT_EVPN_LEARN_EVENTS_REPLY);
}

#include <evpn/evpn.api.c>

static clib_error_t *
evpn_api_init (vlib_main_t * vm)
{
  evpn_main.msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_INIT_FUNCTION (evpn_api_init);
