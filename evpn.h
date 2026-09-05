/*
 * Copyright (c) 2026
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * Minimal EVPN-to-FIB/FDB agent for VPP.
 * Composes BD / BVI / VXLAN / L2FIB / IP FIB — no new graph nodes, no BGP.
 */
#ifndef included_evpn_h
#define included_evpn_h

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/l2/l2_fib.h>
#include <vnet/l2/l2_input.h>
#include <vnet/fib/fib_types.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_source.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vlib/log.h>

#define EVPN_PLUGIN_VERSION_MAJOR 0
#define EVPN_PLUGIN_VERSION_MINOR 1

/* L3-VNI BD id = base + fib table id (matches lab stub convention). */
#define EVPN_L3_BD_BASE 10000

/* Synthetic overlay NH in 169.254.0.0/16 derived from remote VTEP. */
#define EVPN_OVERLAY_NH_BASE 0xa9fe0000 /* 169.254.0.0 */

typedef struct
{
  u32 evi;
  u32 vni;
  u32 bd_id;
  u32 bd_index;
  u8 irb;			/* create/bind BVI in this BD */
  u32 bvi_sw_if_index;		/* ~0 if no IRB */
  mac_address_t bvi_mac;
} evpn_evi_t;

typedef struct
{
  u32 table_id;
  u32 fib_index4;
  u32 fib_index6;
  u32 l3_vni;
  u32 bd_id;
  u32 bd_index;
  u32 bvi_sw_if_index;
  mac_address_t router_mac;
} evpn_vrf_t;

typedef struct
{
  ip46_address_t local;
  ip46_address_t remote;
  u32 encap_table_id;
  u8 is_ip6;
} evpn_vtep_t;

/* Refcounted VXLAN tunnel {src,dst,vni} → sw_if_index */
typedef struct
{
  ip46_address_t src;
  ip46_address_t dst;
  u32 vni;
  u32 encap_fib_index;
  u8 is_ip6;
  u32 sw_if_index;
  u32 instance;			/* vxlan_tunnel instance id */
  u32 refcnt;
} evpn_tunnel_t;

typedef struct
{
  u32 evi;
  mac_address_t mac;
  ip46_address_t ip;		/* zero if MAC-only */
  u8 has_ip;
  u8 is_ip6;
  ip46_address_t remote;	/* VTEP */
  u32 tunnel_index;		/* pool index into tunnels */
} evpn_mac_t;

typedef struct
{
  u32 evi;
  ip46_address_t remote;
  u32 tunnel_index;
} evpn_imet_t;

typedef struct
{
  u32 table_id;
  fib_prefix_t prefix;
  ip46_address_t remote;	/* VTEP */
  mac_address_t router_mac;
  ip4_address_t overlay_nh4;
  u32 tunnel_index;
  u32 vrf_index;		/* pool index into vrfs */
} evpn_prefix_t;

typedef struct
{
  /* Object pools */
  evpn_evi_t *evis;
  evpn_vrf_t *vrfs;
  evpn_vtep_t *vteps;
  evpn_tunnel_t *tunnels;
  evpn_mac_t *macs;
  evpn_imet_t *imets;
  evpn_prefix_t *prefixes;

  /* Indexes: key → pool index */
  uword *evi_by_id;		/* evi → index */
  uword *vrf_by_table;		/* table_id → index */
  uword *vtep_by_key;		/* hash of local||remote */
  uword *tunnel_by_key;		/* hash of src||dst||vni */
  uword *mac_by_key;		/* hash of evi||mac */
  uword *imet_by_key;		/* hash of evi||remote */
  uword *prefix_by_key;		/* hash of table||prefix */

  /* Local VTEP used when creating tunnels (set by first vtep add) */
  ip46_address_t default_local;
  u8 have_default_local;
  u8 default_local_is_ip6;
  u32 default_encap_table_id;

  fib_source_t fib_src;

  /* Learn / origination */
  u8 learn_enabled;
  u32 learn_process_node_index;
  uword *learned_mac_seen;	/* evi||mac already advertised */
  uword *learned_pfx_seen;

  /* Binary API */
  u16 msg_id_base;
  uword *learn_clients;		/* client_index bitmap / vec */

  /* Logging: class "evpn". Level via `evpn logging` or
   * `set logging class evpn level <emerg|alert|crit|error|warn|notice|info|debug|disabled>`. */
  vlib_log_class_t log_class;

  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} evpn_main_t;

extern evpn_main_t evpn_main;

#define EVPN_DBG(...)	vlib_log_debug (evpn_main.log_class, __VA_ARGS__)
#define EVPN_INFO(...)	vlib_log_info (evpn_main.log_class, __VA_ARGS__)
#define EVPN_NOTICE(...) vlib_log_notice (evpn_main.log_class, __VA_ARGS__)
#define EVPN_WARN(...)	vlib_log_warn (evpn_main.log_class, __VA_ARGS__)
#define EVPN_ERR(...)	vlib_log_err (evpn_main.log_class, __VA_ARGS__)

/* ---- Object API (CLI and binary API call these) ---- */

int evpn_evi_add (u32 evi, u32 vni, u32 bd_id, u8 irb,
		  mac_address_t * router_mac_opt);
int evpn_evi_del (u32 evi);

int evpn_vrf_add (u32 table_id, u32 l3_vni, mac_address_t * router_mac_opt);
int evpn_vrf_del (u32 table_id);

int evpn_vtep_add (ip46_address_t * local, ip46_address_t * remote,
		   u32 encap_table_id, u8 is_ip6);
int evpn_vtep_del (ip46_address_t * local, ip46_address_t * remote, u8 is_ip6);

int evpn_mac_add (u32 evi, mac_address_t * mac, ip46_address_t * ip_opt,
		  u8 has_ip, u8 is_ip6, ip46_address_t * remote);
int evpn_mac_del (u32 evi, mac_address_t * mac);

int evpn_imet_add (u32 evi, ip46_address_t * remote);
int evpn_imet_del (u32 evi, ip46_address_t * remote);

int evpn_prefix_add (u32 table_id, fib_prefix_t * pfx,
		     ip46_address_t * remote, mac_address_t * router_mac);
int evpn_prefix_del (u32 table_id, fib_prefix_t * pfx);

int evpn_learn_enable (u8 enable);

/* Tunnel refcount helpers */
int evpn_tunnel_acquire (ip46_address_t * src, ip46_address_t * dst,
			 u32 vni, u8 is_ip6, u32 encap_fib_index,
			 u32 * tunnel_index, u32 * sw_if_index);
void evpn_tunnel_release (u32 tunnel_index);

/* Learn event publishers (called from learn path) */
void evpn_publish_mac_learn (u32 evi, mac_address_t * mac, u32 sw_if_index,
			     u8 is_add);
void evpn_publish_prefix_learn (u32 table_id, fib_prefix_t * pfx,
				mac_address_t * router_mac, u8 is_add);

u8 *format_evpn_evi (u8 * s, va_list * args);
u8 *format_evpn_vrf (u8 * s, va_list * args);
u8 *format_evpn_tunnel (u8 * s, va_list * args);

void evpn_send_mac_learn_event (u32 evi, mac_address_t * mac, u32 sw_if_index,
				u8 is_add);
void evpn_send_prefix_learn_event (u32 table_id, fib_prefix_t * pfx,
				   mac_address_t * router_mac, u8 is_add);

#endif /* included_evpn_h */
