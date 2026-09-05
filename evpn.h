/*
 * Copyright (c) 2026
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * Minimal EVPN-to-FIB/FDB agent for VPP.
 * Borrows BD / BVI; manages VXLAN / L2FIB / IP FIB — no new graph nodes, no BGP.
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
#include <svm/queue.h>

#define EVPN_PLUGIN_VERSION_MAJOR 0
#define EVPN_PLUGIN_VERSION_MINOR 4

/* L3-VNI BD id = base + fib table id (matches lab stub convention). */
#define EVPN_L3_BD_BASE 10000

/* Synthetic overlay NH allocation ranges; unique per peer within a VRF. */
#define EVPN_OVERLAY_NH_BASE 0xa9fe0000 /* 169.254.0.0 */
/* IPv6 Type-5 overlay: fd00:a9fe::/64 with 16-bit host id (mirror of above). */
#define EVPN_OVERLAY_NH6_WORD0_HOST 0xfd00a9fe
#define EVPN_OVERLAY_NH6_WORD1_HOST 0x00000000
#define EVPN_OVERLAY_NH6_WORD2_HOST 0x00000000
/* word3 host = 16-bit host id in low 16 bits */

/* IANA VXLAN UDP dest port; used when dst_port is omitted or 0. */
#define EVPN_VXLAN_DST_PORT 4789

/* How a protected anycast / SVI gateway MAC or IP was inferred. */
typedef enum
{
  EVPN_GW_SRC_BVI = 1,
  EVPN_GW_SRC_L2FIB_BVI = 2,
  EVPN_GW_SRC_MACVLAN = 3,
} evpn_gw_src_t;

typedef struct
{
  u32 evi;
  mac_address_t mac;
  evpn_gw_src_t src;
  u8 plugin_l2fib;		/* plugin installed local FDB → BVI */
  u32 gen;
} evpn_gw_mac_t;

typedef struct
{
  u32 evi;
  ip46_address_t ip;
  u8 is_ip6;
  u8 prefix_len;
  evpn_gw_src_t src;
  u32 gen;
} evpn_gw_ip_t;

typedef struct
{
  u32 evi;
  u32 vni;
  u32 bd_id;
  u32 bd_index;
  u8 irb;			/* reference existing BVI in this BD */
  u32 bvi_sw_if_index;		/* ~0 if no IRB */
  mac_address_t bvi_mac;
} evpn_evi_t;

/* How IPv4 Type-5 prefixes choose the L3-BVI overlay next hop. */
typedef enum
{
  EVPN_IPV4_NH_AUTO = 0,	/* no IPv4 on L3 BVI → IPv6 NH (RFC 8950-style) */
  EVPN_IPV4_NH_IPV4 = 1,	/* classic 169.254.x.y */
  EVPN_IPV4_NH_IPV6 = 2,	/* always fd00:a9fe:: (no 169.254) */
} evpn_ipv4_nh_mode_t;

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
  evpn_ipv4_nh_mode_t ipv4_nh_mode;
} evpn_vrf_t;

typedef struct
{
  ip46_address_t local;
  ip46_address_t remote;
  u32 encap_table_id;
  u16 dst_port;			/* remote VTEP UDP dest port */
  u8 is_ip6;
} evpn_vtep_t;

/* Refcounted VXLAN tunnel {src,dst,vni} → sw_if_index */
typedef struct
{
  ip46_address_t src;
  ip46_address_t dst;
  u32 vni;
  u32 encap_fib_index;
  u16 dst_port;
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
  ip46_address_t overlay_nh;	/* 169.254.x.y or fd00:a9fe::xxxx */
  u32 tunnel_index;
  u32 vrf_index;		/* pool index into vrfs */
  u8 from_kernel;		/* installed from FRR/zebra netlink */
  u32 kernel_gen;
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
  evpn_gw_mac_t *gw_macs;	/* protected gateway MACs (anycast / SVI) */
  evpn_gw_ip_t *gw_ips;		/* protected gateway IPs */

  /* Indexes: key → pool index */
  uword *evi_by_id;		/* evi → index */
  uword *evi_by_bd;		/* bd_index → evi id */
  uword *vrf_by_table;		/* table_id → index */
  uword *vtep_by_key;		/* hash of local||remote */
  uword *tunnel_by_key;		/* hash of src||dst||vni */
  uword *mac_by_key;		/* hash of evi||mac */
  uword *imet_by_key;		/* hash of evi||remote */
  uword *prefix_by_key;		/* hash of table||prefix */
  uword *gw_mac_by_key;		/* hash of evi||mac → gw_macs index */
  uword *gw_ip_by_key;		/* hash of evi||ip → gw_ips index */
  uword *kernel_neigh4;		/* IPv4 via → packed router MAC */
  uword *kernel_neigh6;		/* hash of IPv6 via → packed router MAC */
  uword *nl_if_mac;		/* ifindex → packed MAC (dataplane links) */
  uword *nl_macvlan_parent;	/* macvlan ifindex → parent ifindex */

  /* Local VTEP used when creating tunnels (set by first vtep add) */
  ip46_address_t default_local;
  u8 have_default_local;
  u8 default_local_is_ip6;
  u32 default_encap_table_id;
  u16 default_dst_port;

  fib_source_t fib_src;

  /* Learn / origination (event-driven; reconcile on enable / overrun) */
  u8 learn_enabled;
  u32 learn_process_node_index;
  uword *learned_mac_seen;	/* evi||mac already advertised */
  uword *learned_pfx_seen;
  u32 kernel_route_gen;
  u32 gw_gen;			/* protected-set refresh generation */
  u8 gw_macvlan_skip_logged;	/* once-per-cycle macvlan skip */

  /* Long-lived dataplane netlink */
  int nl_fd;
  u32 nl_file_index;
  u32 nl_seq;

  /* In-process L2 MAC event client (want_l2_macs_events machinery) */
  svm_queue_t *mac_evt_queue;
  u32 mac_evt_client_index;
  int mac_evt_fd;
  u32 mac_evt_file_index;
  u8 mac_evt_registered;

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

int evpn_vrf_add (u32 table_id, u32 l3_vni, mac_address_t * router_mac_opt,
		  evpn_ipv4_nh_mode_t ipv4_nh_mode);
int evpn_vrf_del (u32 table_id);

int evpn_vtep_add (ip46_address_t * local, ip46_address_t * remote,
		   u32 encap_table_id, u16 dst_port, u8 is_ip6);
int evpn_vtep_del (ip46_address_t * local, ip46_address_t * remote, u8 is_ip6);

int evpn_mac_add (u32 evi, mac_address_t * mac, ip46_address_t * ip_opt,
		  u8 has_ip, u8 ip_is_ip6, ip46_address_t * remote);
int evpn_mac_del (u32 evi, mac_address_t * mac);

int evpn_imet_add (u32 evi, ip46_address_t * remote);
int evpn_imet_del (u32 evi, ip46_address_t * remote);

int evpn_prefix_add (u32 table_id, fib_prefix_t * pfx,
		     ip46_address_t * remote, mac_address_t * router_mac);
int evpn_prefix_del (u32 table_id, fib_prefix_t * pfx);

int evpn_learn_enable (u8 enable);
void evpn_learn_sync (void);
void evpn_ensure_pools (void);

/* Anycast / SVI gateway protection (inferred; no dedicated CLI). */
const char *evpn_gw_src_str (evpn_gw_src_t src);
int evpn_gw_mac_is_protected (u32 evi, mac_address_t * mac);
int evpn_gw_ip_is_protected (u32 evi, ip46_address_t * ip, u8 is_ip6);
void evpn_gw_protect_mac (u32 evi, mac_address_t * mac, evpn_gw_src_t src,
			  u8 install_l2fib);
void evpn_gw_protect_ip (u32 evi, ip46_address_t * ip, u8 is_ip6,
			 u8 prefix_len, evpn_gw_src_t src);
void evpn_gw_unprotect_mac (u32 evi, mac_address_t * mac, evpn_gw_src_t src);
void evpn_gw_unprotect_ip (u32 evi, ip46_address_t * ip, u8 is_ip6,
			   evpn_gw_src_t src);
void evpn_gw_refresh_evi (evpn_evi_t * e);
void evpn_gw_refresh_all (void);
void evpn_gw_scan_macvlan (void);

/* Tunnel refcount helpers */
int evpn_tunnel_acquire (ip46_address_t * src, ip46_address_t * dst,
			 u32 vni, u8 is_ip6, u32 encap_fib_index, u16 dst_port,
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
u8 *format_evpn_gw_mac (u8 * s, va_list * args);
u8 *format_evpn_gw_ip (u8 * s, va_list * args);

void evpn_send_mac_learn_event (u32 evi, mac_address_t * mac, u32 sw_if_index,
				u8 is_add);
void evpn_send_prefix_learn_event (u32 table_id, fib_prefix_t * pfx,
				   mac_address_t * router_mac, u8 is_add);

#endif /* included_evpn_h */
