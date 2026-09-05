/*
 * Copyright (c) 2026
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * Local MAC / prefix origination, plus remote Type-5 from the kernel.
 *
 * Scans L2FIB on EVI bridge-domains for dynamically learned MACs (skip
 * static / VXLAN / BVI) and watches IRB interface addresses for Type-5
 * candidates (events via binary-API notifications).
 *
 * linux-cp ignores VRF / VXLAN / L3-VNI bridge objects. FRR still installs
 * imported Type-5 as BGP routes and router-MAC neighbours in that netns.
 * With learn enabled, dump those routes and call evpn_prefix_add.
 */
#define _GNU_SOURCE
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/l2/l2_fib.h>
#include <vnet/fib/fib_table.h>
#include <string.h>

#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>

#ifndef NDA_RTA
#define NDA_RTA(r) \
  ((struct rtattr *) (((char *) (r)) + NLMSG_ALIGN (sizeof (struct ndmsg))))
#endif

#include "evpn.h"

#ifndef RTPROT_BGP
#define RTPROT_BGP 186
#endif
#ifndef RTPROT_ZEBRA
#define RTPROT_ZEBRA 196
#endif

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
  EVPN_DBG ("learn mac %s evi %u mac %U sw_if %u", is_add ? "add" : "del",
	    evi, format_mac_address_t, mac, sw_if_index);
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
  EVPN_DBG ("learn prefix %s table %u %U rmac %U", is_add ? "add" : "del",
	    table_id, format_fib_prefix, pfx, format_mac_address_t,
	    router_mac);
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

static int
evpn_nl_open_dataplane (void)
{
  int oldfd, nsfd, sock;
  const char *paths[] = { "/run/netns/dataplane", "/var/run/netns/dataplane",
    0 };
  int i;

  oldfd = open ("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
  if (oldfd < 0)
    return -1;

  nsfd = -1;
  for (i = 0; paths[i]; i++)
    {
      nsfd = open (paths[i], O_RDONLY | O_CLOEXEC);
      if (nsfd >= 0)
	break;
    }
  if (nsfd >= 0)
    {
      if (setns (nsfd, CLONE_NEWNET) < 0)
	{
	  close (nsfd);
	  close (oldfd);
	  return -1;
	}
      close (nsfd);
    }

  sock = socket (AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (setns (oldfd, CLONE_NEWNET) < 0)
    {
      if (sock >= 0)
	close (sock);
      close (oldfd);
      return -1;
    }
  close (oldfd);
  return sock;
}

static int
evpn_nl_dump (int sock, u16 type, u8 family, u8 ** bufp)
{
  struct
  {
    struct nlmsghdr nh;
    struct rtgenmsg gen;
  } req;
  struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
  u8 *buf = 0;
  ssize_t n;
  int done = 0;

  memset (&req, 0, sizeof (req));
  req.nh.nlmsg_len = sizeof (req);
  req.nh.nlmsg_type = type;
  req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.nh.nlmsg_seq = 1;
  req.gen.rtgen_family = family;

  if (sendto (sock, &req, sizeof (req), 0, (struct sockaddr *) &nladdr,
	      sizeof (nladdr)) < 0)
    return -1;

  while (!done)
    {
      u8 chunk[8192];
      struct nlmsghdr *nh;

      n = recv (sock, chunk, sizeof (chunk), 0);
      if (n < 0)
	{
	  vec_free (buf);
	  return -1;
	}
      vec_add (buf, chunk, n);
      for (nh = (struct nlmsghdr *) chunk; NLMSG_OK (nh, (unsigned) n);
	   nh = NLMSG_NEXT (nh, n))
	{
	  if (nh->nlmsg_type == NLMSG_DONE)
	    done = 1;
	  if (nh->nlmsg_type == NLMSG_ERROR)
	    {
	      vec_free (buf);
	      return -1;
	    }
	}
    }
  *bufp = buf;
  return 0;
}

static void
evpn_nl_parse_attrs (struct rtattr *rta, int len, struct rtattr **tb,
		     int max)
{
  memset (tb, 0, sizeof (*tb) * (max + 1));
  for (; RTA_OK (rta, len); rta = RTA_NEXT (rta, len))
    {
      if (rta->rta_type <= max)
	tb[rta->rta_type] = rta;
    }
}

static uword *
evpn_kernel_neigh_macs (u8 * buf)
{
  uword *macs = 0;
  unsigned len = vec_len (buf);
  struct nlmsghdr *nh = (struct nlmsghdr *) buf;

  for (; NLMSG_OK (nh, len); nh = NLMSG_NEXT (nh, len))
    {
      struct ndmsg *ndm;
      struct rtattr *tb[NDA_MAX + 1];
      u32 ip;
      u8 *ll;
      u64 packed;

      if (nh->nlmsg_type != RTM_NEWNEIGH)
	continue;
      ndm = NLMSG_DATA (nh);
      if (ndm->ndm_family != AF_INET)
	continue;
      evpn_nl_parse_attrs (NDA_RTA (ndm),
			   nh->nlmsg_len - NLMSG_LENGTH (sizeof (*ndm)), tb,
			   NDA_MAX);
      if (!tb[NDA_DST] || !tb[NDA_LLADDR])
	continue;
      if (RTA_PAYLOAD (tb[NDA_DST]) < 4 || RTA_PAYLOAD (tb[NDA_LLADDR]) < 6)
	continue;
      ip = *(u32 *) RTA_DATA (tb[NDA_DST]);
      ll = RTA_DATA (tb[NDA_LLADDR]);
      packed = ((u64) ll[0] << 40) | ((u64) ll[1] << 32) | ((u64) ll[2] << 24) |
	((u64) ll[3] << 16) | ((u64) ll[4] << 8) | (u64) ll[5];
      hash_set (macs, ip, packed);
    }
  return macs;
}

static int
evpn_proto_is_control_plane (u8 proto)
{
  return proto == RTPROT_BGP || proto == RTPROT_ZEBRA;
}

static void
evpn_kernel_install_prefix (evpn_vrf_t * v, fib_prefix_t * pfx,
			    ip46_address_t * remote, mac_address_t * rmac,
			    u32 gen)
{
  evpn_main_t *em = &evpn_main;
  uword key, *p;
  evpn_prefix_t *pr;
  int rv;

  rv = evpn_prefix_add (v->table_id, pfx, remote, rmac);
  if (rv)
    {
      EVPN_DBG ("kernel prefix add table %u %U rv=%d", v->table_id,
		format_fib_prefix, pfx, rv);
      return;
    }
  key = v->table_id;
  key ^= pfx->fp_addr.ip4.as_u32 ^ ((uword) pfx->fp_len << 8);
  p = hash_get (em->prefix_by_key, key);
  if (!p)
    return;
  pr = pool_elt_at_index (em->prefixes, p[0]);
  pr->from_kernel = 1;
  pr->kernel_gen = gen;
}

static void
evpn_learn_scan_kernel_routes (void)
{
  evpn_main_t *em = &evpn_main;
  int sock;
  u8 *rbuf = 0, *nbuf = 0;
  uword *neigh = 0;
  u32 gen;
  struct nlmsghdr *nh;
  unsigned len;
  evpn_prefix_t *pr;
  u32 *to_del = 0;
  u32 i;

  if (pool_elts (em->vrfs) == 0)
    return;

  sock = evpn_nl_open_dataplane ();
  if (sock < 0)
    return;
  if (evpn_nl_dump (sock, RTM_GETNEIGH, AF_INET, &nbuf) ||
      evpn_nl_dump (sock, RTM_GETROUTE, AF_INET, &rbuf))
    {
      close (sock);
      vec_free (nbuf);
      vec_free (rbuf);
      return;
    }
  close (sock);

  gen = ++em->kernel_route_gen;
  neigh = evpn_kernel_neigh_macs (nbuf);
  vec_free (nbuf);

  len = vec_len (rbuf);
  nh = (struct nlmsghdr *) rbuf;
  for (; NLMSG_OK (nh, len); nh = NLMSG_NEXT (nh, len))
    {
      struct rtmsg *rtm;
      struct rtattr *tb[RTA_MAX + 1];
      u32 table, via, dst;
      u8 plen;
      uword *mp;
      evpn_vrf_t *v;
      uword *vp;
      fib_prefix_t pfx;
      ip46_address_t remote;
      mac_address_t rmac;
      u64 packed;

      if (nh->nlmsg_type != RTM_NEWROUTE)
	continue;
      rtm = NLMSG_DATA (nh);
      if (rtm->rtm_family != AF_INET || rtm->rtm_type != RTN_UNICAST)
	continue;
      if (!evpn_proto_is_control_plane (rtm->rtm_protocol))
	continue;
      evpn_nl_parse_attrs (RTM_RTA (rtm),
			   nh->nlmsg_len - NLMSG_LENGTH (sizeof (*rtm)), tb,
			   RTA_MAX);
      table = rtm->rtm_table;
      if (tb[RTA_TABLE])
	table = *(u32 *) RTA_DATA (tb[RTA_TABLE]);
      vp = hash_get (em->vrf_by_table, table);
      if (!vp)
	continue;
      v = pool_elt_at_index (em->vrfs, vp[0]);
      if (!tb[RTA_DST] || !tb[RTA_GATEWAY])
	continue;
      if (RTA_PAYLOAD (tb[RTA_DST]) < 4 || RTA_PAYLOAD (tb[RTA_GATEWAY]) < 4)
	continue;
      dst = *(u32 *) RTA_DATA (tb[RTA_DST]);
      via = *(u32 *) RTA_DATA (tb[RTA_GATEWAY]);
      plen = rtm->rtm_dst_len;
      if (em->have_default_local && !em->default_local_is_ip6 &&
	  via == em->default_local.ip4.as_u32)
	continue;
      /* Skip the L3-BVI host prefix. */
      if (plen >= 16 && (clib_net_to_host_u32 (dst) & 0xffff0000) == 0xa9fe0000)
	continue;
      mp = hash_get (neigh, via);
      if (!mp)
	continue;
      packed = mp[0];
      rmac.bytes[0] = (packed >> 40) & 0xff;
      rmac.bytes[1] = (packed >> 32) & 0xff;
      rmac.bytes[2] = (packed >> 24) & 0xff;
      rmac.bytes[3] = (packed >> 16) & 0xff;
      rmac.bytes[4] = (packed >> 8) & 0xff;
      rmac.bytes[5] = packed & 0xff;
      clib_memset (&remote, 0, sizeof (remote));
      remote.ip4.as_u32 = via;
      clib_memset (&pfx, 0, sizeof (pfx));
      pfx.fp_proto = FIB_PROTOCOL_IP4;
      pfx.fp_len = plen;
      pfx.fp_addr.ip4.as_u32 = dst;
      evpn_kernel_install_prefix (v, &pfx, &remote, &rmac, gen);
    }
  vec_free (rbuf);
  hash_free (neigh);

  pool_foreach (pr, em->prefixes)
  {
    if (pr->from_kernel && pr->kernel_gen != gen)
      vec_add1 (to_del, pr - em->prefixes);
  }
  for (i = 0; i < vec_len (to_del); i++)
    {
      pr = pool_elt_at_index (em->prefixes, to_del[i]);
      evpn_prefix_del (pr->table_id, &pr->prefix);
    }
  vec_free (to_del);
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
	pool_foreach (e, em->evis)
	{
	  evpn_learn_scan_evi (e);
	}
	evpn_learn_scan_kernel_routes ();
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
  EVPN_NOTICE ("learn %s", enable ? "enabled" : "disabled");

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
