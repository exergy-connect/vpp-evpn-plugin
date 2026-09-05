/*
 * Copyright (c) 2026
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * Local MAC / prefix origination, plus remote Type-5 from the kernel.
 *
 * Event-driven: VPP L2 MAC events, IPv4 address callbacks, and a long-lived
 * dataplane netlink socket. Full-table dumps run only on learn enable and
 * after netlink overrun (ENOBUFS).
 */
#define _GNU_SOURCE
#include <vppinfra/bihash_8_8.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/l2/l2_fib.h>
#include <vnet/l2/l2_input.h>
#include <vnet/fib/fib_table.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/l2/l2.api_enum.h>
#include <vnet/l2/l2.api_types.h>
#include <string.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
#include <linux/if_link.h>

#ifndef NDA_RTA
#define NDA_RTA(r) \
  ((struct rtattr *) (((char *) (r)) + NLMSG_ALIGN (sizeof (struct ndmsg))))
#endif
#ifndef IFLA_RTA
#define IFLA_RTA(r) \
  ((struct rtattr *) (((char *) (r)) + NLMSG_ALIGN (sizeof (struct ifinfomsg))))
#endif
#ifndef IFA_RTA
#define IFA_RTA(r) \
  ((struct rtattr *) (((char *) (r)) + NLMSG_ALIGN (sizeof (struct ifaddrmsg))))
#endif

#include "evpn.h"

#ifndef RTPROT_BGP
#define RTPROT_BGP 186
#endif
#ifndef RTPROT_ZEBRA
#define RTPROT_ZEBRA 196
#endif

/* l2_learn.h is not installed; match in-tree layout for client fields. */
typedef struct
{
  BVT (clib_bihash) * mac_table;
  u32 global_learn_count;
  u32 global_learn_limit;
  u32 bd_default_learn_limit;
  u32 client_pid;
  u32 client_index;
  u32 feat_next_node_index[32];
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} l2learn_main_t;

extern l2learn_main_t l2learn_main;
extern vlib_node_registration_t l2fib_mac_age_scanner_process_node;

typedef enum
{
  L2_MAC_AGE_PROCESS_EVENT_START = 1,
  L2_MAC_AGE_PROCESS_EVENT_STOP = 2,
  L2_MAC_AGE_PROCESS_EVENT_ONE_PASS = 3,
} l2_mac_age_process_event_t;

enum
{
  EVPN_LEARN_EVT_RECONCILE = 1,
};

/* Forward decls */
extern vlib_node_registration_t evpn_learn_process_node;
static void evpn_learn_reconcile (void);

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
evpn_handle_l2_mac_entry (vl_api_mac_entry_t * me)
{
  evpn_main_t *em = &evpn_main;
  u32 swi = ntohl (me->sw_if_index);
  u32 action = ntohl (me->action);
  l2_input_config_t *cfg;
  uword *ep;
  mac_address_t mac;
  u32 evi;

  if (swi == ~0 || swi >= vec_len (l2input_main.configs))
    return;
  cfg = l2input_intf_config (swi);
  if (!cfg || !l2_input_is_bridge (cfg))
    return;
  ep = hash_get (em->evi_by_bd, cfg->bd_index);
  if (!ep)
    return;
  evi = ep[0];

  if (action == MAC_EVENT_ACTION_API_DELETE)
    {
      mac_address_from_bytes (&mac, me->mac_addr);
      evpn_publish_mac_learn (evi, &mac, swi, 0);
      return;
    }

  if (evpn_sw_is_vxlan (swi) || evpn_sw_is_bvi (swi))
    return;

  mac_address_from_bytes (&mac, me->mac_addr);
  evpn_publish_mac_learn (evi, &mac, swi, 1);
}

static void
evpn_mac_evt_drain (void)
{
  evpn_main_t *em = &evpn_main;
  u16 expect_id;
  uword msg;

  if (!em->mac_evt_queue || !em->mac_evt_registered)
    return;

  expect_id = l2input_main.msg_id_base + VL_API_L2_MACS_EVENT;

  while (svm_queue_sub (em->mac_evt_queue, (u8 *) &msg, SVM_Q_NOWAIT, 0) == 0)
    {
      vl_api_l2_macs_event_t *mp = (vl_api_l2_macs_event_t *) msg;
      u32 n, i;

      if (!mp)
	continue;
      if (clib_net_to_host_u16 (mp->_vl_msg_id) != expect_id)
	{
	  vl_msg_api_free (mp);
	  continue;
	}
      n = ntohl (mp->n_macs);
      for (i = 0; i < n; i++)
	evpn_handle_l2_mac_entry (&mp->mac[i]);
      vl_msg_api_free (mp);
    }
}

static clib_error_t *
evpn_mac_evt_fd_read (clib_file_t * uf)
{
  evpn_main_t *em = &evpn_main;
  u64 unused;
  ssize_t n;

  n = read (em->mac_evt_fd, &unused, sizeof (unused));
  if (n < 0 && errno != EAGAIN)
    return clib_error_return_unix (0, "mac evtfd read");
  evpn_mac_evt_drain ();
  return 0;
}

static void
evpn_mac_events_disable (void)
{
  evpn_main_t *em = &evpn_main;
  l2learn_main_t *lm = &l2learn_main;

  if (em->mac_evt_registered && lm->client_pid == (u32) getpid ())
    {
      lm->client_pid = 0;
      lm->client_index = 0;
    }
  em->mac_evt_registered = 0;

  if (em->mac_evt_file_index != ~0)
    {
      clib_file_del_by_index (&file_main, em->mac_evt_file_index);
      em->mac_evt_file_index = ~0;
    }
  if (em->mac_evt_fd >= 0)
    {
      close (em->mac_evt_fd);
      em->mac_evt_fd = -1;
    }
  /* Leave memclnt registration; reclaiming is awkward mid-run. */
  em->mac_evt_queue = 0;
  em->mac_evt_client_index = ~0;
}

static int
evpn_mac_events_enable (void)
{
  evpn_main_t *em = &evpn_main;
  l2learn_main_t *lm = &l2learn_main;
  l2fib_main_t *fm = &l2fib_main;
  clib_file_t template = { 0 };
  void *oldheap;
  u32 pid = getpid ();

  if (em->mac_evt_registered)
    return 0;

  if (lm->client_pid != 0 && lm->client_pid != pid)
    {
      EVPN_WARN ("learn: L2 MAC events owned by pid %u; local MAC learn "
		 "uses reconcile dumps only", lm->client_pid);
      return -1;
    }

  em->mac_evt_fd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (em->mac_evt_fd < 0)
    {
      EVPN_ERR ("learn: eventfd failed: %d", errno);
      return -1;
    }

  oldheap = vl_msg_push_heap ();
  em->mac_evt_queue =
    svm_queue_alloc_and_init (256, sizeof (uword), pid);
  vl_msg_pop_heap (oldheap);
  if (!em->mac_evt_queue)
    {
      close (em->mac_evt_fd);
      em->mac_evt_fd = -1;
      return -1;
    }

  svm_queue_set_producer_event_fd (em->mac_evt_queue, em->mac_evt_fd);
  em->mac_evt_client_index =
    vl_api_memclnt_create_internal ("evpn-learn", em->mac_evt_queue);

  lm->client_pid = pid;
  lm->client_index = em->mac_evt_client_index;
  if (fm->event_scan_delay == 0.0)
    fm->event_scan_delay = 0.1;
  if (fm->max_macs_in_event == 0)
    fm->max_macs_in_event = 100;

  template.read_function = evpn_mac_evt_fd_read;
  template.file_descriptor = em->mac_evt_fd;
  template.description = format (0, "evpn-mac-events");
  em->mac_evt_file_index = clib_file_add (&file_main, &template);

  vlib_process_signal_event (em->vlib_main,
			     l2fib_mac_age_scanner_process_node.index,
			     L2_MAC_AGE_PROCESS_EVENT_ONE_PASS, 0);

  em->mac_evt_registered = 1;
  EVPN_DBG ("learn: subscribed to L2 MAC events");
  return 0;
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
  u8 is_evi_bvi = 0;
  ip46_address_t ip46;

  if (!em->learn_enabled)
    return;

  pool_foreach (e, em->evis)
  {
    if (e->bvi_sw_if_index == sw_if_index)
      {
	mac_address_copy (&rmac, &e->bvi_mac);
	found = 1;
	is_evi_bvi = 1;
	clib_memset (&ip46, 0, sizeof (ip46));
	ip46.ip4 = *address;
	if (is_del)
	  evpn_gw_unprotect_ip (e->evi, &ip46, 0, EVPN_GW_SRC_BVI);
	else
	  evpn_gw_protect_ip (e->evi, &ip46, 0, address_length,
			      EVPN_GW_SRC_BVI);
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

  /* Skip host-side GW VIP advertisement as Type-5 when it is the IRB anycast. */
  if (is_evi_bvi && is_del == 0)
    {
      /* Still publish learn for control plane; GW protect already done. */
    }

  pfx.fp_proto = FIB_PROTOCOL_IP4;
  pfx.fp_len = address_length;
  pfx.fp_addr.ip4 = *address;
  evpn_publish_prefix_learn (table_id, &pfx, &rmac, is_del ? 0 : 1);
}

static int
evpn_nl_open_dataplane_ex (u8 * entered_dataplane)
{
  int oldfd, nsfd, sock;
  const char *paths[] = { "/run/netns/dataplane", "/var/run/netns/dataplane",
    0 };
  int i;

  if (entered_dataplane)
    *entered_dataplane = 0;

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
      if (entered_dataplane)
	*entered_dataplane = 1;
    }

  sock = socket (AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
		 NETLINK_ROUTE);
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
evpn_nl_open_dataplane (void)
{
  return evpn_nl_open_dataplane_ex (0);
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
  evpn_main_t *em = &evpn_main;

  memset (&req, 0, sizeof (req));
  req.nh.nlmsg_len = sizeof (req);
  req.nh.nlmsg_type = type;
  req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.nh.nlmsg_seq = ++em->nl_seq;
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
	  if (errno == EAGAIN || errno == EWOULDBLOCK)
	    continue;
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

static void
evpn_kernel_neigh_set (u32 ip, const u8 * ll)
{
  evpn_main_t *em = &evpn_main;
  u64 packed;

  packed = ((u64) ll[0] << 40) | ((u64) ll[1] << 32) | ((u64) ll[2] << 24) |
    ((u64) ll[3] << 16) | ((u64) ll[4] << 8) | (u64) ll[5];
  hash_set (em->kernel_neigh, ip, packed);
}

static void
evpn_kernel_neigh_unset (u32 ip)
{
  hash_unset (evpn_main.kernel_neigh, ip);
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

typedef struct
{
  u32 ifindex;
  u32 parent;
  u8 is_macvlan;
  u8 mac[6];
  u8 have_mac;
  u8 name[64];
} evpn_nl_link_t;

static void
evpn_nl_parse_linkinfo (struct rtattr *rta, int len, u8 * is_macvlan)
{
  struct rtattr *tb[IFLA_INFO_MAX + 1];
  evpn_nl_parse_attrs (rta, len, tb, IFLA_INFO_MAX);
  if (tb[IFLA_INFO_KIND] && RTA_PAYLOAD (tb[IFLA_INFO_KIND]) >= 7 &&
      !strncmp ((char *) RTA_DATA (tb[IFLA_INFO_KIND]), "macvlan", 7))
    *is_macvlan = 1;
}

static evpn_nl_link_t *
evpn_nl_parse_links (u8 * buf)
{
  evpn_nl_link_t *links = 0;
  unsigned len = vec_len (buf);
  struct nlmsghdr *nh = (struct nlmsghdr *) buf;

  for (; NLMSG_OK (nh, len); nh = NLMSG_NEXT (nh, len))
    {
      struct ifinfomsg *ifi;
      struct rtattr *tb[IFLA_MAX + 1];
      evpn_nl_link_t *l;

      if (nh->nlmsg_type != RTM_NEWLINK)
	continue;
      ifi = NLMSG_DATA (nh);
      evpn_nl_parse_attrs (IFLA_RTA (ifi),
			   nh->nlmsg_len - NLMSG_LENGTH (sizeof (*ifi)), tb,
			   IFLA_MAX);
      vec_add2 (links, l, 1);
      clib_memset (l, 0, sizeof (*l));
      l->ifindex = ifi->ifi_index;
      if (tb[IFLA_ADDRESS] && RTA_PAYLOAD (tb[IFLA_ADDRESS]) >= 6)
	{
	  clib_memcpy (l->mac, RTA_DATA (tb[IFLA_ADDRESS]), 6);
	  l->have_mac = 1;
	}
      if (tb[IFLA_LINK] && RTA_PAYLOAD (tb[IFLA_LINK]) >= 4)
	l->parent = *(u32 *) RTA_DATA (tb[IFLA_LINK]);
      if (tb[IFLA_IFNAME] && RTA_PAYLOAD (tb[IFLA_IFNAME]) > 0)
	{
	  u32 nlen = RTA_PAYLOAD (tb[IFLA_IFNAME]);
	  if (nlen >= sizeof (l->name))
	    nlen = sizeof (l->name) - 1;
	  clib_memcpy (l->name, RTA_DATA (tb[IFLA_IFNAME]), nlen);
	  l->name[nlen] = 0;
	}
      if (tb[IFLA_LINKINFO])
	evpn_nl_parse_linkinfo (RTA_DATA (tb[IFLA_LINKINFO]),
				RTA_PAYLOAD (tb[IFLA_LINKINFO]),
				&l->is_macvlan);
    }
  return links;
}

static void
evpn_gw_protect_addrs_on_if (u32 evi, u32 ifindex, u8 * abuf,
			     evpn_gw_src_t src)
{
  unsigned len = vec_len (abuf);
  struct nlmsghdr *nh = (struct nlmsghdr *) abuf;

  for (; NLMSG_OK (nh, len); nh = NLMSG_NEXT (nh, len))
    {
      struct ifaddrmsg *ifa;
      struct rtattr *tb[IFA_MAX + 1];
      ip46_address_t ip46;

      if (nh->nlmsg_type != RTM_NEWADDR)
	continue;
      ifa = NLMSG_DATA (nh);
      if (ifa->ifa_index != ifindex)
	continue;
      if (ifa->ifa_family != AF_INET && ifa->ifa_family != AF_INET6)
	continue;
      evpn_nl_parse_attrs (IFA_RTA (ifa),
			   nh->nlmsg_len - NLMSG_LENGTH (sizeof (*ifa)), tb,
			   IFA_MAX);
      if (!tb[IFA_ADDRESS])
	continue;
      clib_memset (&ip46, 0, sizeof (ip46));
      if (ifa->ifa_family == AF_INET)
	{
	  if (RTA_PAYLOAD (tb[IFA_ADDRESS]) < 4)
	    continue;
	  ip46.ip4.as_u32 = *(u32 *) RTA_DATA (tb[IFA_ADDRESS]);
	  evpn_gw_protect_ip (evi, &ip46, 0, ifa->ifa_prefixlen, src);
	}
      else
	{
	  if (RTA_PAYLOAD (tb[IFA_ADDRESS]) < 16)
	    continue;
	  clib_memcpy (ip46.ip6.as_u8, RTA_DATA (tb[IFA_ADDRESS]), 16);
	  evpn_gw_protect_ip (evi, &ip46, 1, ifa->ifa_prefixlen, src);
	}
    }
}

void
evpn_gw_scan_macvlan (void)
{
  evpn_main_t *em = &evpn_main;
  int sock;
  u8 entered = 0;
  u8 *lbuf = 0, *abuf = 0;
  evpn_nl_link_t *links = 0;
  evpn_evi_t *e;
  u32 i, j;

  if (pool_elts (em->evis) == 0)
    return;

  sock = evpn_nl_open_dataplane_ex (&entered);
  if (sock < 0)
    {
      if (!em->gw_macvlan_skip_logged)
	{
	  EVPN_DBG ("gw macvlan skip reason no-dataplane-netns");
	  em->gw_macvlan_skip_logged = 1;
	}
      return;
    }
  if (!entered && !em->gw_macvlan_skip_logged)
    {
      EVPN_DBG ("gw macvlan scan using process netns (no dataplane ns)");
      em->gw_macvlan_skip_logged = 1;
    }

  if (evpn_nl_dump (sock, RTM_GETLINK, AF_UNSPEC, &lbuf) ||
      evpn_nl_dump (sock, RTM_GETADDR, AF_UNSPEC, &abuf))
    {
      close (sock);
      vec_free (lbuf);
      vec_free (abuf);
      return;
    }
  close (sock);

  links = evpn_nl_parse_links (lbuf);
  vec_free (lbuf);

  pool_foreach (e, em->evis)
  {
    u32 *parents = 0;

    if (!e->irb || e->bvi_sw_if_index == ~0)
      continue;

    for (i = 0; i < vec_len (links); i++)
      {
	if (!links[i].have_mac)
	  continue;
	if (memcmp (links[i].mac, e->bvi_mac.bytes, 6))
	  continue;
	vec_add1 (parents, links[i].ifindex);
      }

    if (vec_len (parents) == 0)
      continue;

    for (i = 0; i < vec_len (links); i++)
      {
	mac_address_t mac;
	u8 parent_ok = 0;

	if (!links[i].is_macvlan || !links[i].have_mac)
	  continue;
	for (j = 0; j < vec_len (parents); j++)
	  if (links[i].parent == parents[j])
	    {
	      parent_ok = 1;
	      break;
	    }
	if (!parent_ok)
	  continue;

	mac_address_from_bytes (&mac, links[i].mac);
	EVPN_DBG
	  ("gw evi %u protect mac %U src macvlan if %s parent ifindex %u",
	   e->evi, format_mac_address_t, &mac, links[i].name,
	   links[i].parent);
	evpn_gw_protect_mac (e->evi, &mac, EVPN_GW_SRC_MACVLAN, 1);
	evpn_gw_protect_addrs_on_if (e->evi, links[i].ifindex, abuf,
				     EVPN_GW_SRC_MACVLAN);
      }
    vec_free (parents);
  }

  vec_free (links);
  vec_free (abuf);
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

  sock = (em->nl_fd >= 0) ? em->nl_fd : evpn_nl_open_dataplane ();
  if (sock < 0)
    return;
  if (evpn_nl_dump (sock, RTM_GETNEIGH, AF_INET, &nbuf) ||
      evpn_nl_dump (sock, RTM_GETROUTE, AF_INET, &rbuf))
    {
      if (sock != em->nl_fd)
	close (sock);
      vec_free (nbuf);
      vec_free (rbuf);
      return;
    }
  if (sock != em->nl_fd)
    close (sock);

  gen = ++em->kernel_route_gen;
  neigh = evpn_kernel_neigh_macs (nbuf);
  vec_free (nbuf);

  /* Refresh live neigh cache from dump. */
  hash_free (em->kernel_neigh);
  em->kernel_neigh = neigh;
  neigh = 0;

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
      if (plen >= 16 && (clib_net_to_host_u32 (dst) & 0xffff0000) == 0xa9fe0000)
	continue;
      mp = hash_get (em->kernel_neigh, via);
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

static void
evpn_nl_handle_neigh (struct nlmsghdr *nh)
{
  struct ndmsg *ndm = NLMSG_DATA (nh);
  struct rtattr *tb[NDA_MAX + 1];
  u32 ip;
  u8 *ll;

  if (ndm->ndm_family != AF_INET)
    return;
  evpn_nl_parse_attrs (NDA_RTA (ndm),
		       nh->nlmsg_len - NLMSG_LENGTH (sizeof (*ndm)), tb,
		       NDA_MAX);
  if (!tb[NDA_DST] || RTA_PAYLOAD (tb[NDA_DST]) < 4)
    return;
  ip = *(u32 *) RTA_DATA (tb[NDA_DST]);
  if (nh->nlmsg_type == RTM_DELNEIGH)
    {
      evpn_kernel_neigh_unset (ip);
      return;
    }
  if (!tb[NDA_LLADDR] || RTA_PAYLOAD (tb[NDA_LLADDR]) < 6)
    return;
  ll = RTA_DATA (tb[NDA_LLADDR]);
  evpn_kernel_neigh_set (ip, ll);
}

static void
evpn_nl_handle_route (struct nlmsghdr *nh)
{
  evpn_main_t *em = &evpn_main;
  struct rtmsg *rtm = NLMSG_DATA (nh);
  struct rtattr *tb[RTA_MAX + 1];
  u32 table, via, dst;
  u8 plen;
  uword *mp, *vp;
  evpn_vrf_t *v;
  fib_prefix_t pfx;
  ip46_address_t remote;
  mac_address_t rmac;
  u64 packed;

  if (rtm->rtm_family != AF_INET || rtm->rtm_type != RTN_UNICAST)
    return;
  if (!evpn_proto_is_control_plane (rtm->rtm_protocol))
    return;
  evpn_nl_parse_attrs (RTM_RTA (rtm),
		       nh->nlmsg_len - NLMSG_LENGTH (sizeof (*rtm)), tb,
		       RTA_MAX);
  table = rtm->rtm_table;
  if (tb[RTA_TABLE])
    table = *(u32 *) RTA_DATA (tb[RTA_TABLE]);
  vp = hash_get (em->vrf_by_table, table);
  if (!vp)
    return;
  v = pool_elt_at_index (em->vrfs, vp[0]);

  clib_memset (&pfx, 0, sizeof (pfx));
  pfx.fp_proto = FIB_PROTOCOL_IP4;
  pfx.fp_len = rtm->rtm_dst_len;
  if (tb[RTA_DST] && RTA_PAYLOAD (tb[RTA_DST]) >= 4)
    pfx.fp_addr.ip4.as_u32 = *(u32 *) RTA_DATA (tb[RTA_DST]);

  if (nh->nlmsg_type == RTM_DELROUTE)
    {
      evpn_prefix_del (v->table_id, &pfx);
      return;
    }

  if (!tb[RTA_DST] || !tb[RTA_GATEWAY])
    return;
  if (RTA_PAYLOAD (tb[RTA_DST]) < 4 || RTA_PAYLOAD (tb[RTA_GATEWAY]) < 4)
    return;
  dst = *(u32 *) RTA_DATA (tb[RTA_DST]);
  via = *(u32 *) RTA_DATA (tb[RTA_GATEWAY]);
  plen = rtm->rtm_dst_len;
  if (em->have_default_local && !em->default_local_is_ip6 &&
      via == em->default_local.ip4.as_u32)
    return;
  if (plen >= 16 && (clib_net_to_host_u32 (dst) & 0xffff0000) == 0xa9fe0000)
    return;
  mp = hash_get (em->kernel_neigh, via);
  if (!mp)
    return;
  packed = mp[0];
  rmac.bytes[0] = (packed >> 40) & 0xff;
  rmac.bytes[1] = (packed >> 32) & 0xff;
  rmac.bytes[2] = (packed >> 24) & 0xff;
  rmac.bytes[3] = (packed >> 16) & 0xff;
  rmac.bytes[4] = (packed >> 8) & 0xff;
  rmac.bytes[5] = packed & 0xff;
  clib_memset (&remote, 0, sizeof (remote));
  remote.ip4.as_u32 = via;
  pfx.fp_len = plen;
  pfx.fp_addr.ip4.as_u32 = dst;
  evpn_kernel_install_prefix (v, &pfx, &remote, &rmac, em->kernel_route_gen);
}

static u64
evpn_pack_mac (const u8 * mac)
{
  return ((u64) mac[0] << 40) | ((u64) mac[1] << 32) | ((u64) mac[2] << 24) |
    ((u64) mac[3] << 16) | ((u64) mac[4] << 8) | (u64) mac[5];
}

static void
evpn_nl_handle_link (struct nlmsghdr *nh)
{
  evpn_main_t *em = &evpn_main;
  struct ifinfomsg *ifi = NLMSG_DATA (nh);
  struct rtattr *tb[IFLA_MAX + 1];
  u8 is_macvlan = 0;
  u8 mac[6];
  u8 have_mac = 0;
  u32 parent = 0;
  evpn_evi_t *e;
  mac_address_t m;
  char name[64];
  uword *pp;
  u64 parent_mac;

  evpn_nl_parse_attrs (IFLA_RTA (ifi),
		       nh->nlmsg_len - NLMSG_LENGTH (sizeof (*ifi)), tb,
		       IFLA_MAX);
  if (tb[IFLA_LINKINFO])
    evpn_nl_parse_linkinfo (RTA_DATA (tb[IFLA_LINKINFO]),
			    RTA_PAYLOAD (tb[IFLA_LINKINFO]), &is_macvlan);
  if (tb[IFLA_ADDRESS] && RTA_PAYLOAD (tb[IFLA_ADDRESS]) >= 6)
    {
      clib_memcpy (mac, RTA_DATA (tb[IFLA_ADDRESS]), 6);
      have_mac = 1;
    }
  if (tb[IFLA_LINK] && RTA_PAYLOAD (tb[IFLA_LINK]) >= 4)
    parent = *(u32 *) RTA_DATA (tb[IFLA_LINK]);
  name[0] = 0;
  if (tb[IFLA_IFNAME] && RTA_PAYLOAD (tb[IFLA_IFNAME]) > 0)
    {
      u32 nlen = RTA_PAYLOAD (tb[IFLA_IFNAME]);
      if (nlen >= sizeof (name))
	nlen = sizeof (name) - 1;
      clib_memcpy (name, RTA_DATA (tb[IFLA_IFNAME]), nlen);
      name[nlen] = 0;
    }

  if (nh->nlmsg_type == RTM_DELLINK)
    {
      if (have_mac && is_macvlan)
	{
	  mac_address_from_bytes (&m, mac);
	  pool_foreach (e, em->evis)
	  {
	    if (e->irb)
	      evpn_gw_unprotect_mac (e->evi, &m, EVPN_GW_SRC_MACVLAN);
	  }
	}
      hash_unset (em->nl_if_mac, ifi->ifi_index);
      hash_unset (em->nl_macvlan_parent, ifi->ifi_index);
      return;
    }

  if (have_mac)
    hash_set (em->nl_if_mac, ifi->ifi_index, evpn_pack_mac (mac));
  if (is_macvlan)
    hash_set (em->nl_macvlan_parent, ifi->ifi_index, parent);
  else
    hash_unset (em->nl_macvlan_parent, ifi->ifi_index);

  if (!is_macvlan || !have_mac)
    return;

  mac_address_from_bytes (&m, mac);
  pp = hash_get (em->nl_if_mac, parent);
  if (!pp)
    return;
  parent_mac = pp[0];

  pool_foreach (e, em->evis)
  {
    u64 bvi_packed;

    if (!e->irb || e->bvi_sw_if_index == ~0)
      continue;
    bvi_packed = evpn_pack_mac (e->bvi_mac.bytes);
    if (bvi_packed != parent_mac)
      continue;
    EVPN_DBG ("gw evi %u protect mac %U src macvlan if %s parent ifindex %u",
	      e->evi, format_mac_address_t, &m, name, parent);
    evpn_gw_protect_mac (e->evi, &m, EVPN_GW_SRC_MACVLAN, 1);
  }
}

static void
evpn_nl_handle_addr (struct nlmsghdr *nh)
{
  evpn_main_t *em = &evpn_main;
  struct ifaddrmsg *ifa = NLMSG_DATA (nh);
  struct rtattr *tb[IFA_MAX + 1];
  ip46_address_t ip46;
  evpn_evi_t *e;
  u8 is_ip6;
  uword *pp, *pm;
  u32 parent;
  u64 parent_mac;

  if (ifa->ifa_family != AF_INET && ifa->ifa_family != AF_INET6)
    return;
  pp = hash_get (em->nl_macvlan_parent, ifa->ifa_index);
  if (!pp)
    return;
  parent = pp[0];
  pm = hash_get (em->nl_if_mac, parent);
  if (!pm)
    return;
  parent_mac = pm[0];

  evpn_nl_parse_attrs (IFA_RTA (ifa),
		       nh->nlmsg_len - NLMSG_LENGTH (sizeof (*ifa)), tb,
		       IFA_MAX);
  if (!tb[IFA_ADDRESS])
    return;
  clib_memset (&ip46, 0, sizeof (ip46));
  is_ip6 = (ifa->ifa_family == AF_INET6);
  if (!is_ip6)
    {
      if (RTA_PAYLOAD (tb[IFA_ADDRESS]) < 4)
	return;
      ip46.ip4.as_u32 = *(u32 *) RTA_DATA (tb[IFA_ADDRESS]);
    }
  else
    {
      if (RTA_PAYLOAD (tb[IFA_ADDRESS]) < 16)
	return;
      clib_memcpy (ip46.ip6.as_u8, RTA_DATA (tb[IFA_ADDRESS]), 16);
    }

  pool_foreach (e, em->evis)
  {
    if (!e->irb || e->bvi_sw_if_index == ~0)
      continue;
    if (evpn_pack_mac (e->bvi_mac.bytes) != parent_mac)
      continue;
    if (nh->nlmsg_type == RTM_DELADDR)
      evpn_gw_unprotect_ip (e->evi, &ip46, is_ip6, EVPN_GW_SRC_MACVLAN);
    else
      evpn_gw_protect_ip (e->evi, &ip46, is_ip6, ifa->ifa_prefixlen,
			  EVPN_GW_SRC_MACVLAN);
  }
}

static void
evpn_nl_process_msg (struct nlmsghdr *nh)
{
  switch (nh->nlmsg_type)
    {
    case RTM_NEWNEIGH:
    case RTM_DELNEIGH:
      evpn_nl_handle_neigh (nh);
      break;
    case RTM_NEWROUTE:
    case RTM_DELROUTE:
      evpn_nl_handle_route (nh);
      break;
    case RTM_NEWLINK:
    case RTM_DELLINK:
      evpn_nl_handle_link (nh);
      break;
    case RTM_NEWADDR:
    case RTM_DELADDR:
      evpn_nl_handle_addr (nh);
      break;
    default:
      break;
    }
}

static clib_error_t *
evpn_nl_fd_read (clib_file_t * uf)
{
  evpn_main_t *em = &evpn_main;
  u8 chunk[8192];
  ssize_t n;
  struct nlmsghdr *nh;

  if (!em->learn_enabled || em->nl_fd < 0)
    return 0;

  while (1)
    {
      n = recv (em->nl_fd, chunk, sizeof (chunk), 0);
      if (n < 0)
	{
	  if (errno == EAGAIN || errno == EWOULDBLOCK)
	    break;
	  if (errno == ENOBUFS)
	    {
	      EVPN_WARN ("learn: netlink overrun; reconciling");
	      vlib_process_signal_event (em->vlib_main,
					evpn_learn_process_node.index,
					EVPN_LEARN_EVT_RECONCILE, 0);
	      break;
	    }
	  return clib_error_return_unix (0, "netlink recv");
	}
      if (n == 0)
	break;
      for (nh = (struct nlmsghdr *) chunk; NLMSG_OK (nh, (unsigned) n);
	   nh = NLMSG_NEXT (nh, n))
	{
	  if (nh->nlmsg_type == NLMSG_ERROR)
	    {
	      struct nlmsgerr *err = NLMSG_DATA (nh);
	      if (err->error)
		EVPN_DBG ("learn: netlink err %d", err->error);
	      continue;
	    }
	  evpn_nl_process_msg (nh);
	}
    }
  return 0;
}

static void
evpn_nl_socket_close (void)
{
  evpn_main_t *em = &evpn_main;

  if (em->nl_file_index != ~0)
    {
      clib_file_del_by_index (&file_main, em->nl_file_index);
      em->nl_file_index = ~0;
    }
  if (em->nl_fd >= 0)
    {
      close (em->nl_fd);
      em->nl_fd = -1;
    }
}

static int
evpn_nl_socket_open (void)
{
  evpn_main_t *em = &evpn_main;
  struct sockaddr_nl sa;
  clib_file_t template = { 0 };
  u8 entered = 0;
  int sock;
  int groups;

  if (em->nl_fd >= 0)
    return 0;

  sock = evpn_nl_open_dataplane_ex (&entered);
  if (sock < 0)
    {
      EVPN_WARN ("learn: cannot open dataplane netlink socket");
      return -1;
    }

  groups = RTMGRP_IPV4_ROUTE | RTMGRP_NEIGH | RTMGRP_LINK | RTMGRP_IPV4_IFADDR;
  clib_memset (&sa, 0, sizeof (sa));
  sa.nl_family = AF_NETLINK;
  sa.nl_groups = groups;
  if (bind (sock, (struct sockaddr *) &sa, sizeof (sa)) < 0)
    {
      EVPN_ERR ("learn: netlink bind failed: %d", errno);
      close (sock);
      return -1;
    }

  /* Enlarge receive buffer to reduce ENOBUFS under churn. */
  {
    int rcv = 1 << 20;
    setsockopt (sock, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof (rcv));
  }

  em->nl_fd = sock;
  template.read_function = evpn_nl_fd_read;
  template.file_descriptor = sock;
  template.flags = UNIX_FILE_EVENT_EDGE_TRIGGERED;
  template.description = format (0, "evpn-netlink");
  em->nl_file_index = clib_file_add (&file_main, &template);

  if (!entered)
    EVPN_DBG ("learn: netlink using process netns");
  else
    EVPN_DBG ("learn: netlink bound in dataplane netns");
  return 0;
}

static void
evpn_learn_reconcile (void)
{
  evpn_main_t *em = &evpn_main;
  evpn_evi_t *e;

  if (!em->learn_enabled)
    return;

  EVPN_DBG ("learn: reconcile");
  pool_foreach (e, em->evis)
  {
    evpn_learn_scan_evi (e);
  }
  evpn_gw_refresh_all ();
  evpn_learn_scan_kernel_routes ();
}

void
evpn_learn_sync (void)
{
  /* Synchronous reconcile for CLI/tests; ENOBUFS still signals the process. */
  evpn_learn_reconcile ();
}

static uword
evpn_learn_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
		    vlib_frame_t * f)
{
  uword event_type, *event_data = 0;

  while (1)
    {
      vlib_process_wait_for_event (vm);
      event_type = vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      if (event_type == EVPN_LEARN_EVT_RECONCILE)
	evpn_learn_reconcile ();
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

  if (enable == em->learn_enabled && enable)
    {
      /* Re-enable while already on: treat as sync (tests / recovery). */
      vlib_process_signal_event (em->vlib_main, evpn_learn_process_node.index,
				 EVPN_LEARN_EVT_RECONCILE, 0);
      return 0;
    }

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
    {
      evpn_ensure_pools ();
      evpn_mac_events_enable ();
      evpn_nl_socket_open ();
      vlib_process_signal_event (em->vlib_main, evpn_learn_process_node.index,
				 EVPN_LEARN_EVT_RECONCILE, 0);
    }
  else
    {
      evpn_nl_socket_close ();
      evpn_mac_events_disable ();
    }

  return 0;
}
