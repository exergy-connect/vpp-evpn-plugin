/* SPDX-License-Identifier: Apache-2.0
 * Event-driven Zebra dataplane connection inside the existing VPP plugin.
 * File callbacks wake a VLIB process; all FDB and port changes execute there.
 * Only disconnected transports have a retry timer. Connected operation waits
 * exclusively for socket, local MAC, and service configuration events.
 */
#define _GNU_SOURCE
#include "evpn.h"
#include "evpn_srv6_wire.h"
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <net/if.h>
#include <vlib/file.h>
#include <vnet/bonding/node.h>
#include <vnet/feature/feature.h>
#include <vnet/l2/l2_output.h>
#include <vlib/unix/unix.h>

static int zebra_fd = -1;
static u32 zebra_file = ~0;
static u8 enabled, ready, reset_requested, in_snapshot;
static u8 *netns_path, *output;
static uword output_used, input_used;
static struct evpn_srv6_msg input;
static f64 retry_delay = 0.25;
extern vlib_node_registration_t evpn_zebra_process_node;

enum
{
  ZEBRA_IO = 1,
  ZEBRA_RESET,
  ZEBRA_ES
};

static void
wake (uword event)
{
  vlib_process_signal_event (evpn_main.vlib_main, evpn_zebra_process_node.index, event, 0);
}

static evpn_evi_t *
evi_for_vni (u32 vni)
{
  evpn_evi_t *e;
  pool_foreach (e, evpn_main.evis)
    if (e->vni == vni && evpn_srv6_service_exists (e->evi))
      return e;
  return 0;
}

static void
flush_remote (void)
{
  vlib_worker_thread_barrier_sync (evpn_main.vlib_main);
  evpn_evi_t *e;
  pool_foreach (e, evpn_main.evis)
    if (evpn_srv6_service_exists (e->evi))
      evpn_srv6_flush (e->evi);
  evpn_srv6_local_sid_reset ();
  evpn_srv6_control_reset ();
  vlib_worker_thread_barrier_release (evpn_main.vlib_main);
}

static void mh_reset (void);

static void
disconnect_zebra (void)
{
  ready = in_snapshot = 0;
  if (zebra_file != ~0)
    {
      /* clib_file_del closes the descriptor. */
      clib_file_del_by_index (&file_main, zebra_file);
      zebra_file = ~0;
    }
  else if (zebra_fd >= 0)
    close (zebra_fd);
  zebra_fd = -1;
  input_used = output_used = 0;
  vec_reset_length (output);
  mh_reset ();
  flush_remote ();
}

void
evpn_zebra_resync (void)
{
  if (enabled)
    {
      ready = 0;
      reset_requested = 1;
      wake (ZEBRA_RESET);
    }
}

/* Local attachments and learned MAC ownership survive control reconnects. */
typedef struct
{
  u32 evi, sw_if_index, linux_if_index;
  u8 esi[10], sent, oper_up, df;
  ip6_address_t *peers;
  u16 df_pref;
  ip6_address_t source;
} evpn_local_es_t;
static evpn_local_es_t *local_es;
typedef struct
{
  u32 evi, sw_if_index;
  mac_address_t mac;
} evpn_local_mac_t;
static evpn_local_mac_t *local_macs;

static u32
linux_index (const char *name)
{
  int original = -1, target = -1;
  u32 index = 0;
  if (netns_path)
    {
      original = open ("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
      target = open ((char *) netns_path, O_RDONLY | O_CLOEXEC);
      if (original < 0 || target < 0 || setns (target, CLONE_NEWNET) < 0)
	goto done;
    }
  index = if_nametoindex (name);
  if (target >= 0 && setns (original, CLONE_NEWNET) < 0)
    clib_panic ("EVPN cannot restore network namespace");
done:
  if (target >= 0)
    close (target);
  if (original >= 0)
    close (original);
  return index;
}
static u32
linux_for_vpp (u32 swi)
{
  /* Linux models a tagged VPP attachment as VLAN membership on its parent. */
  vnet_sw_interface_t *sw = vnet_get_sw_interface (evpn_main.vnet_main, swi);
  swi = sw->sup_sw_if_index;
  u8 *name = format (0, "%U%c", format_vnet_sw_if_index_name, evpn_main.vnet_main, swi, 0);
  const char *n = (char *) name;
  if (!strncmp (n, "host-", 5))
    n += 5;
  u32 index = linux_index (n);
  vec_free (name);
  return index;
}
static u32
vpp_for_linux (u32 index, u32 bd_index)
{
  if (!index)
    return ~0;
  vnet_sw_interface_t *sw;
  pool_foreach (sw, evpn_main.vnet_main->interface_main.sw_interfaces)
    if (linux_for_vpp (sw->sw_if_index) == index)
      {
        l2_input_config_t *l2 = l2input_intf_config (sw->sw_if_index);
        if ((l2->flags & L2_INPUT_FLAG_BRIDGE) && l2->bd_index == bd_index)
          return sw->sw_if_index;
      }
  return ~0;
}

static u8 es_oper_up (evpn_local_es_t *es);
static const char *mh_arcs[] = { "l2-output-ip4", "l2-output-ip6", "l2-output-nonip" };
static void
mh_feature_one (u32 swi, u8 enable)
{
  for (u32 i = 0; i < ARRAY_LEN (mh_arcs); i++)
    vnet_feature_enable_disable (mh_arcs[i], "evpn-mh-output", swi, enable, 0, 0);
  u8 features = 0;
  for (u32 i = 0; i < ARRAY_LEN (mh_arcs); i++)
    features |= vnet_have_features (vnet_get_feature_arc_index (mh_arcs[i]), swi);
  l2output_intf_bitmap_enable (swi, L2OUTPUT_FEAT_OUTPUT_FEAT_ARC, features);
}
/* Bonds may carry VLAN subinterfaces; filtering belongs on each L2 egress. */
static void
mh_feature (u32 swi, u8 enable)
{
  if (!enable)
    {
      evpn_local_es_t *es;
      u32 refs = 0;
      vec_foreach (es, local_es)
	if (es->sw_if_index == swi)
	  refs++;
      if (refs > 1)
	return;
    }
  vnet_sw_interface_t *sw;
  pool_foreach (sw, evpn_main.vnet_main->interface_main.sw_interfaces)
    if (sw->sw_if_index == swi || sw->sup_sw_if_index == swi)
      mh_feature_one (sw->sw_if_index, enable);
}
static void
mh_reset (void)
{
  vlib_worker_thread_barrier_sync (evpn_main.vlib_main);
  evpn_local_es_t *es;
  vec_foreach (es, local_es)
    {
      es->df = 0;
      vec_reset_length (es->peers);
    }
  vlib_worker_thread_barrier_release (evpn_main.vlib_main);
}
static int
mh_update (const struct evpn_srv6_msg *m)
{
  if ((m->op == EVPN_SRV6_DF && m->flags != 0 && m->flags != 1 && m->flags != 2) ||
      (m->op == EVPN_SRV6_PEER && (!m->add || m->flags)))
    return -1;
  evpn_local_es_t *es;
  vlib_worker_thread_barrier_sync (evpn_main.vlib_main);
  vec_foreach (es, local_es)
    if (es->linux_if_index == clib_net_to_host_u32 (m->sw_if_index))
      {
	if (m->op == EVPN_SRV6_DF)
	  {
	    es->df = (m->flags & 1) && es_oper_up (es);
	    if (m->flags & 2)
	      vec_reset_length (es->peers);
	  }
	else
	  {
	    ip6_address_t peer;
	    clib_memcpy (&peer, m->sid, 16);
	    if (ip6_address_is_zero (&peer) || ip6_address_is_multicast (&peer))
	      {
		vlib_worker_thread_barrier_release (evpn_main.vlib_main);
		return -1;
	      }
	    uword j;
	    vec_foreach_index (j, es->peers)
	      if (!memcmp (&es->peers[j], &peer, 16))
		break;
	    if (j >= 4096)
	      {
		vlib_worker_thread_barrier_release (evpn_main.vlib_main);
		return -1;
	      }
	    if (j == vec_len (es->peers))
	      vec_add1 (es->peers, peer);
	  }
      }
  vlib_worker_thread_barrier_release (evpn_main.vlib_main);
  return 0;
}

static void
queue_local (struct evpn_srv6_msg *message)
{
  if (!ready)
    return;
  if (vec_len (output) - output_used + sizeof (*message) > EVPN_SRV6_QUEUE_LIMIT)
    {
      EVPN_WARN ("ZEBRA local state queue overflow; reconnecting for replay");
      evpn_zebra_resync ();
      return;
    }
  if (output_used)
    {
      vec_delete (output, output_used, 0);
      output_used = 0;
    }
  vec_add (output, (u8 *) message, sizeof (*message));
  wake (ZEBRA_IO);
}

static evpn_local_es_t *
es_for_interface (u32 evi, u32 sw_if_index)
{
  evpn_local_es_t *es;
  vnet_sw_interface_t *sw = vnet_get_sw_interface (evpn_main.vnet_main, sw_if_index);
  vec_foreach (es, local_es)
    if (es->evi == evi &&
	(es->sw_if_index == sw_if_index || es->sw_if_index == sw->sup_sw_if_index))
      return es;
  return 0;
}

static u8
es_oper_up (evpn_local_es_t *es)
{
  vnet_main_t *vnm = evpn_main.vnet_main;
  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, es->sw_if_index);
  return vnet_sw_interface_is_admin_up (vnm, es->sw_if_index) &&
	 (hw->flags & VNET_HW_INTERFACE_FLAG_LINK_UP) != 0;
}

static void
send_es (evpn_local_es_t *es, u8 add)
{
  evpn_evi_t *e;
  uword *index = hash_get (evpn_main.evi_by_id, es->evi);
  if (!index || !evpn_srv6_service_exists (es->evi))
    return;
  e = pool_elt_at_index (evpn_main.evis, index[0]);
  es->linux_if_index = linux_for_vpp (es->sw_if_index);
  if (!es->linux_if_index)
    return;
  struct evpn_srv6_msg message = {
    .magic = clib_host_to_net_u32 (EVPN_SRV6_MAGIC),
    .version = EVPN_SRV6_VERSION,
    .op = EVPN_SRV6_ES,
    .type = 4,
    .add = add,
    .vni = clib_host_to_net_u32 (e->vni),
    .sw_if_index = clib_host_to_net_u32 (es->linux_if_index),
    .df_pref = clib_host_to_net_u16 (es->df_pref),
    .flags = es->oper_up ? EVPN_SRV6_ES_OPER_UP : 0,
  };
  clib_memcpy (message.esi, es->esi, 10);
  clib_memcpy (message.sid, &es->source, 16);
  queue_local (&message);
}

static void
send_mac (evpn_local_mac_t *local, u8 add)
{
  uword *index = hash_get (evpn_main.evi_by_id, local->evi);
  if (!index || !evpn_srv6_service_exists (local->evi))
    return;
  evpn_evi_t *e = pool_elt_at_index (evpn_main.evis, index[0]);
  evpn_local_es_t *es = es_for_interface (local->evi, local->sw_if_index);
  if (add && es && !es_oper_up (es))
    return;
  struct evpn_srv6_msg message = {
    .magic = clib_host_to_net_u32 (EVPN_SRV6_MAGIC),
    .version = EVPN_SRV6_VERSION,
    .op = EVPN_SRV6_LOCAL,
    .type = 2,
    .add = add,
    .vni = clib_host_to_net_u32 (e->vni),
    .sw_if_index = clib_host_to_net_u32 (linux_for_vpp (local->sw_if_index)),
  };
  clib_memcpy (message.key, local->mac.bytes, 6);
  if (es)
    clib_memcpy (message.esi, es->esi, 10);
  queue_local (&message);
}

void
evpn_zebra_mac (u32 evi, mac_address_t *mac, u32 sw_if_index, u8 add)
{
  uword i;
  vec_foreach_index (i, local_macs)
    if (local_macs[i].evi == evi && !memcmp (&local_macs[i].mac, mac, 6))
      break;
  if (add)
    {
      if (i == vec_len (local_macs))
	{
	  evpn_local_mac_t entry = { .evi = evi, .mac = *mac };
	  vec_add1 (local_macs, entry);
	}
      local_macs[i].sw_if_index = sw_if_index;
      send_mac (&local_macs[i], 1);
    }
  else if (i < vec_len (local_macs) && local_macs[i].sw_if_index == sw_if_index)
    {
      send_mac (&local_macs[i], 0);
      vec_del1 (local_macs, i);
    }
}

static void
reconcile_es (u8 replay)
{
  evpn_local_es_t *es;
  vec_foreach (es, local_es)
    {
      u8 up = es_oper_up (es);
      if (replay || !es->sent || es->oper_up != up)
	{
	  if (!up)
	    es->df = 0;
	  es->oper_up = up;
	  /* Withdraw attached MACs before withdrawing ES reachability. */
	  if (!up && !replay)
	    {
	      evpn_local_mac_t *mac;
	      vec_foreach (mac, local_macs)
		if (es_for_interface (mac->evi, mac->sw_if_index) == es)
		  send_mac (mac, 0);
	    }
	  send_es (es, 1);
	  es->sent = ready;
	  if (up && !replay)
	    evpn_learn_replay ();
	}
    }
}

static clib_error_t *
es_sw_state (vnet_main_t *vnm, u32 sw_if_index, u32 flags)
{
  if (vec_len (local_es))
    wake (ZEBRA_ES);
  return 0;
}
VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (es_sw_state);
static clib_error_t *
es_hw_state (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  if (vec_len (local_es))
    wake (ZEBRA_ES);
  return 0;
}
VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION (es_hw_state);

/* Interface removal must not leave an ES pointing at a recycled index. */
static clib_error_t *
es_interface_add_del (vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  if (is_add)
    {
      vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, sw_if_index);
      evpn_local_es_t *es;
      vec_foreach (es, local_es)
	if (es->sw_if_index == sw->sup_sw_if_index)
	  {
	    mh_feature_one (sw_if_index, 1);
	    break;
	  }
      return 0;
    }
  uword i = 0;
  while (i < vec_len (local_macs))
    {
      evpn_local_mac_t copy = local_macs[i];
      evpn_local_es_t *es = es_for_interface (copy.evi, copy.sw_if_index);
      if (copy.sw_if_index == sw_if_index || (es && es->sw_if_index == sw_if_index))
	evpn_publish_mac_learn (copy.evi, &copy.mac, copy.sw_if_index, 0);
      else
	i++;
    }
  i = 0;
  while (i < vec_len (local_es))
    {
      if (local_es[i].sw_if_index == sw_if_index)
	{
	  send_es (&local_es[i], 0);
	  mh_feature (local_es[i].sw_if_index, 0);
	  vec_free (local_es[i].peers);
	  vec_del1 (local_es, i);
	}
      else
	i++;
    }

  return 0;
}
VNET_SW_INTERFACE_ADD_DEL_FUNCTION (es_interface_add_del);

static clib_error_t *
es_command (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  evpn_local_es_t config = { .evi = ~0, .sw_if_index = ~0, .df_pref = 32767 };
  u8 add = 0, have_esi = 0, have_source = 0;
  u32 bytes[10], pref;
  if (unformat (input, "add"))
    add = 1;
  else if (!unformat (input, "del"))
    return clib_error_return (0, "add|del required");
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "evi %u", &config.evi))
	;
      else if (unformat (input, "interface %U", unformat_vnet_sw_interface, evpn_main.vnet_main,
			 &config.sw_if_index))
	;
      else if (unformat (input, "source %U", unformat_ip6_address, &config.source))
	have_source = 1;
      else if (unformat (input, "df-pref %u", &pref) && pref <= 65535)
	config.df_pref = pref;
      else if (unformat (input, "esi %x:%x:%x:%x:%x:%x:%x:%x:%x:%x", &bytes[0], &bytes[1],
			 &bytes[2], &bytes[3], &bytes[4], &bytes[5], &bytes[6], &bytes[7],
			 &bytes[8], &bytes[9]))
	{
	  for (u32 j = 0; j < 10; j++)
	    {
	      if (bytes[j] > 255)
		return clib_error_return (0, "ESI byte out of range");
	      config.esi[j] = bytes[j];
	    }
	  have_esi = 1;
	}
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }
  if (config.evi == ~0 || config.sw_if_index == ~0)
    return clib_error_return (0, "evi and interface required");
  if (add &&
      (!have_esi || !memcmp (config.esi, (u8[10]) { 0 }, 10) || !have_source ||
       ip6_address_is_zero (&config.source) || ip6_address_is_multicast (&config.source) ||
       !hash_get (evpn_main.evi_by_id, config.evi) || !evpn_srv6_service_exists (config.evi)))
    return clib_error_return (0, "native EVI, nonzero ESI and unicast source required");
  evpn_local_es_t *other;
  if (add)
    vec_foreach (other, local_es)
      {
	if (other->evi == config.evi && other->sw_if_index == config.sw_if_index)
	  continue; /* Replacement validated below and replayed atomically. */
	if ((!memcmp (other->esi, config.esi, 10) && other->sw_if_index != config.sw_if_index) ||
	    (other->sw_if_index == config.sw_if_index &&
	     (memcmp (other->esi, config.esi, 10) || memcmp (&other->source, &config.source, 16) ||
	      other->df_pref != config.df_pref)))
	  return clib_error_return (
	    0, "an ES must use one attachment, source and DF preference across EVIs");
      }
  uword i;
  vec_foreach_index (i, local_es)
    if (local_es[i].evi == config.evi && local_es[i].sw_if_index == config.sw_if_index)
      break;
  if (i < vec_len (local_es))
    {
      evpn_local_mac_t *mac;
      vec_foreach (mac, local_macs)
	if (es_for_interface (mac->evi, mac->sw_if_index) == &local_es[i])
	  send_mac (mac, 0);
      send_es (&local_es[i], 0);
      vec_free (local_es[i].peers);
      vec_del1 (local_es, i);
      u8 shared = 0;
      vec_foreach (other, local_es)
        if (other->sw_if_index == config.sw_if_index)
          shared = 1;
      mh_feature (config.sw_if_index, shared);
    }
  if (add)
    {
      vec_add1 (local_es, config);
      mh_feature (config.sw_if_index, 1);
    }
  reconcile_es (0);
  evpn_learn_replay ();
  return 0;
}
VLIB_CLI_COMMAND (evpn_es_command, static) = {
  .path = "evpn es",
  .function = es_command,
  .short_help =
    "evpn es add|del evi <id> interface <name> [esi <10 octets> source <IPv6> df-pref <0..65535>]",
};

static u8 *
format_local_esi (u8 *s, va_list *args)
{
  u8 *esi = va_arg (*args, u8 *);
  for (u32 i = 0; i < 10; i++)
    s = format (s, "%s%02x", i ? ":" : "", esi[i]);
  return s;
}

static clib_error_t *
show_es (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  evpn_local_es_t *es;
  vec_foreach (es, local_es)
    vlib_cli_output (vm, "EVI %u interface %U ESI %U source %U df-pref %u %s DF %s peers %u",
		     es->evi, format_vnet_sw_if_index_name, evpn_main.vnet_main, es->sw_if_index,
		     format_local_esi, es->esi, format_ip6_address, &es->source, es->df_pref,
		     es_oper_up (es) ? "up" : "down", es->df ? "yes" : "no", vec_len (es->peers));
  return 0;
}
VLIB_CLI_COMMAND (show_evpn_es_command, static) = {
  .path = "show evpn es",
  .function = show_es,
  .short_help = "show evpn es",
};

static int
write_pending (void)
{
  while (output_used < vec_len (output))
    {
      ssize_t n =
	send (zebra_fd, output + output_used, vec_len (output) - output_used, MSG_NOSIGNAL);
      if (n < 0)
	{
	  if (errno == EINTR)
	    continue;
	  if (errno == EAGAIN || errno == EWOULDBLOCK)
	    {
	      clib_file_set_data_available_to_write (&file_main, zebra_file, 1);
	      return 0;
	    }
	  return -1;
	}
      if (!n)
	return -1;
      output_used += n;
    }
  output_used = 0;
  vec_reset_length (output);
  clib_file_set_data_available_to_write (&file_main, zebra_file, 0);
  return 0;
}

static void
send_services (void)
{
  evpn_evi_t *e;
  pool_foreach (e, evpn_main.evis)
    if (evpn_srv6_service_exists (e->evi))
      {
	u8 *name = format (0, "vxlan%u%c", e->vni, 0);
	u32 index = linux_index ((char *) name);
	vec_free (name);
	if (!index)
	  {
	    EVPN_WARN ("Missing Linux VXLAN metadata for VNI %u", e->vni);
	    continue;
	  }
	struct evpn_srv6_msg m = {
	  .magic = clib_host_to_net_u32 (EVPN_SRV6_MAGIC),
	  .version = EVPN_SRV6_VERSION,
	  .op = EVPN_SRV6_SERVICE,
	  .add = 1,
	  .vni = clib_host_to_net_u32 (e->vni),
	  .sw_if_index = clib_host_to_net_u32 (index),
	};
	queue_local (&m);
      }
}
static int
route_update (const struct evpn_srv6_msg *m)
{
  evpn_evi_t *e = evi_for_vni (clib_net_to_host_u32 (m->vni));
  if (!e)
    return 0;
  ip6_address_t sid, peer;
  mac_address_t mac;
  clib_memcpy (&sid, m->sid, 16);
  clib_memcpy (&peer, m->key, 16);
  mac_address_from_bytes (&mac, m->key);
  if (m->type == 3)
    return evpn_srv6_vtep (e->evi, &peer, &sid, m->add);
  if (m->type != 2 || m->flags > 2)
    return -1;
  if (!m->add)
    return evpn_srv6_mac (e->evi, &mac, &sid, 0);
  if (m->flags == 2)
    return evpn_srv6_mac_nhg (e->evi, &mac, clib_net_to_host_u32 (m->sw_if_index));
  if (m->flags == 1)
    {
      u32 swi = vpp_for_linux (clib_net_to_host_u32 (m->sw_if_index), e->bd_index);
      return swi == ~0 ? -1 : evpn_srv6_mac_local (e->evi, &mac, &sid, swi);
    }
  return evpn_srv6_mac (e->evi, &mac, &sid, 1);
}

static int
receive_message (const struct evpn_srv6_msg *message)
{
  if (clib_net_to_host_u32 (message->magic) != EVPN_SRV6_MAGIC ||
      message->version != EVPN_SRV6_VERSION || message->add > 1)
    return -1;
  switch (message->op)
    {
    case EVPN_SRV6_BEGIN:
      if (ready || in_snapshot)
	return -1;
      flush_remote ();
      in_snapshot = 1;
      return 0;
    case EVPN_SRV6_END:
      if (!in_snapshot)
	return -1;
      in_snapshot = 0;
      ready = 1;
      retry_delay = 0.25;
      send_services ();
      reconcile_es (1);
      evpn_learn_replay ();
      EVPN_NOTICE ("Zebra SRv6 dataplane connected; replaying local state");
      return 0;
    case EVPN_SRV6_LOCAL_SID:
      {
        if (!ready)
          return -1;
        evpn_evi_t *e = evi_for_vni (clib_net_to_host_u32 (message->vni));
        ip6_address_t source, sid;
        clib_memcpy (&source, message->key, 16);
        clib_memcpy (&sid, message->sid, 16);
        vlib_worker_thread_barrier_sync (evpn_main.vlib_main);
        int rv = e ? evpn_srv6_local_sid (e->evi, &source, &sid,
                                         message->type, message->add) : -1;
        vlib_worker_thread_barrier_release (evpn_main.vlib_main);
        return rv;
      }
    case EVPN_SRV6_SYNC:
      if (!ready)
	return -1;
      /* Recreate ES associations before replaying their MAC ownership. */
      send_services ();
      reconcile_es (1);
      evpn_learn_replay ();
      return 0;
    case EVPN_SRV6_DF:
    case EVPN_SRV6_PEER:
      return ready ? mh_update (message) : -1;
    case EVPN_SRV6_SID:
    case EVPN_SRV6_NH:
    case EVPN_SRV6_NHG:
    case EVPN_SRV6_ROUTE:
      {
	if (!ready && !in_snapshot)
	  return -1;
	vlib_worker_thread_barrier_sync (evpn_main.vlib_main);
	int rv;
	if (message->op == EVPN_SRV6_ROUTE)
	  rv = route_update (message);
	else if (message->op == EVPN_SRV6_SID)
	  {
	    evpn_evi_t *e = evi_for_vni (clib_net_to_host_u32 (message->vni));
	    ip6_address_t peer, sid;
	    clib_memcpy (&peer, message->key, 16);
	    clib_memcpy (&sid, message->sid, 16);
	    rv = e ? evpn_srv6_peer_sid (e->evi, &peer, &sid, message->type) : 0;
	  }
	else
	  {
	    ip6_address_t peer;
	    clib_memcpy (&peer, message->sid, 16);
	    rv = evpn_srv6_nh_update (clib_net_to_host_u32 (message->sw_if_index), &peer,
				      message->op == EVPN_SRV6_NHG, message->add, message->flags,
				      clib_net_to_host_u32 (message->vni));
	  }
	vlib_worker_thread_barrier_release (evpn_main.vlib_main);
	return rv;
      }
    default:
      return -1;
    }
}

static int
read_pending (void)
{
  for (u32 frames = 0; frames < 256; frames++)
    {
      ssize_t n = recv (zebra_fd, (u8 *) &input + input_used, sizeof (input) - input_used, 0);
      if (n < 0)
	{
	  if (errno == EINTR)
	    continue;
	  return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
	}
      if (!n)
	return -1;
      input_used += n;
      if (input_used == sizeof (input))
	{
	  input_used = 0;
	  if (receive_message (&input))
	    return -1;
	}
    }
  /* Edge-triggered fd: finish any remaining data without a polling timer. */
  wake (ZEBRA_IO);
  return 0;
}

static clib_error_t *
zebra_read_ready (clib_file_t *file)
{
  wake (ZEBRA_IO);
  return 0;
}

static clib_error_t *
zebra_write_ready (clib_file_t *file)
{
  clib_file_set_data_available_to_write (&file_main, zebra_file, 0);
  wake (ZEBRA_IO);
  return 0;
}

static clib_error_t *
zebra_error (clib_file_t *file)
{
  evpn_zebra_resync ();
  return 0;
}

static int
connect_zebra (void)
{
  struct sockaddr_un address = { .sun_family = AF_UNIX };
  int original_ns = -1, target_ns = -1, fd = -1, result = -1;
  if (netns_path)
    {
      original_ns = open ("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
      target_ns = open ((char *) netns_path, O_RDONLY | O_CLOEXEC);
      if (original_ns < 0 || target_ns < 0 || setns (target_ns, CLONE_NEWNET) < 0)
	goto done;
    }
  fd = socket (AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd >= 0)
    {
      memcpy (address.sun_path + 1, EVPN_SRV6_SOCKET, strlen (EVPN_SRV6_SOCKET));
      result = connect (fd, (struct sockaddr *) &address,
			offsetof (struct sockaddr_un, sun_path) + 1 + strlen (EVPN_SRV6_SOCKET));
    }
  if (target_ns >= 0 && original_ns >= 0 && setns (original_ns, CLONE_NEWNET) < 0)
    clib_panic ("EVPN cannot restore VPP network namespace");
done:
  if (target_ns >= 0)
    close (target_ns);
  if (original_ns >= 0)
    close (original_ns);
  if (result < 0)
    {
      if (fd >= 0)
	close (fd);
      return -1;
    }
  clib_file_t file = {
    .file_descriptor = fd,
    .read_function = zebra_read_ready,
    .write_function = zebra_write_ready,
    .error_function = zebra_error,
    .flags = UNIX_FILE_EVENT_EDGE_TRIGGERED,
    .description = format (0, "evpn-zebra-srv6"),
  };
  zebra_fd = fd;
  zebra_file = clib_file_add (&file_main, &file);
  EVPN_NOTICE ("ZEBRA native SRv6 control connected");
  return 0;
}

static uword
zebra_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *frame)
{
  uword *events = 0;
  while (1)
    {
      if (enabled && zebra_fd < 0)
	{
	  if (connect_zebra ())
	    {
	      vlib_process_wait_for_event_or_clock (vm, retry_delay);
	      retry_delay = clib_min (retry_delay * 2, 8.0);
	    }
	  else
	    wake (ZEBRA_IO);
	}
      else
	vlib_process_wait_for_event (vm);
      uword type = vlib_process_get_events (vm, &events);
      vec_reset_length (events);
      if (!enabled || reset_requested || type == ZEBRA_RESET)
	{
	  reset_requested = 0;
	  disconnect_zebra ();
	  retry_delay = 0.25;
	  continue;
	}
      if (ready)
	reconcile_es (0);
      if (zebra_fd >= 0 && (read_pending () || write_pending ()))
	{
	  EVPN_WARN ("ZEBRA native control disconnected; flushing remote state");
	  disconnect_zebra ();
	}
    }
  return 0;
}
VLIB_REGISTER_NODE (evpn_zebra_process_node) = {
  .function = zebra_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "evpn-zebra-process",
};

static clib_error_t *
zebra_command (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u8 enable = 0, *path = 0;
  if (unformat (input, "enable"))
    enable = 1;
  else if (!unformat (input, "disable"))
    return clib_error_return (0, "enable [netns <path>] | disable required");
  if (enable)
    unformat (input, "netns %s", &path);
  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      vec_free (path);
      return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }
  vec_free (netns_path);
  netns_path = path;
  enabled = enable;
  ready = 0;
  reset_requested = 1;
  if (enable)
    evpn_learn_enable (1);
  wake (ZEBRA_RESET);
  return 0;
}
VLIB_CLI_COMMAND (evpn_zebra_command, static) = {
  .path = "evpn zebra",
  .function = zebra_command,
  .short_help = "evpn zebra enable [netns <path>] | disable",
};

static clib_error_t *
show_zebra (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vlib_cli_output (vm, "Zebra %s, control %s, %u queued bytes", enabled ? "enabled" : "disabled",
		   ready	 ? "ready" :
		   zebra_fd >= 0 ? "snapshot" :
				   "disconnected",
		   vec_len (output) - output_used);
  return 0;
}
VLIB_CLI_COMMAND (show_evpn_zebra_command, static) = {
  .path = "show evpn zebra",
  .function = show_zebra,
  .short_help = "show evpn zebra",
};

static uword
mh_output (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u32 next;
      vnet_feature_next (&next, b);
      ip6_address_t origin;
      if (evpn_srv6_bum_origin (b, &origin))
	{
	  u32 tx = vnet_buffer (b)->sw_if_index[VLIB_TX];
	  u32 bd = vnet_buffer (b)->l2.bd_index;
	  evpn_local_es_t *es;
	  vec_foreach (es, local_es)
	    {
	      uword *ei = hash_get (evpn_main.evi_by_id, es->evi);
	      if (!ei)
		continue;
	      evpn_evi_t *e = pool_elt_at_index (evpn_main.evis, ei[0]);
	      vnet_sw_interface_t *sw = vnet_get_sw_interface (evpn_main.vnet_main, tx);
	      if (e->bd_index != bd ||
		  (tx != es->sw_if_index && sw->sup_sw_if_index != es->sw_if_index))
		continue;
	      u8 same = 0;
	      ip6_address_t *peer;
	      vec_foreach (peer, es->peers)
		if (!memcmp (peer, &origin, 16))
		  {
		    same = 1;
		    break;
		  }
	      if (same)
		{
		  next = 0;
		  b->error = node->errors[1];
		}
	      else if (!es->df)
		{
		  next = 0;
		  b->error = node->errors[0];
		}
	      break;
	    }
	}
      vlib_set_next_frame_buffer (vm, node, next, from[i]);
    }
  return frame->n_vectors;
}
static char *mh_errors[] = { "non-DF BUM drops", "same-ES BUM drops" };
VLIB_REGISTER_NODE (evpn_mh_output_node) = {
  .name = "evpn-mh-output",
  .function = mh_output,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = sizeof (u32),
  .n_errors = 2,
  .error_strings = mh_errors,
  .n_next_nodes = 1,
  .next_nodes = { [0] = "error-drop" },
};
#define MH_FEATURE(sym, arc)                                                                       \
  VNET_FEATURE_INIT (sym, static) = { .arc_name = arc,                                             \
				      .node_name = "evpn-mh-output",                               \
				      .runs_before = VNET_FEATURES ("l2-output-feat-arc-end") };
MH_FEATURE (mh_ip4, "l2-output-ip4")
MH_FEATURE (mh_ip6, "l2-output-ip6")
MH_FEATURE (mh_nonip, "l2-output-nonip")
