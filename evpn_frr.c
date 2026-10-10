/* SPDX-License-Identifier: Apache-2.0
 * Direct, event-driven bgpd connection inside the existing VPP plugin.
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
#include <vlib/file.h>
#include <vlib/unix/unix.h>

static int frr_fd = -1;
static u32 frr_file = ~0;
static u8 enabled, ready, reset_requested, in_snapshot;
static u8 *netns_path, *output;
static uword output_used, input_used;
static struct evpn_srv6_msg input;
static f64 retry_delay = 0.25;
extern vlib_node_registration_t evpn_frr_process_node;

typedef struct
{
  u32 vni;
  u8 type, key[16];
  ip6_address_t sid;
} evpn_frr_route_t;
static evpn_frr_route_t *routes;

enum
{
  FRR_IO = 1,
  FRR_RESET
};

static void
wake (uword event)
{
  vlib_process_signal_event (evpn_main.vlib_main, evpn_frr_process_node.index,
                             event, 0);
}

static evpn_evi_t *
evi_for_vni (u32 vni)
{
  evpn_evi_t *e;
  pool_foreach (
      e, evpn_main.evis) if (e->vni == vni
                             && evpn_srv6_service_exists (e->evi)) return e;
  return 0;
}

static void
flush_remote (void)
{
  evpn_evi_t *e;
  pool_foreach (e, evpn_main.evis) if (evpn_srv6_service_exists (e->evi))
      evpn_srv6_flush (e->evi);
  vec_reset_length (routes);
}

static void
disconnect_frr (void)
{
  ready = in_snapshot = 0;
  if (frr_file != ~0)
    {
      /* clib_file_del closes the descriptor. */
      clib_file_del_by_index (&file_main, frr_file);
      frr_file = ~0;
    }
  else if (frr_fd >= 0)
    close (frr_fd);
  frr_fd = -1;
  input_used = output_used = 0;
  vec_reset_length (output);
  flush_remote ();
}

void
evpn_frr_resync (void)
{
  if (enabled)
    {
      ready = 0;
      reset_requested = 1;
      wake (FRR_RESET);
    }
}

/* Called directly by the existing in-process MAC learn publisher. */
void
evpn_frr_mac (u32 evi, mac_address_t *mac, u8 add)
{
  uword *index = hash_get (evpn_main.evi_by_id, evi);
  if (!ready || !index || !evpn_srv6_service_exists (evi))
    return;
  evpn_evi_t *e = pool_elt_at_index (evpn_main.evis, index[0]);
  struct evpn_srv6_msg message = {
    .magic = clib_host_to_net_u32 (EVPN_SRV6_MAGIC),
    .version = EVPN_SRV6_VERSION,
    .op = EVPN_SRV6_LOCAL,
    .type = 2,
    .add = add,
    .vni = clib_host_to_net_u32 (e->vni),
  };
  clib_memcpy (message.key, mac->bytes, 6);
  if (vec_len (output) - output_used + sizeof (message)
      > EVPN_SRV6_QUEUE_LIMIT)
    {
      EVPN_WARN ("FRR local MAC queue overflow; reconnecting for replay");
      evpn_frr_resync ();
      return;
    }
  /* Compact only when queued data has already been partially written. */
  if (output_used)
    {
      vec_delete (output, output_used, 0);
      output_used = 0;
    }
  vec_add (output, (u8 *)&message, sizeof (message));
  wake (FRR_IO);
}

static int
write_pending (void)
{
  while (output_used < vec_len (output))
    {
      ssize_t n = send (frr_fd, output + output_used,
                        vec_len (output) - output_used, MSG_NOSIGNAL);
      if (n < 0)
        {
          if (errno == EINTR)
            continue;
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
              clib_file_set_data_available_to_write (&file_main, frr_file, 1);
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
  clib_file_set_data_available_to_write (&file_main, frr_file, 0);
  return 0;
}

static u8
imet_in_use (u32 vni, ip6_address_t *sid)
{
  evpn_frr_route_t *r;
  vec_foreach (r, routes) if (r->vni == vni && r->type == 3
                              && !memcmp (&r->sid, sid, 16)) return 1;
  return 0;
}

static int
route_update (const struct evpn_srv6_msg *message)
{
  u32 vni = clib_net_to_host_u32 (message->vni);
  evpn_evi_t *e = evi_for_vni (vni);
  ip6_address_t sid;
  mac_address_t mac;
  uword i;
  if (message->type != 2 && message->type != 3)
    return -1;
  if (!e)
    return 0; /* No matching native service provisioned in VPP. */
  clib_memcpy (&sid, message->sid, 16);
  mac_address_from_bytes (&mac, message->key);
  vec_foreach_index (
      i, routes) if (routes[i].vni == vni && routes[i].type == message->type
                     && !memcmp (routes[i].key, message->key, 16)) break;
  if (i < vec_len (routes))
    {
      ip6_address_t old = routes[i].sid;
      if (message->add && !memcmp (&old, &sid, 16))
        return 0;
      vec_del1 (routes, i);
      if (message->type == 3 && !imet_in_use (vni, &old)
          && evpn_srv6_imet (e->evi, &old, 0))
        return -1;
    }
  if (message->type == 2)
    {
      if (evpn_srv6_mac (e->evi, &mac, &sid, message->add))
        return -1;
    }
  else if (message->add && !imet_in_use (vni, &sid)
           && evpn_srv6_imet (e->evi, &sid, 1))
    return -1;
  if (message->add)
    {
      evpn_frr_route_t *r;
      vec_add2 (routes, r, 1);
      r->vni = vni;
      r->type = message->type;
      clib_memcpy (r->key, message->key, 16);
      r->sid = sid;
    }
  return 0;
}

static int
receive_message (const struct evpn_srv6_msg *message)
{
  if (clib_net_to_host_u32 (message->magic) != EVPN_SRV6_MAGIC
      || message->version != EVPN_SRV6_VERSION || message->add > 1)
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
      evpn_learn_replay ();
      EVPN_NOTICE ("FRR native SRv6 snapshot complete: %u routes",
                   vec_len (routes));
      return 0;
    case EVPN_SRV6_SYNC:
      if (!ready)
        return -1;
      /* FRR cleared local advertisements during service reconfiguration. */
      evpn_learn_replay ();
      return 0;
    case EVPN_SRV6_ROUTE:
      return (ready || in_snapshot) ? route_update (message) : -1;
    default:
      return -1;
    }
}

static int
read_pending (void)
{
  for (u32 frames = 0; frames < 256; frames++)
    {
      ssize_t n = recv (frr_fd, (u8 *)&input + input_used,
                        sizeof (input) - input_used, 0);
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
  wake (FRR_IO);
  return 0;
}

static clib_error_t *
frr_read_ready (clib_file_t *file)
{
  wake (FRR_IO);
  return 0;
}

static clib_error_t *
frr_write_ready (clib_file_t *file)
{
  clib_file_set_data_available_to_write (&file_main, frr_file, 0);
  wake (FRR_IO);
  return 0;
}

static clib_error_t *
frr_error (clib_file_t *file)
{
  evpn_frr_resync ();
  return 0;
}

static int
connect_frr (void)
{
  struct sockaddr_un address = { .sun_family = AF_UNIX };
  int original_ns = -1, target_ns = -1, fd = -1, result = -1;
  if (netns_path)
    {
      original_ns = open ("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
      target_ns = open ((char *)netns_path, O_RDONLY | O_CLOEXEC);
      if (original_ns < 0 || target_ns < 0
          || setns (target_ns, CLONE_NEWNET) < 0)
        goto done;
    }
  fd = socket (AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd >= 0)
    {
      memcpy (address.sun_path + 1, EVPN_SRV6_SOCKET,
              strlen (EVPN_SRV6_SOCKET));
      result = connect (fd, (struct sockaddr *)&address,
                        offsetof (struct sockaddr_un, sun_path) + 1
                            + strlen (EVPN_SRV6_SOCKET));
    }
  if (target_ns >= 0 && original_ns >= 0
      && setns (original_ns, CLONE_NEWNET) < 0)
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
    .read_function = frr_read_ready,
    .write_function = frr_write_ready,
    .error_function = frr_error,
    .flags = UNIX_FILE_EVENT_EDGE_TRIGGERED,
    .description = format (0, "evpn-frr-srv6"),
  };
  frr_fd = fd;
  frr_file = clib_file_add (&file_main, &file);
  EVPN_NOTICE ("FRR native SRv6 control connected");
  return 0;
}

static uword
frr_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *frame)
{
  uword *events = 0;
  while (1)
    {
      if (enabled && frr_fd < 0)
        {
          if (connect_frr ())
            {
              vlib_process_wait_for_event_or_clock (vm, retry_delay);
              retry_delay = clib_min (retry_delay * 2, 8.0);
            }
          else
            wake (FRR_IO);
        }
      else
        vlib_process_wait_for_event (vm);
      uword type = vlib_process_get_events (vm, &events);
      vec_reset_length (events);
      if (!enabled || reset_requested || type == FRR_RESET)
        {
          reset_requested = 0;
          disconnect_frr ();
          retry_delay = 0.25;
          continue;
        }
      if (frr_fd >= 0 && (read_pending () || write_pending ()))
        {
          EVPN_WARN ("FRR native control disconnected; flushing remote state");
          disconnect_frr ();
        }
    }
  return 0;
}
VLIB_REGISTER_NODE (evpn_frr_process_node) = {
  .function = frr_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "evpn-frr-process",
};

static clib_error_t *
frr_command (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
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
      return clib_error_return (0, "unknown input `%U'", format_unformat_error,
                                input);
    }
  vec_free (netns_path);
  netns_path = path;
  enabled = enable;
  ready = 0;
  reset_requested = 1;
  if (enable)
    evpn_learn_enable (1);
  wake (FRR_RESET);
  return 0;
}
VLIB_CLI_COMMAND (evpn_frr_command, static) = {
  .path = "evpn frr",
  .function = frr_command,
  .short_help = "evpn frr enable [netns <path>] | disable",
};

static clib_error_t *
show_frr (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vlib_cli_output (vm, "FRR %s, control %s, %u routes, %u queued bytes",
                   enabled ? "enabled" : "disabled",
                   ready         ? "ready"
                   : frr_fd >= 0 ? "snapshot"
                                 : "disconnected",
                   vec_len (routes), vec_len (output) - output_used);
  return 0;
}
VLIB_CLI_COMMAND (show_evpn_frr_command, static) = {
  .path = "show evpn frr",
  .function = show_frr,
  .short_help = "show evpn frr",
};
