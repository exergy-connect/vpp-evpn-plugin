/*
 * Copyright (c) 2026
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * EVPN debug CLI.
 */
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib_types.h>
#include <string.h>
#include "evpn.h"

static clib_error_t *
evpn_evi_command_fn (vlib_main_t * vm, unformat_input_t * input,
		     vlib_cli_command_t * cmd)
{
  u32 evi = ~0, vni = ~0, bd_id = ~0;
  u8 irb = 0, is_add = 1;
  mac_address_t rmac;
  int rv;

  mac_address_set_zero (&rmac);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "add"))
	is_add = 1;
      else if (unformat (input, "evi %u", &evi))
	;
      else if (unformat (input, "vni %u", &vni))
	;
      else if (unformat (input, "bd %u", &bd_id))
	;
      else if (unformat (input, "irb"))
	irb = 1;
      else if (unformat (input, "router-mac %U", unformat_mac_address_t, &rmac))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (evi == ~0)
    return clib_error_return (0, "evi required");

  if (is_add)
    {
      if (vni == ~0 || bd_id == ~0)
	return clib_error_return (0, "vni and bd required");
      rv = evpn_evi_add (evi, vni, bd_id, irb,
			 mac_address_is_zero (&rmac) ? 0 : &rmac);
    }
  else
    rv = evpn_evi_del (evi);

  if (rv)
    return clib_error_return (0, "evpn evi failed: %d", rv);
  return 0;
}

VLIB_CLI_COMMAND (evpn_evi_command, static) = {
  .path = "evpn evi",
  .short_help = "evpn evi add evi <id> vni <n> bd <id> [irb] [router-mac <mac>] | del evi <id>",
  .function = evpn_evi_command_fn,
};

static clib_error_t *
evpn_vrf_command_fn (vlib_main_t * vm, unformat_input_t * input,
		     vlib_cli_command_t * cmd)
{
  u32 table_id = ~0, l3_vni = ~0;
  u8 is_add = 1;
  mac_address_t rmac;
  int rv;

  mac_address_set_zero (&rmac);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "add"))
	is_add = 1;
      else if (unformat (input, "table %u", &table_id))
	;
      else if (unformat (input, "l3-vni %u", &l3_vni))
	;
      else if (unformat (input, "router-mac %U", unformat_mac_address_t, &rmac))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (table_id == ~0)
    return clib_error_return (0, "table required");

  if (is_add)
    {
      if (l3_vni == ~0)
	return clib_error_return (0, "l3-vni required");
      rv = evpn_vrf_add (table_id, l3_vni,
			 mac_address_is_zero (&rmac) ? 0 : &rmac);
    }
  else
    rv = evpn_vrf_del (table_id);

  if (rv)
    return clib_error_return (0, "evpn vrf failed: %d", rv);
  return 0;
}

VLIB_CLI_COMMAND (evpn_vrf_command, static) = {
  .path = "evpn vrf",
  .short_help = "evpn vrf add table <id> l3-vni <n> [router-mac <mac>] | del table <id>",
  .function = evpn_vrf_command_fn,
};

static clib_error_t *
evpn_vtep_command_fn (vlib_main_t * vm, unformat_input_t * input,
		      vlib_cli_command_t * cmd)
{
  ip46_address_t local = { }, remote = { };
  u32 encap_table = 0, dst_port = EVPN_VXLAN_DST_PORT;
  u8 is_add = 1, have_local = 0, have_remote = 0, is_ip6 = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "add"))
	is_add = 1;
      else if (unformat (input, "local %U", unformat_ip4_address, &local.ip4))
	{
	  have_local = 1;
	  is_ip6 = 0;
	}
      else if (unformat (input, "local %U", unformat_ip6_address, &local.ip6))
	{
	  have_local = 1;
	  is_ip6 = 1;
	}
      else if (unformat (input, "remote %U", unformat_ip4_address, &remote.ip4))
	have_remote = 1;
      else if (unformat (input, "remote %U", unformat_ip6_address, &remote.ip6))
	{
	  have_remote = 1;
	  is_ip6 = 1;
	}
      else if (unformat (input, "encap-table %u", &encap_table))
	;
      else if (unformat (input, "dst_port %u", &dst_port))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (!have_local || !have_remote)
    return clib_error_return (0, "local and remote required");

  if (dst_port > 65535)
    return clib_error_return (0, "dst_port must be 0-65535");

  if (is_add)
    rv = evpn_vtep_add (&local, &remote, encap_table, (u16) dst_port, is_ip6);
  else
    rv = evpn_vtep_del (&local, &remote, is_ip6);

  if (rv)
    return clib_error_return (0, "evpn vtep failed: %d", rv);
  return 0;
}

VLIB_CLI_COMMAND (evpn_vtep_command, static) = {
  .path = "evpn vtep",
  .short_help =
    "evpn vtep add local <ip> remote <ip> [encap-table <id>] [dst_port <n>] | del ...",
  .function = evpn_vtep_command_fn,
};

static clib_error_t *
evpn_mac_command_fn (vlib_main_t * vm, unformat_input_t * input,
		     vlib_cli_command_t * cmd)
{
  u32 evi = ~0;
  mac_address_t mac;
  ip46_address_t ip = { }, remote = { };
  u8 is_add = 1, has_ip = 0, is_ip6 = 0, have_mac = 0, have_remote = 0;
  int rv;

  mac_address_set_zero (&mac);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "add"))
	is_add = 1;
      else if (unformat (input, "evi %u", &evi))
	;
      else if (unformat (input, "mac %U", unformat_mac_address_t, &mac))
	have_mac = 1;
      else if (unformat (input, "ip %U", unformat_ip4_address, &ip.ip4))
	{
	  has_ip = 1;
	  is_ip6 = 0;
	}
      else if (unformat (input, "ip %U", unformat_ip6_address, &ip.ip6))
	{
	  has_ip = 1;
	  is_ip6 = 1;
	}
      else if (unformat (input, "remote %U", unformat_ip4_address, &remote.ip4))
	have_remote = 1;
      else if (unformat (input, "remote %U", unformat_ip6_address, &remote.ip6))
	{
	  have_remote = 1;
	  is_ip6 = 1;
	}
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (evi == ~0 || !have_mac)
    return clib_error_return (0, "evi and mac required");

  if (is_add)
    {
      if (!have_remote)
	return clib_error_return (0, "remote required");
      rv =
	evpn_mac_add (evi, &mac, has_ip ? &ip : 0, has_ip, is_ip6, &remote);
    }
  else
    rv = evpn_mac_del (evi, &mac);

  if (rv)
    return clib_error_return (0, "evpn mac failed: %d", rv);
  return 0;
}

VLIB_CLI_COMMAND (evpn_mac_command, static) = {
  .path = "evpn mac",
  .short_help = "evpn mac add evi <id> mac <mac> [ip <addr>] remote <vtep> | del evi <id> mac <mac>",
  .function = evpn_mac_command_fn,
};

static clib_error_t *
evpn_imet_command_fn (vlib_main_t * vm, unformat_input_t * input,
		      vlib_cli_command_t * cmd)
{
  u32 evi = ~0;
  ip46_address_t remote = { };
  u8 is_add = 1, have_remote = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "add"))
	is_add = 1;
      else if (unformat (input, "evi %u", &evi))
	;
      else if (unformat (input, "remote %U", unformat_ip4_address, &remote.ip4))
	have_remote = 1;
      else if (unformat (input, "remote %U", unformat_ip6_address, &remote.ip6))
	have_remote = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (evi == ~0 || !have_remote)
    return clib_error_return (0, "evi and remote required");

  if (is_add)
    rv = evpn_imet_add (evi, &remote);
  else
    rv = evpn_imet_del (evi, &remote);

  if (rv)
    return clib_error_return (0, "evpn imet failed: %d", rv);
  return 0;
}

VLIB_CLI_COMMAND (evpn_imet_command, static) = {
  .path = "evpn imet",
  .short_help = "evpn imet add evi <id> remote <vtep> | del evi <id> remote <vtep>",
  .function = evpn_imet_command_fn,
};

static clib_error_t *
evpn_prefix_command_fn (vlib_main_t * vm, unformat_input_t * input,
			vlib_cli_command_t * cmd)
{
  u32 table_id = ~0;
  fib_prefix_t pfx;
  ip46_address_t remote = { };
  mac_address_t rmac;
  u8 is_add = 1, have_pfx = 0, have_remote = 0, have_rmac = 0;
  int rv;

  clib_memset (&pfx, 0, sizeof (pfx));
  mac_address_set_zero (&rmac);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "add"))
	is_add = 1;
      else if (unformat (input, "table %u", &table_id))
	;
      else if (unformat (input, "%U/%d", unformat_ip4_address,
			 &pfx.fp_addr.ip4, &pfx.fp_len))
	{
	  pfx.fp_proto = FIB_PROTOCOL_IP4;
	  have_pfx = 1;
	}
      else if (unformat (input, "%U/%d", unformat_ip6_address,
			 &pfx.fp_addr.ip6, &pfx.fp_len))
	{
	  pfx.fp_proto = FIB_PROTOCOL_IP6;
	  have_pfx = 1;
	}
      else if (unformat (input, "remote %U", unformat_ip4_address, &remote.ip4))
	have_remote = 1;
      else if (unformat (input, "remote %U", unformat_ip6_address, &remote.ip6))
	have_remote = 1;
      else if (unformat (input, "router-mac %U", unformat_mac_address_t, &rmac))
	have_rmac = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (table_id == ~0 || !have_pfx)
    return clib_error_return (0, "table and prefix required");

  if (is_add)
    {
      if (!have_remote || !have_rmac)
	return clib_error_return (0, "remote and router-mac required");
      rv = evpn_prefix_add (table_id, &pfx, &remote, &rmac);
    }
  else
    rv = evpn_prefix_del (table_id, &pfx);

  if (rv)
    return clib_error_return (0, "evpn prefix failed: %d", rv);
  return 0;
}

VLIB_CLI_COMMAND (evpn_prefix_command, static) = {
  .path = "evpn prefix",
  .short_help =
    "evpn prefix add table <id> <prefix>/<len> remote <vtep> router-mac <mac> | del table <id> <prefix>/<len>",
  .function = evpn_prefix_command_fn,
};

static clib_error_t *
evpn_learn_command_fn (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  u8 enable = 1;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
	enable = 1;
      else if (unformat (input, "disable"))
	enable = 0;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  rv = evpn_learn_enable (enable);
  if (rv)
    return clib_error_return (0, "evpn learn failed: %d", rv);
  return 0;
}

VLIB_CLI_COMMAND (evpn_learn_command, static) = {
  .path = "evpn learn",
  .short_help = "evpn learn enable | disable",
  .function = evpn_learn_command_fn,
};

static clib_error_t *
show_evpn_command_fn (vlib_main_t * vm, unformat_input_t * input,
		      vlib_cli_command_t * cmd)
{
  evpn_main_t *em = &evpn_main;
  evpn_evi_t *e;
  evpn_vrf_t *v;
  evpn_tunnel_t *t;
  evpn_mac_t *m;
  evpn_imet_t *im;
  evpn_prefix_t *pr;
  evpn_vtep_t *vt;
  evpn_gw_mac_t *gm;
  evpn_gw_ip_t *gi;
  u8 show_evi = 0, show_vrf = 0, show_mac = 0, show_prefix = 0;
  u8 show_tunnel = 0, show_imet = 0, show_vtep = 0, show_all = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "evi"))
	{
	  show_evi = 1;
	  show_all = 0;
	}
      else if (unformat (input, "vrf"))
	{
	  show_vrf = 1;
	  show_all = 0;
	}
      else if (unformat (input, "mac"))
	{
	  show_mac = 1;
	  show_all = 0;
	}
      else if (unformat (input, "prefix"))
	{
	  show_prefix = 1;
	  show_all = 0;
	}
      else if (unformat (input, "tunnel"))
	{
	  show_tunnel = 1;
	  show_all = 0;
	}
      else if (unformat (input, "imet"))
	{
	  show_imet = 1;
	  show_all = 0;
	}
      else if (unformat (input, "vtep"))
	{
	  show_vtep = 1;
	  show_all = 0;
	}
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (show_all || show_evi)
    {
      vlib_cli_output (vm, "EVIs:");
      pool_foreach (e, em->evis)
	{
	  vlib_cli_output (vm, "  %U", format_evpn_evi, e);
	}
      vlib_cli_output (vm, "Protected gateways:");
      pool_foreach (gm, em->gw_macs)
	{
	  vlib_cli_output (vm, "  %U", format_evpn_gw_mac, gm);
	}
      pool_foreach (gi, em->gw_ips)
	{
	  vlib_cli_output (vm, "  %U", format_evpn_gw_ip, gi);
	}
    }
  if (show_all || show_vrf)
    {
      vlib_cli_output (vm, "VRFs:");
      pool_foreach (v, em->vrfs)
	{
	  vlib_cli_output (vm, "  %U", format_evpn_vrf, v);
	}
    }
  if (show_all || show_vtep)
    {
      vlib_cli_output (vm, "VTEPs:");
      pool_foreach (vt, em->vteps)
	{
	  vlib_cli_output (vm, "  local %U remote %U encap-table %u dst_port %u",
			   format_ip46_address, &vt->local, IP46_TYPE_ANY,
			   format_ip46_address, &vt->remote, IP46_TYPE_ANY,
			   vt->encap_table_id, vt->dst_port);
	}
    }
  if (show_all || show_tunnel)
    {
      vlib_cli_output (vm, "Tunnels:");
      pool_foreach (t, em->tunnels)
	{
	  vlib_cli_output (vm, "  %U", format_evpn_tunnel, t);
	}
    }
  if (show_all || show_mac)
    {
      vlib_cli_output (vm, "MACs:");
      pool_foreach (m, em->macs)
	{
	  vlib_cli_output (vm, "  evi %u mac %U remote %U%s",
			   m->evi, format_mac_address_t, &m->mac,
			   format_ip46_address, &m->remote, IP46_TYPE_ANY,
			   m->has_ip ? " (has-ip)" : "");
	}
    }
  if (show_all || show_imet)
    {
      vlib_cli_output (vm, "IMETs:");
      pool_foreach (im, em->imets)
	{
	  vlib_cli_output (vm, "  evi %u remote %U", im->evi,
			   format_ip46_address, &im->remote, IP46_TYPE_ANY);
	}
    }
  if (show_all || show_prefix)
    {
      vlib_cli_output (vm, "Prefixes:");
      pool_foreach (pr, em->prefixes)
	{
	  vlib_cli_output (vm, "  table %u %U remote %U rmac %U via %U",
			   pr->table_id, format_fib_prefix, &pr->prefix,
			   format_ip46_address, &pr->remote, IP46_TYPE_ANY,
			   format_mac_address_t, &pr->router_mac,
			   format_ip4_address, &pr->overlay_nh4);
	}
    }
  vlib_cli_output (vm, "learn: %s", em->learn_enabled ? "enabled" : "disabled");
  {
    vlib_log_subclass_data_t *sc =
      vlib_log_get_subclass_data (em->log_class);
    vlib_cli_output (vm, "logging: class evpn level %U syslog-level %U",
		     format_vlib_log_level, sc->level,
		     format_vlib_log_level, sc->syslog_level);
  }
  return 0;
}

VLIB_CLI_COMMAND (show_evpn_command, static) = {
  .path = "show evpn",
  .short_help = "show evpn [evi|vrf|mac|prefix|tunnel|imet|vtep]",
  .function = show_evpn_command_fn,
};

static uword
unformat_evpn_log_level (unformat_input_t * input, va_list * args)
{
  vlib_log_level_t *level = va_arg (*args, vlib_log_level_t *);
  u8 *level_str = 0;
  uword rv = 0;

  if (!unformat (input, "%s", &level_str))
    return 0;

#define _(uc, lc)							\
  if (!strcmp ((char *) level_str, #lc))				\
    {									\
      *level = VLIB_LOG_LEVEL_##uc;					\
      rv = 1;								\
      goto done;							\
    }
  foreach_vlib_log_level;
#undef _

done:
  vec_free (level_str);
  return rv;
}

static clib_error_t *
evpn_logging_command_fn (vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  evpn_main_t *em = &evpn_main;
  vlib_log_subclass_data_t *sc;
  vlib_log_level_t level = VLIB_LOG_LEVEL_UNKNOWN;
  vlib_log_level_t syslog_level = VLIB_LOG_LEVEL_UNKNOWN;
  u8 have_level = 0, have_syslog = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "level %U", unformat_evpn_log_level, &level))
	have_level = 1;
      else if (unformat (input, "syslog-level %U", unformat_evpn_log_level,
			 &syslog_level))
	have_syslog = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  sc = vlib_log_get_subclass_data (em->log_class);
  if (have_level)
    sc->level = level;
  if (have_syslog)
    sc->syslog_level = syslog_level;

  vlib_cli_output (vm, "evpn logging: level %U syslog-level %U",
		   format_vlib_log_level, sc->level, format_vlib_log_level,
		   sc->syslog_level);
  return 0;
}

VLIB_CLI_COMMAND (evpn_logging_command, static) = {
  .path = "evpn logging",
  .short_help =
    "evpn logging [level <emerg|alert|crit|error|warn|notice|info|debug|disabled>] [syslog-level <level>]",
  .function = evpn_logging_command_fn,
};
