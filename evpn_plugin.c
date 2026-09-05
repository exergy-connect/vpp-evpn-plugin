/*
 * Copyright (c) 2026
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * Plugin registration — no graph nodes; EVPN agent only.
 */
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include "evpn.h"

#ifndef EVPN_GIT_HASH
#define EVPN_GIT_HASH "unknown"
#endif
#ifndef EVPN_BUILD_DATE
#define EVPN_BUILD_DATE "unknown"
#endif

static clib_error_t *
evpn_init (vlib_main_t * vm)
{
  evpn_main_t *em = &evpn_main;

  em->vlib_main = vm;
  em->vnet_main = vnet_get_main ();
  em->log_class = vlib_log_register_class ("evpn", 0);
  EVPN_NOTICE ("plugin initialized (logging class evpn) build-date %s git %s",
	       EVPN_BUILD_DATE, EVPN_GIT_HASH);
  return 0;
}

VLIB_INIT_FUNCTION (evpn_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "EVPN-to-FIB/FDB agent (L2 + symmetric IRB)",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
