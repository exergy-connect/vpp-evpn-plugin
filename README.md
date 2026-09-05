# Minimal VPP EVPN plugin (L2 + symmetric IRB)

Out-of-tree VPP plugin that is an **EVPN-to-FIB/FDB agent**. It does **not**
speak BGP or EVPN on the wire. A userspace agent (BIRD `vppevpn`, FRR hook,
or custom) translates EVPN Type-2 / Type-3 / Type-5 into the CLI / binary API
below. The plugin only allocates and wires existing VPP objects:

- bridge-domains + L2FIB
- BVI (IRB)
- VXLAN tunnels (via `vxlan_plugin.so`)
- IP tables / FIB + IP neighbors

No new graph nodes.

## Layout

```
vpp-evpn-plugin/
  Dockerfile               # multi-stage: build .so + runtime VPP image
  CMakeLists.txt
  README.md
  evpn.h / evpn.c          # object pools + tunnel refcount
  evpn_cli.c               # debug CLI
  evpn.api / evpn_api.c    # binary API + learn events
  evpn_learn.c             # L2FIB scan + address callbacks
  evpn_plugin.c            # VLIB_PLUGIN_REGISTER
  test/smoke.cli           # example two-leaf L2 + IRB sequence
```

## Build

### Docker (recommended)

From this directory:

```bash
docker build -t exergy/vpp-with-evpn-plugin .
# Pin FD.io version (same style as the lab image):
docker build -t exergy/vpp-with-evpn-plugin --build-arg VPP_VERSION=25.06-release .
```

CI (`.github/workflows/docker.yml`) builds on `main` / `v*` tags and pushes
`exergy/vpp-with-evpn-plugin` to Docker Hub. Configure repo secrets
`DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`. PRs build but do not push.

The image is VPP bookworm + `evpn_plugin.so` enabled. Smoke CLI is at
`/usr/share/vpp/evpn-smoke.cli`.

Extract only the plugin:

```bash
id=$(docker create exergy/vpp-with-evpn-plugin)
docker cp "$id":/usr/lib/x86_64-linux-gnu/vpp_plugins/evpn_plugin.so .
docker rm "$id"
```

### In-tree

```bash
ln -sfn "$(pwd)" /path/to/vpp/src/plugins/evpn
cd /path/to/vpp && make rebuild
# → build-root/.../vpp_plugins/evpn_plugin.so
```

### Out-of-tree against installed `vpp-dev`

```bash
cmake -B build -DVPP_EXTERNAL_PROJECT=ON -DVPP_INSTALL_PATH=/usr
cmake --build build
sudo cmake --install build
```

Enable in `startup.conf` (already done in the Docker image):

```
plugins {
  plugin evpn_plugin.so { enable }
  plugin vxlan_plugin.so { enable }
}
```

## CLI

```
evpn evi add evi <id> vni <n> bd <id> [irb] [router-mac <mac>]
evpn vrf add table <id> l3-vni <n> [router-mac <mac>]
evpn vtep add local <ip> remote <ip> [encap-table <id>]
evpn mac add evi <id> mac <mac> [ip <addr>] remote <vtep>
evpn imet add evi <id> remote <vtep>
evpn prefix add table <id> <prefix>/<len> remote <vtep> router-mac <mac>
evpn learn enable|disable
show evpn [evi|vrf|mac|prefix|tunnel|imet|vtep]
```

Matching `… del …` forms remove state. VXLAN tunnels are refcounted per
`{src,dst,vni}`.

## Datapath model

**L2 EVI** — BD = `bd`, per-remote VTEP VXLAN attached to the BD, Type-2 →
static L2FIB, Type-3 IMET → flood membership, optional IRB BVI + neighbor.

**Symmetric IRB** — tenant IP table + L3-VNI BD with BVI (router-mac). Type-5
installs `prefix via <overlay-nh> bvi_l3` where `overlay-nh` is a synthetic
`169.254.x.y` derived from the remote VTEP, with neighbor
`overlay-nh → remote router-mac` on the L3 BVI. Inner Ethernet over the L3 VNI
(not VPP `vxlan … l3`).

VXLAN tunnels are created through the existing `create vxlan tunnel …`
CLI (the vxlan plugin does not `__clib_export` its C entry point), with an
explicit `instance` so the agent can resolve `vxlan_tunnel<N>`.

## Learn / origination

`evpn learn enable` starts a process that:

1. Scans EVI L2FIB for dynamic (non-static, non-VXLAN, non-BVI) MACs
2. Watches IPv4 addresses on IRB / L3 BVIs

and publishes `evpn_mac_learn_event` / `evpn_prefix_learn_event` to clients
registered with `want_evpn_learn_events`. The plugin never writes BGP.

## Smoke test

See [`test/smoke.cli`](test/smoke.cli) for a CLI-only two-leaf L2 + symmetric
IRB programming sequence (run once per leaf with local/remote swapped).

## Non-goals (v0.1)

ESI / Type-1 / Type-4, VLAN-aware bundle, asymmetric IRB, multicast underlay,
MAC→VTEP map inside a single VXLAN interface.
