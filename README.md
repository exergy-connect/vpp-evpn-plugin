# Minimal VPP EVPN plugin (L2 + symmetric IRB)

Out-of-tree VPP plugin that is an **EVPN-to-FIB/FDB agent**. It does **not**
speak BGP or EVPN on the wire. A userspace agent (BIRD `vppevpn`, FRR hook,
or custom) translates EVPN Type-2 / Type-3 / Type-5 into the CLI / binary API
below. The plugin registers existing VPP infrastructure and programs remote
reachability into it. No new graph nodes.

## Minimal ownership model

The lab or provisioning system owns bridge domains, BVIs, IP tables, addresses,
interface state, access ports, tagged VLAN subinterfaces, and LCP peers. Create
and configure these **before** registering EVIs or VRFs. Registration does not
create, reconfigure, or delete any of these objects.

- `evpn evi add ... bd N` requires bridge domain N. `irb` also requires a BVI
  already attached to that domain; it does not create one.
- `evpn vrf add table T ...` requires an existing IPv4 and/or IPv6 table T,
  bridge domain `10000 + T`, and its existing BVI. The BVI must already be bound
  to T for every address family present at registration. Configure addresses
  and enable the interface in the provisioning layer.
- Optional `router-mac` is an assertion against the existing BVI MAC, not a
  request to change it. Missing objects or mismatched bindings/MACs fail
  registration without provisioning anything.
- A registration holds references to these objects. Keep them and their
  bindings/MACs stable until registration is removed. To change them, withdraw
  remote state, unregister, reconfigure, and register again.
- Withdraw MAC and IMET entries before deleting an EVI, and prefixes before
  deleting a VRF. Deletion rejects outstanding children and leaves the BD,
  BVI, addresses, interface state, and IP tables intact.

The plugin owns EVPN-installed remote MAC entries, routes, neighbors, and
refcounted VXLAN tunnels. Type-2 and Type-3 updates attach remote tunnels to
existing L2 domains; Type-5 updates use the existing L3 domain/BVI. Do not also
provision static VXLAN tunnels for the same local/remote/VNI combinations.
Local learning is optional (`evpn learn enable`); an external control-plane
agent still translates events and BGP EVPN updates. The plugin does not speak
BGP, create Linux interfaces, or configure access VLANs.

This changes the previous implicit-provisioning behavior. Existing CLI/API
fields remain, but callers must provision infrastructure first. In particular,
`irb` now means “use the existing BVI.” The lab's module ordering and static
tunnel generation must follow this ownership model before deployment.

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
docker build -t ghcr.io/exergy-connect/vpp-with-evpn-plugin .
# Pin FD.io version (same style as the lab image):
docker build -t ghcr.io/exergy-connect/vpp-with-evpn-plugin \
  --build-arg VPP_VERSION=25.06-release .
```

CI (`.github/workflows/docker.yml`) builds on `main` / `v*` tags and pushes
`ghcr.io/exergy-connect/vpp-with-evpn-plugin` to GHCR (`packages: write` via
`GITHUB_TOKEN`). PRs build but do not push.

Pull:

```bash
docker pull ghcr.io/exergy-connect/vpp-with-evpn-plugin:latest
```

The image is VPP bookworm + `evpn_plugin.so` enabled, plus **bird3** and
**FRR** (`frr`, `frr-pythontools`) so xForm leaves can run either control
plane in the dataplane netns. Smoke CLI is at `/usr/share/vpp/evpn-smoke.cli`.

Extract only the plugin:

```bash
id=$(docker create ghcr.io/exergy-connect/vpp-with-evpn-plugin)
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
evpn logging [level <emerg|alert|crit|error|warn|notice|info|debug|disabled>] [syslog-level <level>]
show evpn [evi|vrf|mac|prefix|tunnel|imet|vtep]
```

Matching `… del …` forms remove state. VXLAN tunnels are refcounted per
`{src,dst,vni}`.

## Logging

The plugin registers VPP log class `evpn`. CRUD and learn events log at
`debug`; missing objects at `warn`; tunnel / VTEP failures at `error`.
Default class level follows VPP (`notice`), so debug lines are silent until
raised:

```
evpn logging level debug
# equivalent:
set logging class evpn level debug
show logging
show evpn
```

## Datapath model

**L2 EVI** — BD = `bd`, per-remote VTEP VXLAN attached to the BD, Type-2 →
static L2FIB, Type-3 IMET → flood membership, optional IRB BVI + neighbor.

**Symmetric IRB** — existing tenant IP table + L3-VNI BD with BVI (router-mac). Type-5
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

### Registration regression check

With the rebuilt plugin loaded in a fresh disposable VPP container:

```bash
python3 test/registration.py CONTAINER
```

This provisions test BDs/BVIs and checks missing prerequisites, MAC and table
binding validation, IPv4-only registration, preservation after unregister,
re-registration, and rejection of deletion with outstanding IMET/prefix state.
Do not run it against a deployed lab.
