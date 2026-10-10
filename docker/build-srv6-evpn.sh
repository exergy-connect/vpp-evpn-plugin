#!/usr/bin/env bash
# Usage: build-srv6-evpn.sh /path/to/patched/frr [image-tag]
set -euo pipefail
frr_source=$(realpath "${1:?Provide the FRR checkout containing native SRv6 EVPN support}")
plugin_source=$(cd "$(dirname "$0")/.." && pwd)
build_context=$(mktemp -d)
trap 'rm -rf "$build_context"' EXIT
mkdir -p "$build_context/frr" "$build_context/plugin"
# Copy the working trees, including uncommitted changes, without build artifacts.
git -C "$frr_source" ls-files -z --cached --others --exclude-standard | tar -C "$frr_source" --null -T - -cf - | tar -C "$build_context/frr" -xf -
tar -C "$plugin_source" --exclude=.git --exclude=build --exclude=__pycache__ -cf - . | tar -C "$build_context/plugin" -xf -
docker build --build-arg "VPP_BASE=${VPP_BASE:-xform/vpp:linux-cp-srv6-route-sync}" \
    -t "${2:-xform/vpp:srv6-evpn}" -f "$plugin_source/docker/Dockerfile.srv6-evpn" "$build_context"
