# Build the EVPN plugin against FD.io VPP (matches lab image: debian bookworm).
#
#   docker build -t exergy/vpp-with-evpn-plugin .
#   docker build -t exergy/vpp-with-evpn-plugin --build-arg VPP_VERSION=25.06-release .
#
# Extract the .so:
#   docker create --name evpn-tmp exergy/vpp-with-evpn-plugin
#   docker cp evpn-tmp:/usr/lib/x86_64-linux-gnu/vpp_plugins/evpn_plugin.so .
#   docker rm evpn-tmp
#
# Or run VPP with the plugin already installed:
#   docker run --rm -it --privileged exergy/vpp-with-evpn-plugin

ARG DEBIAN_FRONTEND=noninteractive
ARG REPO=release
ARG VPP_VERSION=

# ---------------------------------------------------------------------------
# Stage 1: build evpn_plugin.so against vpp-dev
# ---------------------------------------------------------------------------
FROM debian:bookworm AS builder

ARG DEBIAN_FRONTEND
ARG REPO
ARG VPP_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
		apt-transport-https \
		ca-certificates \
		cmake \
		curl \
		g++ \
		gcc \
		gnupg \
		make \
		pkg-config \
		python3 \
	&& rm -rf /var/lib/apt/lists/*

# FD.io packagecloud repo + install VPP runtime + headers (vpp-dev).
RUN set -eux; \
	REPO_URL="https://packagecloud.io/install/repositories/fdio/${REPO}"; \
	curl -sS "${REPO_URL}/script.deb.sh" | bash; \
	apt-get update; \
	if [ -n "${VPP_VERSION}" ]; then \
		apt-get install -y --no-install-recommends \
			"vpp=${VPP_VERSION}" \
			"vpp-plugin-core=${VPP_VERSION}" \
			"vpp-dev=${VPP_VERSION}" \
			"libvppinfra-dev=${VPP_VERSION}" \
			"python3-vpp-api=${VPP_VERSION}" \
		|| apt-get install -y --no-install-recommends \
			vpp vpp-plugin-core vpp-dev libvppinfra-dev python3-vpp-api; \
	else \
		apt-get install -y --no-install-recommends \
			vpp vpp-plugin-core vpp-dev libvppinfra-dev python3-vpp-api; \
	fi; \
	dpkg-query -W -f='${Package} ${Version}\n' 'vpp*' 'libvppinfra*' | sort; \
	rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src/

# Out-of-tree build. Prefer VPP's add_vpp_plugin when cmake helpers exist;
# otherwise the CMakeLists.txt fallback + vppapigen path is used.
RUN set -eux; \
	cmake -B build \
		-DCMAKE_BUILD_TYPE=Release \
		-DVPP_EXTERNAL_PROJECT=ON \
		-DVPP_INSTALL_PATH=/usr \
		-DCMAKE_INSTALL_PREFIX=/usr; \
	cmake --build build -j"$(nproc)"; \
	cmake --install build; \
	find /usr -name 'evpn_plugin.so' -print; \
	test -f /usr/lib/x86_64-linux-gnu/vpp_plugins/evpn_plugin.so \
		|| test -f /usr/lib/vpp_plugins/evpn_plugin.so

# ---------------------------------------------------------------------------
# Stage 2: runtime image — VPP + plugin (no build tools)
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

ARG DEBIAN_FRONTEND
ARG REPO
ARG VPP_VERSION

LABEL description="FD.io VPP with minimal EVPN plugin (L2 + symmetric IRB)"

RUN apt-get update && apt-get install -y --no-install-recommends \
		apt-transport-https \
		ca-certificates \
		curl \
		gnupg \
		iproute2 \
		procps \
	&& rm -rf /var/lib/apt/lists/*

RUN set -eux; \
	REPO_URL="https://packagecloud.io/install/repositories/fdio/${REPO}"; \
	curl -sS "${REPO_URL}/script.deb.sh" | bash; \
	# Containers often lack CAP_SYS_ADMIN for sysctl during package scripts.
	sysctl_bin="$(command -v sysctl)"; \
	mv "$sysctl_bin" "${sysctl_bin}.real"; \
	printf '#!/bin/sh\nexit 0\n' > "$sysctl_bin"; \
	chmod +x "$sysctl_bin"; \
	apt-get update; \
	if [ -n "${VPP_VERSION}" ]; then \
		apt-get install -y --no-install-recommends \
			"vpp=${VPP_VERSION}" \
			"vpp-plugin-core=${VPP_VERSION}" \
		|| apt-get install -y --no-install-recommends vpp vpp-plugin-core; \
	else \
		apt-get install -y --no-install-recommends vpp vpp-plugin-core; \
	fi; \
	mv "${sysctl_bin}.real" "$sysctl_bin"; \
	dpkg-query -f '${Version}\n' -W vpp > /vpp-version; \
	rm -rf /var/lib/apt/lists/*

# Collect plugin from whichever path cmake installed it to.
COPY --from=builder /usr/lib /tmp/builder-lib
RUN set -eux; \
	src=$(find /tmp/builder-lib -name 'evpn_plugin.so' | head -n1); \
	test -n "$src"; \
	for d in /usr/lib/x86_64-linux-gnu/vpp_plugins /usr/lib/vpp_plugins; do \
		if [ -d "$d" ]; then \
			install -m 0644 "$src" "$d/evpn_plugin.so"; \
			ls -l "$d/evpn_plugin.so"; \
			break; \
		fi; \
	done; \
	rm -rf /tmp/builder-lib

COPY test/smoke.cli /usr/share/vpp/evpn-smoke.cli

RUN mkdir -p /etc/vpp /run/vpp /var/log/vpp && \
	printf '%s\n' \
		'unix {' \
		'  nodaemon' \
		'  log /var/log/vpp/vpp.log' \
		'  full-coredump' \
		'  cli-listen /run/vpp/cli.sock' \
		'}' \
		'api-trace { on }' \
		'plugins {' \
		'  plugin default { enable }' \
		'  plugin dpdk_plugin.so { disable }' \
		'  plugin evpn_plugin.so { enable }' \
		'  plugin vxlan_plugin.so { enable }' \
		'}' \
		> /etc/vpp/startup.conf

CMD ["/usr/bin/vpp", "-c", "/etc/vpp/startup.conf"]
