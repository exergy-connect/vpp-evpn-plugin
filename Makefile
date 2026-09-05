# Convenience wrapper. Prefer in-tree build (see README).
#
#   make VPP_DIR=/path/to/vpp link   # symlink into src/plugins/evpn
#   make VPP_DIR=/path/to/vpp build  # make rebuild inside VPP
#   make external                    # cmake out-of-tree (needs vpp-dev)

VPP_DIR ?=
PLUGIN_LINK = $(VPP_DIR)/src/plugins/evpn

.PHONY: link build external clean docker docker-so

docker:
	docker build -t ghcr.io/exergy-connect/vpp-with-evpn-plugin .

docker-so: docker
	@id=$$(docker create ghcr.io/exergy-connect/vpp-with-evpn-plugin); \
	docker cp "$$id":/usr/lib/x86_64-linux-gnu/vpp_plugins/evpn_plugin.so ./evpn_plugin.so \
	  || docker cp "$$id":/usr/lib/vpp_plugins/evpn_plugin.so ./evpn_plugin.so; \
	docker rm "$$id"; \
	ls -l evpn_plugin.so


link:
	@test -n "$(VPP_DIR)" || (echo "set VPP_DIR=/path/to/vpp"; exit 1)
	ln -sfn "$(CURDIR)" "$(PLUGIN_LINK)"
	@echo "linked -> $(PLUGIN_LINK)"

build: link
	$(MAKE) -C "$(VPP_DIR)" rebuild

# Optional: EVPN_GIT_HASH=... EVPN_BUILD_DATE=... (UTC ISO8601)
external:
	cmake -B build -DVPP_EXTERNAL_PROJECT=ON -DVPP_INSTALL_PATH=/usr \
		$(if $(EVPN_GIT_HASH),-DEVPN_GIT_HASH=$(EVPN_GIT_HASH)) \
		$(if $(EVPN_BUILD_DATE),-DEVPN_BUILD_DATE=$(EVPN_BUILD_DATE))
	cmake --build build

clean:
	rm -rf build
	@if [ -n "$(VPP_DIR)" ] && [ -L "$(PLUGIN_LINK)" ]; then rm -f "$(PLUGIN_LINK)"; fi
