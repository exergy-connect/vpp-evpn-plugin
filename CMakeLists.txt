# Copyright (c) 2026
# Licensed under the Apache License, Version 2.0 (the "License");
#
# Build as a VPP in-tree plugin:
#   ln -s $(pwd) /path/to/vpp/src/plugins/evpn
#   cd /path/to/vpp && make rebuild
#
# Or as an out-of-tree external project against an installed vpp-dev:
#   cmake -B build -DVPP_INSTALL_PATH=/usr -DVPP_EXTERNAL_PROJECT=ON .
#   cmake --build build

cmake_minimum_required(VERSION 3.16)
project(evpn_plugin C)

if(VPP_EXTERNAL_PROJECT)
  # Standalone out-of-tree build against installed VPP headers/libs.
  if(NOT VPP_INSTALL_PATH)
    set(VPP_INSTALL_PATH "/usr")
  endif()

  list(APPEND CMAKE_MODULE_PATH
    "${VPP_INSTALL_PATH}/share/vpp/cmake"
    "${VPP_INSTALL_PATH}/lib/cmake/vpp")

  find_path(VPP_INCLUDE_DIR NAMES vppinfra/clib.h
    PATHS ${VPP_INSTALL_PATH}/include)
  find_path(VPP_PLUGIN_CMAKE NAMES plugin.cmake
    PATHS ${VPP_INSTALL_PATH}/share/vpp/cmake
          ${VPP_INSTALL_PATH}/lib/cmake/vpp
    NO_DEFAULT_PATH)

  if(NOT VPP_INCLUDE_DIR)
    message(FATAL_ERROR "VPP headers not found (install vpp-dev)")
  endif()

  include_directories(${VPP_INCLUDE_DIR})

  # Prefer VPP's plugin macro when available.
  if(EXISTS "${VPP_INSTALL_PATH}/src/cmake/plugin.cmake")
    include(${VPP_INSTALL_PATH}/src/cmake/plugin.cmake)
  elseif(VPP_PLUGIN_CMAKE)
    include(${VPP_PLUGIN_CMAKE})
  endif()

  if(COMMAND add_vpp_plugin)
    add_vpp_plugin(evpn
      SOURCES
        evpn_plugin.c
        evpn.c
        evpn_cli.c
        evpn_api.c
        evpn_learn.c
        evpn.h
      API_FILES
        evpn.api
    )
  else()
    # Minimal fallback: shared object without vat codegen.
    # Generate API headers with vppapigen if present.
    find_program(VPPAPIGEN vppapigen)
    if(VPPAPIGEN)
      set(API_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/evpn)
      file(MAKE_DIRECTORY ${API_GEN_DIR})
      add_custom_command(
        OUTPUT
          ${API_GEN_DIR}/evpn.api.h
          ${API_GEN_DIR}/evpn.api_enum.h
          ${API_GEN_DIR}/evpn.api_types.h
          ${API_GEN_DIR}/evpn.api.c
        COMMAND ${VPPAPIGEN}
          --input ${CMAKE_CURRENT_SOURCE_DIR}/evpn.api
          --output-directory ${API_GEN_DIR}
          --output-file-prefix evpn
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/evpn.api
        COMMENT "Generating EVPN API bindings")
      set(API_GEN_SRCS
        ${API_GEN_DIR}/evpn.api.h
        ${API_GEN_DIR}/evpn.api_enum.h
        ${API_GEN_DIR}/evpn.api_types.h
        ${API_GEN_DIR}/evpn.api.c)
      include_directories(${CMAKE_CURRENT_BINARY_DIR})
    else()
      message(WARNING "vppapigen not found; build may fail without generated API headers")
      set(API_GEN_SRCS "")
    endif()

    add_library(evpn_plugin SHARED
      evpn_plugin.c
      evpn.c
      evpn_cli.c
      evpn_api.c
      evpn_learn.c
      ${API_GEN_SRCS})
    set_target_properties(evpn_plugin PROPERTIES
      PREFIX ""
      OUTPUT_NAME "evpn_plugin")
    target_include_directories(evpn_plugin PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}
      ${CMAKE_CURRENT_BINARY_DIR})
    target_compile_options(evpn_plugin PRIVATE -Wall -fPIC)
    find_library(VLIB_LIB vlib HINTS ${VPP_INSTALL_PATH}/lib)
    find_library(VNET_LIB vnet HINTS ${VPP_INSTALL_PATH}/lib)
    find_library(VPPINFRA_LIB vppinfra HINTS ${VPP_INSTALL_PATH}/lib)
    target_link_libraries(evpn_plugin ${VLIB_LIB} ${VNET_LIB} ${VPPINFRA_LIB})
    install(TARGETS evpn_plugin
      LIBRARY DESTINATION lib/x86_64-linux-gnu/vpp_plugins)
  endif()
else()
  # In-tree: dropped into src/plugins/evpn
  add_vpp_plugin(evpn
    SOURCES
      evpn_plugin.c
      evpn.c
      evpn_cli.c
      evpn_api.c
      evpn_learn.c
      evpn.h

    API_FILES
      evpn.api
  )
endif()
