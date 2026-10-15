# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)

add_private_sources(el2go_app_net ${CMAKE_CURRENT_LIST_DIR}/el2go_app_net_wifi.c)

# Inject WiFi credentials into the library target that owns el2go_app_net_wifi.c.
# Priority: Kconfig value > OS environment variable > #ifndef fallback in C.
add_lib_config_string(el2go_app_net CONFIG_EL2GO_NET_WIFI_SSID EL2GO_NET_WIFI_SSID)
add_lib_config_string(el2go_app_net CONFIG_EL2GO_NET_WIFI_PSK  EL2GO_NET_WIFI_PSK)
