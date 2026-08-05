# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# Add subdirectories for each protobuf component.
# Each subdirectory handles the BUILD_ZEPHYR flag internally.
add_subdirectory(nanopb)
add_subdirectory(el2go)
add_subdirectory(ota)
add_subdirectory(utils)
