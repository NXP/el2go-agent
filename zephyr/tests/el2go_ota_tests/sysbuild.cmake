# Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0

# Sysbuild does not auto-discover sysbuild/boards/<board>.overlay for child
# images (e.g. MCUboot). Append the board-specific MCUboot DTS overlay here.
string(REPLACE "/" "_" BOARD_NORMALIZED "${BOARD}")

set(board_overlay
    "${APP_DIR}/sysbuild/boards/${BOARD_NORMALIZED}.overlay"
)

if(EXISTS "${board_overlay}")
  message(STATUS "MCUboot board overlay FOUND")
else()
  message(WARNING "MCUboot board overlay NOT FOUND")
endif()

if(EXISTS "${board_overlay}")
    set(mcuboot_DTC_OVERLAY_FILE
        "${APP_DIR}/sysbuild/mcuboot.overlay;${board_overlay}"
        CACHE STRING "" FORCE
    )
endif()