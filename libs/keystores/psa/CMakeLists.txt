# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)

# Add PSA-specific keystore sources directly to parent target
add_private_sources(el2go_keystore
    el2go_keystore_psa.c
)

# Flash-based claimcode injection is only compiled when explicitly enabled.
# When disabled the weak stub in el2go_keystore.c is used instead.
if(CONFIG_EL2GO_RTP_CLAIMCODE_INJECT)
    add_private_sources(el2go_keystore el2go_keystore_psa_claimcode_flash.c)
    # Inject flash address into this library target. Kconfig only.
    add_lib_config_hex(el2go_keystore CONFIG_EL2GO_RTP_CLAIMCODE_FLASH_ADDRESS EL2GO_RTP_CLAIMCODE_FLASH_ADDRESS 0x0)
endif()

# Link PSA dependencies (non-Zephyr only; Zephyr resolves these via the module graph)
add_link_libraries(el2go_keystore
    PRIVATE
        el2go_protobuf
        el2go_platform
        pb_utils
)
