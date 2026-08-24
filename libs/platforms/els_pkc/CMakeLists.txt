# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)

add_private_sources(el2go_platform
    els_pkc_platform.c
    els_pkc_crypto_params.c
)

add_private_directories(el2go_platform
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Key registration and platform_defs: ELS PKC Oracle (no TF-M) or TF-M variants.
if(NXP_IOT_AGENT_HAVE_PSA_IMPL_TFM OR CONFIG_EL2GO_RTP_PSA_BACKEND_TFM)
    add_private_sources(el2go_platform
        tfm/els_pkc_key_registration_tfm.c
    )
    add_private_directories(el2go_platform
        ${CMAKE_CURRENT_SOURCE_DIR}/tfm
    )
else()
    add_private_sources(el2go_platform
        els_pkc_key_registration.c
    )
    add_private_directories(el2go_platform
        ${CMAKE_CURRENT_SOURCE_DIR}/psa
    )
endif()

if(NOT BUILD_ZEPHYR)
    add_private_sources(el2go_platform
        mcuxpresso/els_pkc_board.c
    )
endif()
