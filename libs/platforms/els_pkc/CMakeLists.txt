# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)

add_private_sources(el2go_platform
    els_pkc_platform.c
    els_pkc_crypto_params.c
    els_pkc_key_registration.c
)

add_private_directories(el2go_platform
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Key registration and platform_defs: ELS PKC Oracle (no TF-M) or TF-M variants.
if(NXP_IOT_AGENT_HAVE_PSA_IMPL_TFM)
    set(PSA_BACKEND_TFM tfm)
else()
    set(PSA_BACKEND_TFM psa)
endif()

add_private_directories(el2go_platform
    ${CMAKE_CURRENT_SOURCE_DIR}/${PSA_BACKEND_TFM}
)

add_subdirectory(${PSA_BACKEND_TFM})
