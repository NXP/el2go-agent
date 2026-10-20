# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)

# Strong implementation -- overrides the weak default in the parent directory
# when CONFIG_EL2GO_RTP_PLATFORM_KEY_REGISTRATION is enabled.
if(CONFIG_EL2GO_RTP_PLATFORM_KEY_REGISTRATION)
    add_private_sources(el2go_platform
        els_pkc_key_registration.c
    )
endif()
