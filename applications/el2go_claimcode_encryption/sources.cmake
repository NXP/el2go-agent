# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

set(EL2GO_CLAIMCODE_ENCRYPTION_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/src/el2go_claimcode_encryption.c
    ${CMAKE_CURRENT_LIST_DIR}/src/el2go_claimcode_encrypt.c
    ${CMAKE_CURRENT_LIST_DIR}/flash_config/el2go_flash_config.c
)

if(CONFIG_EL2GO_CLAIMCODE_BACKEND_ELS_PKC)
    list(APPEND EL2GO_CLAIMCODE_ENCRYPTION_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/els_pkc/el2go_claimcode_encrypt_els.c
    )
endif()
