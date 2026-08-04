# Copyright 2024-2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# Sources shared between the bare-metal and Zephyr builds.
set(EL2GO_IMPORT_BLOB_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/src/el2go_import_blob.c
    ${CMAKE_CURRENT_LIST_DIR}/src/el2go_import_blob_validate.c
    ${CMAKE_CURRENT_LIST_DIR}/src/el2go_psa_import.c
)

if(VALIDATE_PSA_IMPORT_MASTER_KEY)
    list(APPEND EL2GO_IMPORT_BLOB_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/psa/el2go_import_blob_validate_aes.c
    )
endif()

if(VALIDATE_PSA_IMPORT_KEY_PAIR)
    list(APPEND EL2GO_IMPORT_BLOB_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/psa/el2go_import_blob_validate_ecc.c
    )
endif()

if(VALIDATE_PSA_IMPORT_KEY_PAIR AND VALIDATE_PSA_IMPORT_CERT)
    list(APPEND EL2GO_IMPORT_BLOB_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/psa/el2go_import_blob_validate_cert.c
    )
endif()
