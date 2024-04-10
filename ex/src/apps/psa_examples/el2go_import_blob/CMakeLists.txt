# Copyright 2024 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

target_sources(app
    PRIVATE
        el2go_import_blob.c
        el2go_psa_import.c
)

target_include_directories(app PRIVATE .)
    