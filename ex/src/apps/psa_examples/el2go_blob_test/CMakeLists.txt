# Copyright 2024 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

target_sources(app
    PRIVATE
        el2go_blob_test.c
        el2go_blob_test_external.c
        el2go_blob_test_internal.c
        el2go_blob_test_psa.c
)

target_include_directories(app PRIVATE .)
