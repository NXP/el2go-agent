# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# Internal test sources
set(INTERNAL_TEST_SOURCES
        ${INTERNAL_TEST_SOURCES}
        ${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_rtp_internal.c
        ${CMAKE_CURRENT_SOURCE_DIR}/rtp_test_utils.c
        ${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_service_internal.c
        ${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_rtp_dispatch.c
	# Add more internal test files here as needed
	PARENT_SCOPE
)