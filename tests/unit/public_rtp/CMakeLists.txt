# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# Public API test sources
set(PUBLIC_TEST_SOURCES
	${PUBLIC_TEST_SOURCES}
	${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_rtp_public.c
	${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_rtp_provision.c
	# Add more public test files here as needed
	PARENT_SCOPE
)
