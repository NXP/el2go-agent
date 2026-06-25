# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# Common keystore test sources
set(INTERNAL_TEST_SOURCES
	${INTERNAL_TEST_SOURCES}
	${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_keystore_internal_common.c
	${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_keystore_internal_${KEYSTORE}.c
	PARENT_SCOPE
)

