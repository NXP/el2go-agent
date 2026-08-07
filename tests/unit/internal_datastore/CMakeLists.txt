# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# Internal test sources
set(INTERNAL_TEST_SOURCES
	${INTERNAL_TEST_SOURCES}
	${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_datastore_internal.c
	${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_datastore_handle_request.c
	${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_datastore_get_size.c
	PARENT_SCOPE
)
