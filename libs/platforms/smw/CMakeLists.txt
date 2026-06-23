# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# Find SMW library
find_package(NXP_SMW REQUIRED)
if(NXP_SMW_FOUND)
    message(STATUS "Found NXP SMW at ${NXP_SMW_DIR}")
endif()

# Add SMW platform sources directly to parent target
target_sources(el2go_platform PRIVATE
    smw_platform.c
    smw_crypto_params.c
)

# Make SMW target globally visible
set_target_properties(NXP_SMW::smw PROPERTIES IMPORTED_GLOBAL TRUE)

target_link_libraries(el2go_platform PUBLIC NXP_SMW::smw)
