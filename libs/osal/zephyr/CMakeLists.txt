# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)

set(OSAL_SOURCES
    alloc.c
    osal.c
    print.c
    file.c
)

# el2go_uuid_zephyr.c provides osal_uuid() via hwinfo and replaces uuid.c
# when the RTP agent is enabled. Only one of the two may be compiled at a time
# to avoid conflicting definitions.
if(CONFIG_EL2GO_RTP_AGENT)
    list(APPEND OSAL_SOURCES el2go_uuid_zephyr.c)
else()
    list(APPEND OSAL_SOURCES uuid.c)
endif()

declare_library(osal)

add_private_sources(osal ${OSAL_SOURCES})

add_public_directories(osal
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

add_private_directories(osal
    ${CMAKE_CURRENT_SOURCE_DIR}
)
