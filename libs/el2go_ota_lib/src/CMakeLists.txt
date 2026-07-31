# Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0

include(add_target_sources)

declare_library(el2go_ota_src)

add_private_sources(el2go_ota_src
    ${CMAKE_CURRENT_SOURCE_DIR}/el2go_ota_tls.c
    ${CMAKE_CURRENT_SOURCE_DIR}/el2go_ota_request_builder.c
    ${CMAKE_CURRENT_SOURCE_DIR}/el2go_ota_response_handler.c
    ${CMAKE_CURRENT_SOURCE_DIR}/el2go_ota_status_reporting.c
)

add_public_directories(el2go_ota_src
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_private_directories(el2go_ota_src
    ${PROJECT_ROOT}/priv
    ${PROJECT_ROOT}/include
    ${PROJECT_ROOT}/libs/osal/include
)

add_link_libraries(el2go_ota_src
    PRIVATE
        el2go_ota_transport
	net_crypto
	ota_protobuf
	el2go_ota_osal
	el2go_ota_cred
)

add_subdirectory(cred)
add_subdirectory(transport)
add_subdirectory(osal)
add_subdirectory(download)
