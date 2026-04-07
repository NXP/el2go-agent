# Platform object library
add_library(el2go_platform OBJECT
    el2go_platform.c
)

target_include_directories(el2go_platform
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/priv
        ${CMAKE_SOURCE_DIR}/lib/osal/include
        ${CMAKE_CURRENT_SOURCE_DIR}
)