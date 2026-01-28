# Keystore object library
add_library(el2go_agent_keystore OBJECT
    el2go_agent_keystore.c
)

target_include_directories(el2go_agent_keystore
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/priv
        ${CMAKE_CURRENT_SOURCE_DIR}
)