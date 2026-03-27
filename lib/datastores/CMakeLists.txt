# Main datastore object library with common interface
add_library(el2go_agent_datastore OBJECT
    el2go_agent_datastore.c
)

target_include_directories(el2go_agent_datastore
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/priv
        ${CMAKE_SOURCE_DIR}/lib/osal/include
)