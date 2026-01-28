# Main core object library with agent logic
add_library(el2go_agent_core OBJECT
    el2go_agent.c
)

target_include_directories(el2go_agent_core
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/priv
)