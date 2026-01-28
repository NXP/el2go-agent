cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(el2go_agent VERSION ${CMAKE_PROJECT_VERSION} LANGUAGES C)

# IoT Agent demo
add_executable(${PROJECT_NAME} src/iot_agent_demo.c)
target_link_libraries(${PROJECT_NAME} PRIVATE el2go_agent_lib)

# Installation rules
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
)