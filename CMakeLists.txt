cmake_minimum_required(VERSION 3.15)
project(NXPIotAgent VERSION 0.1 LANGUAGES C)

# Include standard installation directories
include(GNUInstallDirs)

# Build shared library by default
option(BUILD_SHARED_LIBS "Build shared libraries" ON)

# Option to build applications
option(BUILD_APPLICATIONS "Build applications" ON)

# Enable compiler warnings
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra)
    option(ENABLE_WERROR "Treat warnings as errors" ON)
    if(ENABLE_WERROR)
        add_compile_options(-Werror)
    endif()
endif()

# Add library subdirectory
add_subdirectory(lib)

# Add applications if enabled
if(BUILD_APPLICATIONS)
    add_subdirectory(applications)
endif()
