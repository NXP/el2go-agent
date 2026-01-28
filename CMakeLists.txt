cmake_minimum_required(VERSION 3.15)
project(NXPIotAgent VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Include standard installation directories
include(GNUInstallDirs)

# Build shared library by default
option(BUILD_SHARED_LIBS "Build shared libraries" ON)

# Enable compiler warnings
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra)
    option(ENABLE_WERROR "Treat warnings as errors" ON)
    if(ENABLE_WERROR)
        add_compile_options(-Werror)
    endif()
endif()

# Add subdirectories
add_subdirectory(src)
add_subdirectory(examples)