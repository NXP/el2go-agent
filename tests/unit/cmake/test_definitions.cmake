# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# Test registration for unit tests

# Resolve the path used in add_test() for a test executable target.
# When CMAKE_INSTALL_PREFIX is explicitly set (e.g. by Yocto or build.sh with
# -DCMAKE_INSTALL_PREFIX=/usr) use the installed path so that ctest works after
# installation. Otherwise fall back to the build-directory path so that the
# tests can be run directly from the build tree without installing first.
function(_unit_test_installed_path OUT_VAR TARGET_NAME)
    if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
        set(${OUT_VAR} "$<TARGET_FILE:${TARGET_NAME}>" PARENT_SCOPE)
    else()
        set(${OUT_VAR}
            "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/$<TARGET_FILE_BASE_NAME:${TARGET_NAME}>"
            PARENT_SCOPE)
    endif()
endfunction()

# Helper function to register a test with properties
function(add_unit_test TEST_NAME EXECUTABLE SUITE TYPE)

    _unit_test_installed_path(_exec_path ${EXECUTABLE})
    add_test(NAME ${TEST_NAME} COMMAND ${_exec_path} --suite=${SUITE})

    # Set test properties
    set_tests_properties(${TEST_NAME}
        PROPERTIES
            TIMEOUT 30
            LABELS "unit;${TYPE};${SUITE}"
    )
endfunction()

# Register public API tests with CTest
add_unit_test(unit_public_platform ${PUBLIC_TEST_EXECUTABLE} platform public)
add_unit_test(unit_public_el2go_rtp ${PUBLIC_TEST_EXECUTABLE} el2go_rtp public)
add_unit_test(unit_public_datastore ${PUBLIC_TEST_EXECUTABLE} datastore public)
add_unit_test(unit_public_keystore ${PUBLIC_TEST_EXECUTABLE} keystore public)

if(BUILD_OTA)
    add_unit_test(unit_public_fwual ${PUBLIC_TEST_EXECUTABLE} fwual public)
    add_unit_test(unit_public_ota_lib ${PUBLIC_TEST_EXECUTABLE} ota_lib public)
    add_unit_test(unit_public_ota_agent_core ${PUBLIC_TEST_EXECUTABLE} ota_agent_core public)
    add_unit_test(unit_public_ota_agent_advanced ${PUBLIC_TEST_EXECUTABLE} ota_agent_advanced public)

    # OTA tests are disabled by default - enable explicitly with ctest -R <name>
    set_tests_properties(
        unit_public_fwual
        unit_public_ota_lib
        unit_public_ota_agent_core
        unit_public_ota_agent_advanced
        PROPERTIES DISABLED TRUE)
endif()

# Register internal tests with CTest
add_unit_test(unit_internal_platform ${INTERNAL_TEST_EXECUTABLE} platform internal)
add_unit_test(unit_internal_el2go_rtp ${INTERNAL_TEST_EXECUTABLE} el2go_rtp internal)
add_unit_test(unit_internal_datastore ${INTERNAL_TEST_EXECUTABLE} datastore internal)
add_unit_test(unit_internal_keystore ${INTERNAL_TEST_EXECUTABLE} keystore internal)
add_unit_test(unit_internal_net_crypto ${INTERNAL_TEST_EXECUTABLE} net_crypto internal)

if(BUILD_OTA)
    add_unit_test(unit_internal_fwual ${INTERNAL_TEST_EXECUTABLE} fwual internal)
    add_unit_test(unit_internal_ota_lib ${INTERNAL_TEST_EXECUTABLE} ota_lib internal)
    add_unit_test(unit_internal_ota_agent_core ${INTERNAL_TEST_EXECUTABLE} ota_agent_core internal)
    add_unit_test(unit_internal_ota_agent_advanced ${INTERNAL_TEST_EXECUTABLE} ota_agent_advanced internal)

    # OTA tests are disabled by default - enable explicitly with ctest -R <name>
    set_tests_properties(
        unit_internal_fwual
        unit_internal_ota_lib
        unit_internal_ota_agent_core
        unit_internal_ota_agent_advanced
        PROPERTIES DISABLED TRUE)
endif()
