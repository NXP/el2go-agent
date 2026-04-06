# Test registration for unit tests

# Helper function to register a test with properties
function(add_unit_test TEST_NAME EXECUTABLE SUITE TYPE)
    # Register the test
    add_test(${TEST_NAME} ${EXECUTABLE} --suite=${SUITE})

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

# Register internal tests with CTest
add_unit_test(unit_internal_platform ${INTERNAL_TEST_EXECUTABLE} platform internal)
add_unit_test(unit_internal_el2go_rtp ${INTERNAL_TEST_EXECUTABLE} el2go_rtp internal)
add_unit_test(unit_internal_datastore ${INTERNAL_TEST_EXECUTABLE} datastore internal)
add_unit_test(unit_internal_keystore ${INTERNAL_TEST_EXECUTABLE} keystore internal)