/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>

#include "test_framework.h"
#include "test_utils.h"

#include "osal.h"

#include "common/el2go_keystore.h"
#include "test_el2go_keystore_internal_common.h"

#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include "Dispatcher.pb.h"
#include "Agent.pb.h"
#include "PSA.pb.h"

/** @defgroup test_el2go_keystore_internal_psa Internal Keystore PSA Tests
 * @brief Unit tests for PSA-specific keystore functionality.
 * @{
 */

/**
 * @brief Test PSA keystore initialization with a specific ID.
 *
 * Uses the common test function to verify PSA keystore initialization.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_psa_keystore_init_with_id(void *params)
{
    (void)params;

    /* Test PSA keystore initialization */
    return common_test_keystore_init_with_id(0x50000000, EL2GO_KEYSTORE_PSA);
}

/**
 * @brief Test handle_request with NULL keystore.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_handle_request_null_keystore(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    pb_istream_t input_stream = { 0 };
    pb_ostream_t output_stream = { 0 };
    bool test_status = true;

    (void)params;

    status = el2go_keystore_handle_request(NULL, nxp_iot_PsaRequest_fields, &input_stream,
                                           &output_stream);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER, status);

    return test_status;
}

/**
 * @brief Test handle_request with NULL input stream.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_handle_request_null_input_stream(void *params)
{
    el2go_keystore_t keystore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    pb_ostream_t output_stream = { 0 };
    bool test_status = true;

    (void)params;

    status = el2go_keystore_init(0x50000000, NULL, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status =
        el2go_keystore_handle_request(&keystore, nxp_iot_PsaRequest_fields, NULL, &output_stream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

exit:
    el2go_keystore_free(&keystore);
    return test_status;
}

/**
 * @brief Test handle_request with NULL output stream.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_handle_request_null_output_stream(void *params)
{
    el2go_keystore_t keystore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    pb_istream_t input_stream = { 0 };
    bool test_status = true;

    (void)params;

    status = el2go_keystore_init(0x50000000, NULL, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status =
        el2go_keystore_handle_request(&keystore, nxp_iot_PsaRequest_fields, &input_stream, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

exit:
    el2go_keystore_free(&keystore);
    return test_status;
}

/**
 * @brief Test handle_request with NULL message type.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_handle_request_null_message_type(void *params)
{
    el2go_keystore_t keystore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    pb_istream_t input_stream = { 0 };
    pb_ostream_t output_stream = { 0 };
    bool test_status = true;

    (void)params;

    status = el2go_keystore_init(0x50000000, NULL, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_keystore_handle_request(&keystore, NULL, &input_stream, &output_stream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

exit:
    el2go_keystore_free(&keystore);
    return test_status;
}

/**
 * @brief Test handle_request with unsupported message type.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_handle_request_unsupported_message_type(void *params)
{
    el2go_keystore_t keystore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    pb_istream_t input_stream = { 0 };
    pb_ostream_t output_stream = { 0 };
    bool test_status = true;

    (void)params;

    status = el2go_keystore_init(0x50000000, NULL, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Use a different message type (not PsaRequest) */
    status = el2go_keystore_handle_request(&keystore, nxp_iot_ResponsePayload_fields, &input_stream,
                                           &output_stream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_UNSUPPORTED_OPERATION, status, exit);

exit:
    el2go_keystore_free(&keystore);
    return test_status;
}

/**
 * @brief Test handle_request with malformed protobuf data.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_handle_request_malformed_protobuf(void *params)
{
    el2go_keystore_t keystore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t bad_data[] = { 0xFF, 0xFF, 0xFF, 0xFF };
    pb_istream_t input_stream = pb_istream_from_buffer(bad_data, sizeof(bad_data));
    uint8_t output_buffer[256] = { 0 };
    pb_ostream_t output_stream = pb_ostream_from_buffer(output_buffer, sizeof(output_buffer));
    bool test_status = true;

    (void)params;

    status = el2go_keystore_init(0x50000000, NULL, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_keystore_handle_request(&keystore, nxp_iot_PsaRequest_fields, &input_stream,
                                           &output_stream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_REQUEST, status, exit);

exit:
    el2go_keystore_free(&keystore);
    return test_status;
}

/**
 * @brief Test handle_request with unknown command type.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_handle_request_unknown_command(void *params)
{
    el2go_keystore_t keystore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    nxp_iot_PsaRequest request = nxp_iot_PsaRequest_init_default;
    uint8_t encode_buffer[256] = { 0 };
    pb_ostream_t encode_stream = pb_ostream_from_buffer(encode_buffer, sizeof(encode_buffer));
    pb_istream_t input_stream = { 0 };
    uint8_t output_buffer[256] = { 0 };
    pb_ostream_t output_stream = pb_ostream_from_buffer(output_buffer, sizeof(output_buffer));
    bool test_status = true;

    (void)params;

    status = el2go_keystore_init(0x50000000, NULL, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Create request with unknown command */
    request.which_command = (pb_size_t)99; /* Invalid command */

    /* Encode the request */
    TEST_ASSERT_GOTO(pb_encode_delimited(&encode_stream, nxp_iot_PsaRequest_fields, &request),
                     exit);

    /* Create input stream from encoded data */
    input_stream = pb_istream_from_buffer(encode_buffer, encode_stream.bytes_written);

    status = el2go_keystore_handle_request(&keystore, nxp_iot_PsaRequest_fields, &input_stream,
                                           &output_stream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_UNSUPPORTED_OPERATION, status, exit);

exit:
    el2go_keystore_free(&keystore);
    return test_status;
}

/**
 * @brief Test destroy_key with missing identifier.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_destroy_key_missing_identifier(void *params)
{
    el2go_keystore_t keystore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    nxp_iot_PsaRequest request = nxp_iot_PsaRequest_init_default;
    uint8_t encode_buffer[256] = { 0 };
    pb_ostream_t encode_stream = pb_ostream_from_buffer(encode_buffer, sizeof(encode_buffer));
    pb_istream_t input_stream = { 0 };
    uint8_t output_buffer[256] = { 0 };
    pb_ostream_t output_stream = pb_ostream_from_buffer(output_buffer, sizeof(output_buffer));
    bool test_status = true;

    (void)params;

    status = el2go_keystore_init(0x50000000, NULL, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Create destroy_key request without identifier */
    request.which_command = nxp_iot_PsaRequest_destroy_key_tag;
    request.command.destroy_key.has_identifier = false;

    /* Encode the request */
    TEST_ASSERT_GOTO(pb_encode_delimited(&encode_stream, nxp_iot_PsaRequest_fields, &request),
                     exit);

    /* Create input stream from encoded data */
    input_stream = pb_istream_from_buffer(encode_buffer, encode_stream.bytes_written);

    status = el2go_keystore_handle_request(&keystore, nxp_iot_PsaRequest_fields, &input_stream,
                                           &output_stream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_REQUEST, status, exit);

exit:
    el2go_keystore_free(&keystore);
    return test_status;
}

/**
 * @brief Test import_key with missing required fields.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_import_key_missing_fields(void *params)
{
    el2go_keystore_t keystore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    nxp_iot_PsaRequest request = nxp_iot_PsaRequest_init_default;
    uint8_t encode_buffer[256] = { 0 };
    pb_ostream_t encode_stream = pb_ostream_from_buffer(encode_buffer, sizeof(encode_buffer));
    pb_istream_t input_stream = { 0 };
    uint8_t output_buffer[256] = { 0 };
    pb_ostream_t output_stream = pb_ostream_from_buffer(output_buffer, sizeof(output_buffer));
    bool test_status = true;

    (void)params;

    status = el2go_keystore_init(0x50000000, NULL, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Create import_key request with missing fields */
    request.which_command = nxp_iot_PsaRequest_import_key_tag;
    request.command.import_key.has_identifier = true;
    request.command.import_key.identifier = 1;
    /* Missing: type, usage, algorithm, key_data_format, lifetime, data */

    /* Encode the request */
    TEST_ASSERT_GOTO(pb_encode_delimited(&encode_stream, nxp_iot_PsaRequest_fields, &request),
                     exit);

    /* Create input stream from encoded data */
    input_stream = pb_istream_from_buffer(encode_buffer, encode_stream.bytes_written);

    status = el2go_keystore_handle_request(&keystore, nxp_iot_PsaRequest_fields, &input_stream,
                                           &output_stream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_REQUEST, status, exit);

exit:
    el2go_keystore_free(&keystore);
    return test_status;
}

/**
 * @brief Test import_key with zero-size key data.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */

static bool test_import_key_zero_size(void *params)
{
    el2go_keystore_t keystore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    nxp_iot_PsaRequest request = nxp_iot_PsaRequest_init_default;
    uint8_t encode_buffer[256] = { 0 };
    pb_ostream_t encode_stream = pb_ostream_from_buffer(encode_buffer, sizeof(encode_buffer));
    pb_istream_t input_stream = { 0 };
    uint8_t output_buffer[256] = { 0 };
    pb_ostream_t output_stream = pb_ostream_from_buffer(output_buffer, sizeof(output_buffer));
    PB_BYTES_ARRAY_T(1) key_data = { .size = 0 };
    bool test_status = true;

    (void)params;

    status = el2go_keystore_init(0x50000000, NULL, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Create import_key request with zero-size data */
    request.which_command = nxp_iot_PsaRequest_import_key_tag;
    request.command.import_key.has_identifier = true;
    request.command.import_key.identifier = 1;
    request.command.import_key.has_type = true;
    request.command.import_key.type = 0x1000;
    request.command.import_key.has_usage = true;
    request.command.import_key.usage = 0x01;
    request.command.import_key.has_algorithm = true;
    request.command.import_key.algorithm = 0x06000100;
    request.command.import_key.has_key_data_format = true;
    request.command.import_key.key_data_format = nxp_iot_KeyDataFormat_S50;
    request.command.import_key.has_lifetime = true;
    request.command.import_key.lifetime = 0x00000001;
    request.command.import_key.data = (pb_bytes_array_t *)&key_data;

    /* Encode the request */
    TEST_ASSERT_GOTO(pb_encode_delimited(&encode_stream, nxp_iot_PsaRequest_fields, &request),
                     exit);

    /* Create input stream from encoded data */
    input_stream = pb_istream_from_buffer(encode_buffer, encode_stream.bytes_written);

    status = el2go_keystore_handle_request(&keystore, nxp_iot_PsaRequest_fields, &input_stream,
                                           &output_stream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_REQUEST, status, exit);

exit:
    el2go_keystore_free(&keystore);
    return test_status;
}

/**
 * @brief Test import_key with unsupported key data format.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_import_key_unsupported_key_format(void *params)
{
    el2go_keystore_t keystore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    nxp_iot_PsaRequest request = nxp_iot_PsaRequest_init_default;
    uint8_t encode_buffer[256] = { 0 };
    pb_ostream_t encode_stream = pb_ostream_from_buffer(encode_buffer, sizeof(encode_buffer));
    pb_istream_t input_stream = { 0 };
    uint8_t output_buffer[256] = { 0 };
    pb_ostream_t output_stream = pb_ostream_from_buffer(output_buffer, sizeof(output_buffer));
    PB_BYTES_ARRAY_T(32) key_data = { .size = 32 };
    bool test_status = true;

    (void)params;

    status = el2go_keystore_init(0x50000000, NULL, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Create import_key request with unsupported format */
    request.which_command = nxp_iot_PsaRequest_import_key_tag;
    request.command.import_key.has_identifier = true;
    request.command.import_key.identifier = 1;
    request.command.import_key.has_type = true;
    request.command.import_key.type = 0x1000;
    request.command.import_key.has_usage = true;
    request.command.import_key.usage = 0x01;
    request.command.import_key.has_algorithm = true;
    request.command.import_key.algorithm = 0x06000100;
    request.command.import_key.has_key_data_format = true;
    request.command.import_key.key_data_format = 999; /* Invalid format */
    request.command.import_key.has_lifetime = true;
    request.command.import_key.lifetime = 0x00000001;
    request.command.import_key.data = (pb_bytes_array_t *)&key_data;

    /* Encode the request */
    TEST_ASSERT_GOTO(pb_encode_delimited(&encode_stream, nxp_iot_PsaRequest_fields, &request),
                     exit);

    /* Create input stream from encoded data */
    input_stream = pb_istream_from_buffer(encode_buffer, encode_stream.bytes_written);

    status = el2go_keystore_handle_request(&keystore, nxp_iot_PsaRequest_fields, &input_stream,
                                           &output_stream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_REQUEST, status, exit);

exit:
    el2go_keystore_free(&keystore);
    return test_status;
}

/**
 * @brief Test read_object with missing identifier.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_read_object_missing_identifier(void *params)
{
    el2go_keystore_t keystore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    nxp_iot_PsaRequest request = nxp_iot_PsaRequest_init_default;
    uint8_t encode_buffer[256] = { 0 };
    pb_ostream_t encode_stream = pb_ostream_from_buffer(encode_buffer, sizeof(encode_buffer));
    pb_istream_t input_stream = { 0 };
    uint8_t output_buffer[256] = { 0 };
    pb_ostream_t output_stream = pb_ostream_from_buffer(output_buffer, sizeof(output_buffer));
    bool test_status = true;

    (void)params;

    status = el2go_keystore_init(0x50000000, NULL, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Create read_object request without identifier */
    request.which_command = nxp_iot_PsaRequest_read_object_tag;
    request.command.read_object.has_identifier = false;

    /* Encode the request */
    TEST_ASSERT_GOTO(pb_encode_delimited(&encode_stream, nxp_iot_PsaRequest_fields, &request),
                     exit);

    /* Create input stream from encoded data */
    input_stream = pb_istream_from_buffer(encode_buffer, encode_stream.bytes_written);

    status = el2go_keystore_handle_request(&keystore, nxp_iot_PsaRequest_fields, &input_stream,
                                           &output_stream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_REQUEST, status, exit);

exit:
    el2go_keystore_free(&keystore);
    return test_status;
}

/**
 * @brief Test remove_object with missing identifier.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_remove_object_missing_identifier(void *params)
{
    el2go_keystore_t keystore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    nxp_iot_PsaRequest request = nxp_iot_PsaRequest_init_default;
    uint8_t encode_buffer[256] = { 0 };
    pb_ostream_t encode_stream = pb_ostream_from_buffer(encode_buffer, sizeof(encode_buffer));
    pb_istream_t input_stream = { 0 };
    uint8_t output_buffer[256] = { 0 };
    pb_ostream_t output_stream = pb_ostream_from_buffer(output_buffer, sizeof(output_buffer));
    bool test_status = true;

    (void)params;

    status = el2go_keystore_init(0x50000000, NULL, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Create remove_object request without identifier */
    request.which_command = nxp_iot_PsaRequest_remove_object_tag;
    request.command.remove_object.has_identifier = false;

    /* Encode the request */
    TEST_ASSERT_GOTO(pb_encode_delimited(&encode_stream, nxp_iot_PsaRequest_fields, &request),
                     exit);

    /* Create input stream from encoded data */
    input_stream = pb_istream_from_buffer(encode_buffer, encode_stream.bytes_written);

    status = el2go_keystore_handle_request(&keystore, nxp_iot_PsaRequest_fields, &input_stream,
                                           &output_stream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_REQUEST, status, exit);

exit:
    el2go_keystore_free(&keystore);
    return test_status;
}

/**
 * @brief Test get_version command (positive case for coverage).
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_get_version_success(void *params)
{
    el2go_keystore_t keystore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    nxp_iot_PsaRequest request = nxp_iot_PsaRequest_init_default;
    uint8_t encode_buffer[256] = { 0 };
    pb_ostream_t encode_stream = pb_ostream_from_buffer(encode_buffer, sizeof(encode_buffer));
    pb_istream_t input_stream = { 0 };
    uint8_t output_buffer[256] = { 0 };
    pb_ostream_t output_stream = pb_ostream_from_buffer(output_buffer, sizeof(output_buffer));
    bool test_status = true;

    (void)params;

    status = el2go_keystore_init(0x50000000, NULL, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Create get_version request */
    request.which_command = nxp_iot_PsaRequest_get_version_tag;

    /* Encode the request */
    TEST_ASSERT_GOTO(pb_encode_delimited(&encode_stream, nxp_iot_PsaRequest_fields, &request),
                     exit);

    /* Create input stream from encoded data */
    input_stream = pb_istream_from_buffer(encode_buffer, encode_stream.bytes_written);

    status = el2go_keystore_handle_request(&keystore, nxp_iot_PsaRequest_fields, &input_stream,
                                           &output_stream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Verify response was written */
    TEST_ASSERT_GOTO(output_stream.bytes_written > 0, exit);

exit:
    el2go_keystore_free(&keystore);
    return test_status;
}

void register_keystore_specific_tests(void)
{
    /* Register PSA keystore initialization test */
    TEST_REGISTER(test_psa_keystore_init_with_id);

    /* Register handle_request parameter validation tests */
    TEST_REGISTER(test_handle_request_null_keystore);
    TEST_REGISTER(test_handle_request_null_input_stream);
    TEST_REGISTER(test_handle_request_null_output_stream);
    TEST_REGISTER(test_handle_request_null_message_type);
    TEST_REGISTER(test_handle_request_unsupported_message_type);
    TEST_REGISTER(test_handle_request_malformed_protobuf);
    TEST_REGISTER(test_handle_request_unknown_command);

    /* Register destroy_key negative tests */
    TEST_REGISTER(test_destroy_key_missing_identifier);

    /* Register import_key negative tests */
    TEST_REGISTER(test_import_key_missing_fields);
    TEST_REGISTER(test_import_key_zero_size);
    TEST_REGISTER(test_import_key_unsupported_key_format);

    /* Register read_object negative tests */
    TEST_REGISTER(test_read_object_missing_identifier);

    /* Register remove_object negative tests */
    TEST_REGISTER(test_remove_object_missing_identifier);

    /* Register positive test for coverage */
    TEST_REGISTER(test_get_version_success);
}

/** @} */ /* end of test_el2go_keystore_internal_psa */
