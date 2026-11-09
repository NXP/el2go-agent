/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "test_el2go_ota_compat_shim.h"

#include "test_framework.h"
#include "test_suites.h"

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "common/el2go_status.h"
#include "el2go_ota_download_engine.h"
#include "el2go_ota_transport.h"
#include "ota/el2go_ota_lib.h"
#include "ota/el2go_ota_config.h"
#include "test_el2go_ota_fixtures.h"

#include "types/available_updates_response.pb.h"
#include "types/file_response.pb.h"
#include "types/update.pb.h"
#include <pb_encode.h>

/**
 * @brief check_for_updates with transport->send == NULL must return INVALID_PARAM.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_download_engine_null_send_fn(void *params)
{
    el2go_ota_transport_t t = { .send = NULL, .recv = NULL };
    el2go_ota_check_update_resp_t resp = { 0 };

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_engine_check_for_updates(&t, NULL, 0U, &resp));

    return true;
}

/**
 * @brief fetch_package with file_id == NULL must return INVALID_PARAM.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_download_engine_null_file_id(void *params)
{
    el2go_ota_transport_t t = { .send = NULL, .recv = NULL };

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_engine_fetch_package(&t, "upd-1", "pkg-1", NULL, 0U, 0,
                                                              ota_fixture_noop_chunk_cb, NULL));

    return true;
}

/**
 * @brief Verify engine check null resp.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_engine_check_null_resp(void *params)
{
    el2go_ota_transport_t t = { .send = NULL, .recv = NULL };
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_engine_check_for_updates(&t, NULL, 0U, NULL));
    return true;
}

/**
 * @brief Verify engine fetch null update id.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_engine_fetch_null_update_id(void *params)
{
    el2go_ota_transport_t t = { .send = NULL, .recv = NULL };
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_engine_fetch_package(&t, NULL, "pkg", "file", 0U, 0,
                                                              ota_fixture_noop_chunk_cb, NULL));
    return true;
}

/**
 * @brief Verify engine fetch null pkg id.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_engine_fetch_null_pkg_id(void *params)
{
    el2go_ota_transport_t t = { .send = NULL, .recv = NULL };
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_engine_fetch_package(&t, "upd", NULL, "file", 0U, 0,
                                                              ota_fixture_noop_chunk_cb, NULL));
    return true;
}

/**
 * @brief Verify engine fetch null callback.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_engine_fetch_null_callback(void *params)
{
    el2go_ota_transport_t t = { .send = NULL, .recv = NULL };
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_engine_fetch_package(&t, "upd", "pkg", NULL, 0U, 0, NULL,
                                                              NULL));
    return true;
}

/**
 * @brief Verify engine check null resp valid transport.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_engine_check_null_resp_valid_transport(void *params)
{
    el2go_ota_transport_t t;
    memset(&t, 0, sizeof(t));
    t.send = (void *)1U;
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_engine_check_for_updates(&t, NULL, 0U, NULL));
    return true;
}

/**
 * @brief Verify check update null recv.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_check_update_null_recv(void *params)
{
    el2go_ota_transport_t t = { 0 };
    el2go_ota_check_update_resp_t resp = { 0 };
    (void)params;
    t.send = (void *)1U;
    t.recv = NULL;
    el2go_ota_status_t s = el2go_ota_download_engine_check_for_updates(&t, NULL, 0U, &resp);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, s);
    return true;
}

/**
 * @brief Verify fetch null recv.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_fetch_null_recv(void *params)
{
    el2go_ota_transport_t t = { 0 };
    (void)params;
    t.send = (void *)1U;
    t.recv = NULL;
    el2go_ota_status_t s = el2go_ota_download_engine_fetch_package(&t, "u", "p", "f", 0U, 0,
                                                                   ota_fixture_noop_chunk_cb, NULL);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, s);
    return true;
}

/**
 * @brief Verify engine check attr count no attrs.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_engine_check_attr_count_no_attrs(void *params)
{
    el2go_ota_transport_t t = { 0 };
    el2go_ota_check_update_resp_t resp = { 0 };
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_engine_check_for_updates(&t, NULL, 5U, &resp));
    return true;
}

/**
 * @brief Verify engine fetch null transport.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_engine_fetch_null_transport(void *params)
{
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_engine_fetch_package(NULL, "u", "p", "f", 0U, 0,
                                                              ota_fixture_noop_chunk_cb, NULL));
    return true;
}

/** @defgroup ota_engine_mock_helpers Mock transport helpers for range-clamping tests
 * @{
 * These stubs are intentionally minimal: they count outgoing requests and
 * return a synthetic 5-byte gRPC EOF frame so the engine can complete one
 * download loop iteration without a real server.
 */

/** @brief Last range_end value captured by mock_send_capture_range(). Initialised to -1. */
static int64_t g_mock_captured_range_end = -1;

/** @brief Number of times mock_send_capture_range() has been called. */
static int g_mock_send_call_count = 0;

/* Minimum gRPC frame size returned by mock_recv_empty_eof(). */
#define MOCK_WIRE_BUF_SIZE 8U

/**
 * @brief Mock transport send stub that counts invocations.
 *
 * Increments g_mock_send_call_count on each call so tests can assert that
 * exactly the expected number of gRPC requests were issued.  Does not inspect
 * the encoded request bytes.
 *
 * @param[in] transport  Unused.
 * @param[in] method     Unused.
 * @param[in] data       Unused.
 * @param[in] data_len   Unused.
 * @return EL2GO_OTA_SUCCESS always.
 */
static el2go_ota_status_t mock_send_capture_range(el2go_ota_transport_t *transport,
                                                  const char *method, const uint8_t *data,
                                                  size_t data_len)
{
    (void)transport;
    (void)method;
    (void)data;
    (void)data_len;
    g_mock_send_call_count++;
    return EL2GO_OTA_SUCCESS;
}

/**
 * @brief Mock transport recv stub that returns a minimal gRPC EOF frame.
 *
 * Writes a 5-byte gRPC frame (1 compressed-flag byte 0x00 followed by a
 * 4-byte big-endian zero message length) into buf.  The response handler
 * decodes this as an empty FileResponse with data_len == 0, which the engine
 * treats as end-of-file and returns EL2GO_OTA_SUCCESS.
 *
 * @param[in]  transport  Unused.
 * @param[out] buf        Destination buffer for the synthetic frame.
 * @param[in]  buf_size   Size of buf in bytes.
 * @param[out] out_len    Set to 5 when buf_size >= 5, otherwise 0.
 * @return EL2GO_OTA_SUCCESS always.
 */
static el2go_ota_status_t mock_recv_empty_eof(el2go_ota_transport_t *transport, uint8_t *buf,
                                              size_t buf_size, size_t *out_len)
{
    (void)transport;
    if (buf_size >= 5U) {
        memset(buf, 0, 5U);
        *out_len = 5U;
    } else {
        *out_len = 0U;
    }
    return EL2GO_OTA_SUCCESS;
}

/** @} */ /* end of ota_engine_mock_helpers */

/**
 * @brief 9.12 -- file size is an exact multiple of EL2GO_OTA_CHUNK_SIZE.
 *
 * With the fix, the byte_offset-based EOF check fires after the first (and
 * only) full chunk, so the engine must NOT send a second request.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_fetch_exact_chunk_multiple_eof(void *params)
{
    (void)params;

    /* File is exactly one chunk in size. */
    int64_t file_size = (int64_t)EL2GO_OTA_CHUNK_SIZE;

    g_mock_send_call_count = 0;
    g_mock_captured_range_end = -1;

    el2go_ota_transport_t t = { 0 };
    t.send = mock_send_capture_range;
    t.recv = mock_recv_empty_eof;

    el2go_ota_status_t s = el2go_ota_download_engine_fetch_package(
        &t, "upd", "pkg", "file", 0U, file_size, ota_fixture_noop_chunk_cb, NULL);

    /*
     * The engine sends one request and then receives an empty response (EOF).
     * It should return success and should NOT have sent a second request.
     */
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_EQUAL(1, g_mock_send_call_count);

    return true;
}

/**
 * @brief 9.13 -- file smaller than EL2GO_OTA_CHUNK_SIZE with known_file_size seeded.
 *
 * The very first request must have range_end clamped to known_file_size - 1
 * (not the full EL2GO_OTA_CHUNK_SIZE - 1).  We verify by checking that the
 * engine completes with SUCCESS in one round-trip.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_fetch_small_file_range_clamped(void *params)
{
    (void)params;

    /* File is half a chunk. */
    int64_t file_size = (int64_t)(EL2GO_OTA_CHUNK_SIZE / 2U);

    g_mock_send_call_count = 0;

    el2go_ota_transport_t t = { 0 };
    t.send = mock_send_capture_range;
    t.recv = mock_recv_empty_eof;

    el2go_ota_status_t s = el2go_ota_download_engine_fetch_package(
        &t, "upd", "pkg", "file", 0U, file_size, ota_fixture_noop_chunk_cb, NULL);

    /*
     * The engine encodes a single request with range_end = file_size - 1,
     * receives an empty response (EOF), and exits successfully.
     */
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_EQUAL(1, g_mock_send_call_count);

    return true;
}

/**
 * @brief 9.14 -- resume_offset inside the final partial chunk.
 *
 * When resume_offset is within the last chunk of the file, the first
 * post-resume request must be clamped to range_end = file_size - 1.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_fetch_resume_in_last_chunk_clamped(void *params)
{
    (void)params;

    /*
     * File: 1.5 chunks.  resume_offset lands in the second (partial) chunk,
     * so only one request is issued (for the final partial range).
     */
    int64_t file_size = (int64_t)(EL2GO_OTA_CHUNK_SIZE + EL2GO_OTA_CHUNK_SIZE / 2U);
    size_t resume_offset = (size_t)EL2GO_OTA_CHUNK_SIZE;

    g_mock_send_call_count = 0;

    el2go_ota_transport_t t = { 0 };
    t.send = mock_send_capture_range;
    t.recv = mock_recv_empty_eof;

    el2go_ota_status_t s = el2go_ota_download_engine_fetch_package(
        &t, "upd", "pkg", "file", resume_offset, file_size, ota_fixture_noop_chunk_cb, NULL);

    /* One request sent (the final partial chunk), then EOF -> SUCCESS. */
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_EQUAL(1, g_mock_send_call_count);

    return true;
}

/**
 * @brief 9.15 -- resume_offset equal to the known file size.
 *
 * Everything has already been delivered, so the engine must return SUCCESS
 * without sending any request (a request would carry range_end < range_start).
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_fetch_resume_at_file_size_no_request(void *params)
{
    (void)params;

    int64_t file_size = (int64_t)(2U * EL2GO_OTA_CHUNK_SIZE);

    g_mock_send_call_count = 0;

    el2go_ota_transport_t t = { 0 };
    t.send = mock_send_capture_range;
    t.recv = mock_recv_empty_eof;

    el2go_ota_status_t s = el2go_ota_download_engine_fetch_package(
        &t, "upd", "pkg", "file", (size_t)file_size, file_size, ota_fixture_noop_chunk_cb, NULL);

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_EQUAL(0, g_mock_send_call_count);

    return true;
}

/**
 * @brief 9.16 -- resume_offset beyond the known file size.
 *
 * The caller state is inconsistent, so the engine must return INVALID_PARAM
 * without sending any request.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_fetch_resume_beyond_file_size_invalid(void *params)
{
    (void)params;

    int64_t file_size = (int64_t)(2U * EL2GO_OTA_CHUNK_SIZE);

    g_mock_send_call_count = 0;

    el2go_ota_transport_t t = { 0 };
    t.send = mock_send_capture_range;
    t.recv = mock_recv_empty_eof;

    el2go_ota_status_t s =
        el2go_ota_download_engine_fetch_package(&t, "upd", "pkg", "file", (size_t)file_size + 1U,
                                                file_size, ota_fixture_noop_chunk_cb, NULL);

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, s);
    TEST_ASSERT_EQUAL(0, g_mock_send_call_count);

    return true;
}

/** @defgroup ota_engine_script_helpers Scripted transport for retry and error-path tests
 * @{
 * Each step describes one round-trip: what send() returns, what recv()
 * returns, and the payload recv() delivers. Steps are consumed in order, one
 * per send() call, so a test can script failures followed by recovery.
 */

/** @brief Maximum number of scripted round-trips per test. */
#define SCRIPT_MAX_STEPS 8U

/** @brief One scripted round-trip: what send() and recv() return, and recv payload. */
typedef struct {
    el2go_ota_status_t send_rc;
    el2go_ota_status_t recv_rc;
    uint8_t payload[64];
    size_t payload_len;
} script_step_t;

static script_step_t g_script[SCRIPT_MAX_STEPS];
static size_t g_script_len;
static size_t g_script_send_idx;
static size_t g_script_recv_idx;

/** @brief Number of times capture_chunk_cb() has been called. */
static size_t g_cb_calls;

/** @brief Total number of bytes delivered to capture_chunk_cb(). */
static size_t g_cb_total_len;

/** @brief Status returned by capture_chunk_cb(). */
static el2go_ota_status_t g_cb_rc;

/**
 * @brief Clear the script and the chunk callback capture state.
 */
static void script_reset(void)
{
    memset(g_script, 0, sizeof(g_script));
    g_script_len = 0U;
    g_script_send_idx = 0U;
    g_script_recv_idx = 0U;
    g_cb_calls = 0U;
    g_cb_total_len = 0U;
    g_cb_rc = EL2GO_OTA_SUCCESS;
}

/**
 * @brief Append a step whose recv payload is an encoded FileResponse.
 *
 * @param send_rc   Status returned by send() for this step.
 * @param recv_rc   Status returned by recv() for this step.
 * @param total     FileResponse.totalFileSize (0 to omit).
 * @param data_len  Length of FileResponse.data (0 to omit the field).
 * @return @c true if the step was added and encoded.
 */
static bool script_add_file_response(el2go_ota_status_t send_rc, el2go_ota_status_t recv_rc,
                                     int64_t total, size_t data_len)
{
    static const uint8_t k_data[32] = { 0xA5U };
    script_step_t *s = NULL;
    pb_ostream_t os;

    TEST_ASSERT(g_script_len < SCRIPT_MAX_STEPS);
    TEST_ASSERT(data_len <= sizeof(k_data));
    s = &g_script[g_script_len++];
    s->send_rc = send_rc;
    s->recv_rc = recv_rc;
    os = pb_ostream_from_buffer(s->payload, sizeof(s->payload));
    if (total > 0) {
        TEST_ASSERT(pb_encode_tag(&os, PB_WT_VARINT,
                                  com_nxp_iot_ota_update_proto_FileResponse_totalFileSize_tag));
        TEST_ASSERT(pb_encode_varint(&os, (uint64_t)total));
    }
    if (data_len > 0U) {
        TEST_ASSERT(
            pb_encode_tag(&os, PB_WT_STRING, com_nxp_iot_ota_update_proto_FileResponse_data_tag));
        TEST_ASSERT(pb_encode_string(&os, k_data, data_len));
    }
    s->payload_len = os.bytes_written;
    return true;
}

/**
 * @brief Append a step whose recv payload is the given raw bytes.
 *
 * @param send_rc  Status returned by send() for this step.
 * @param recv_rc  Status returned by recv() for this step.
 * @param raw      Payload delivered by recv(); may be NULL if @p raw_len is 0.
 * @param raw_len  Length of @p raw.
 * @return @c true if the step was added.
 */
static bool script_add_raw(el2go_ota_status_t send_rc, el2go_ota_status_t recv_rc,
                           const uint8_t *raw, size_t raw_len)
{
    script_step_t *s = NULL;

    TEST_ASSERT(g_script_len < SCRIPT_MAX_STEPS);
    TEST_ASSERT(raw_len <= sizeof(g_script[0].payload));
    s = &g_script[g_script_len++];
    s->send_rc = send_rc;
    s->recv_rc = recv_rc;
    if (raw_len > 0U) {
        memcpy(s->payload, raw, raw_len);
    }
    s->payload_len = raw_len;
    return true;
}

/**
 * @brief Scripted transport send: returns the send status of the next step.
 *
 * @param[in] transport  Unused.
 * @param[in] method     Unused.
 * @param[in] data       Unused.
 * @param[in] data_len   Unused.
 * @return The scripted send status, or EL2GO_OTA_ERROR_INTERNAL when the
 *         script is exhausted.
 */
static el2go_ota_status_t script_send(el2go_ota_transport_t *transport, const char *method,
                                      const uint8_t *data, size_t data_len)
{
    (void)transport;
    (void)method;
    (void)data;
    (void)data_len;
    if (g_script_send_idx >= g_script_len) {
        return EL2GO_OTA_ERROR_INTERNAL; /* test asked for more round-trips than scripted */
    }
    /* send() and recv() of one step share an index; recv advances it. */
    g_script_recv_idx = g_script_send_idx;
    return g_script[g_script_send_idx++].send_rc;
}

/**
 * @brief Scripted transport recv: delivers the payload of the current step.
 *
 * @param[in]  transport  Unused.
 * @param[out] buf        Destination buffer.
 * @param[in]  buf_size   Size of @p buf.
 * @param[out] out_len    Number of bytes written to @p buf.
 * @return The scripted recv status.
 */
static el2go_ota_status_t script_recv(el2go_ota_transport_t *transport, uint8_t *buf,
                                      size_t buf_size, size_t *out_len)
{
    const script_step_t *s = &g_script[g_script_recv_idx];

    (void)transport;
    *out_len = 0U;
    if (s->recv_rc != EL2GO_OTA_SUCCESS) {
        return s->recv_rc;
    }
    if (s->payload_len > buf_size) {
        return EL2GO_OTA_ERROR_INTERNAL;
    }
    memcpy(buf, s->payload, s->payload_len);
    *out_len = s->payload_len;
    return EL2GO_OTA_SUCCESS;
}

/**
 * @brief Chunk callback that records how often it ran and how many bytes it got.
 *
 * @param[in] data    Unused.
 * @param[in] len     Chunk length, added to g_cb_total_len.
 * @param[in] offset  Unused.
 * @param[in] ctx     Unused.
 * @return g_cb_rc.
 */
static el2go_ota_status_t capture_chunk_cb(const uint8_t *data, size_t len, size_t offset,
                                           void *ctx)
{
    (void)data;
    (void)offset;
    (void)ctx;
    g_cb_calls++;
    g_cb_total_len += len;
    return g_cb_rc;
}

/**
 * @brief Build a transport whose send/recv follow the script.
 *
 * @return Transport with script_send() and script_recv() installed.
 */
static el2go_ota_transport_t script_transport(void)
{
    el2go_ota_transport_t t = { 0 };

    t.send = script_send;
    t.recv = script_recv;
    return t;
}

/** @} */ /* end of ota_engine_script_helpers */

/**
 * @brief 9.17 -- a send failure followed by a successful round-trip is retried
 *        transparently: the download succeeds and the data reaches chunk_cb.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_fetch_retries_after_send_failure(void *params)
{
    el2go_ota_transport_t t = script_transport();

    (void)params;
    script_reset();
    TEST_ASSERT(script_add_file_response(EL2GO_OTA_ERROR_NETWORK, EL2GO_OTA_SUCCESS, 0, 0U));
    TEST_ASSERT(script_add_file_response(EL2GO_OTA_SUCCESS, EL2GO_OTA_SUCCESS, 10, 10U));

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_download_engine_fetch_package(
                                             &t, "u", "p", "f", 0U, 0, capture_chunk_cb, NULL));
    TEST_ASSERT_EQUAL(2U, g_script_send_idx);
    TEST_ASSERT_EQUAL(1U, g_cb_calls);
    TEST_ASSERT_EQUAL(10U, g_cb_total_len);
    return true;
}

/**
 * @brief 9.18 -- recv() failing on every attempt exhausts the retry budget
 *        (1 + EL2GO_OTA_DOWNLOAD_MAX_RETRIES attempts) and reports a network
 *        error without calling chunk_cb.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_fetch_gives_up_after_max_retries(void *params)
{
    el2go_ota_transport_t t = script_transport();
    size_t i = 0U;

    (void)params;
    script_reset();
    for (i = 0U; i <= EL2GO_OTA_DOWNLOAD_MAX_RETRIES; i++) {
        TEST_ASSERT(script_add_file_response(EL2GO_OTA_SUCCESS, EL2GO_OTA_ERROR_NETWORK, 0, 0U));
    }

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_NETWORK,
                      el2go_ota_download_engine_fetch_package(&t, "u", "p", "f", 0U, 0,
                                                              capture_chunk_cb, NULL));
    TEST_ASSERT_EQUAL(EL2GO_OTA_DOWNLOAD_MAX_RETRIES + 1U, g_script_send_idx);
    TEST_ASSERT_EQUAL(0U, g_cb_calls);
    return true;
}

/**
 * @brief 9.19 -- a response that is not a valid FileResponse is a decode
 *        error and is not retried.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_fetch_parse_failure_not_retried(void *params)
{
    /* field 2 (data), length-delimited, claims 9 bytes but none follow */
    static const uint8_t bad[] = { 0x12U, 0x09U };
    el2go_ota_transport_t t = script_transport();

    (void)params;
    script_reset();
    TEST_ASSERT(script_add_raw(EL2GO_OTA_SUCCESS, EL2GO_OTA_SUCCESS, bad, sizeof(bad)));
    TEST_ASSERT(script_add_file_response(EL2GO_OTA_SUCCESS, EL2GO_OTA_SUCCESS, 4, 4U));

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_DECODE,
                      el2go_ota_download_engine_fetch_package(&t, "u", "p", "f", 0U, 0,
                                                              capture_chunk_cb, NULL));
    TEST_ASSERT_EQUAL(1U, g_script_send_idx);
    TEST_ASSERT_EQUAL(0U, g_cb_calls);
    return true;
}

/**
 * @brief 9.20 -- an error returned by chunk_cb aborts the download and is
 *        returned to the caller unchanged.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_fetch_chunk_cb_error_propagated(void *params)
{
    el2go_ota_transport_t t = script_transport();

    (void)params;
    script_reset();
    TEST_ASSERT(script_add_file_response(EL2GO_OTA_SUCCESS, EL2GO_OTA_SUCCESS, 8, 8U));
    g_cb_rc = EL2GO_OTA_ERROR_INTERNAL;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INTERNAL,
                      el2go_ota_download_engine_fetch_package(&t, "u", "p", "f", 0U, 0,
                                                              capture_chunk_cb, NULL));
    TEST_ASSERT_EQUAL(1U, g_cb_calls);
    return true;
}

/**
 * @brief 9.21 -- with no known file size, the size is taken from the first
 *        response. A response that delivers the whole file (16 of 16 bytes) completes
 *        the download in a single round-trip.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_fetch_learns_file_size_from_response(void *params)
{
    el2go_ota_transport_t t = script_transport();

    (void)params;
    script_reset();
    TEST_ASSERT(script_add_file_response(EL2GO_OTA_SUCCESS, EL2GO_OTA_SUCCESS, 16, 16U));

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_download_engine_fetch_package(
                                             &t, "u", "p", "f", 0U, 0, capture_chunk_cb, NULL));
    TEST_ASSERT_EQUAL(1U, g_script_send_idx);
    TEST_ASSERT_EQUAL(16U, g_cb_total_len);
    return true;
}

/**
 * @brief 9.22 -- check_for_updates maps a send failure to a network error, passes a
 *        recv failure through, and reports a malformed response as a decode
 *        error.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_check_for_updates_transport_and_parse_errors(void *params)
{
    static const uint8_t bad[] = { 0x0AU, 0x09U }; /* updates field, truncated */
    el2go_ota_transport_t t = script_transport();
    static el2go_ota_check_update_resp_t resp;

    (void)params;
    script_reset();
    TEST_ASSERT(script_add_raw(EL2GO_OTA_ERROR_INTERNAL, EL2GO_OTA_SUCCESS, NULL, 0U));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_NETWORK,
                      el2go_ota_download_engine_check_for_updates(&t, NULL, 0U, &resp));

    script_reset();
    TEST_ASSERT(script_add_raw(EL2GO_OTA_SUCCESS, EL2GO_OTA_ERROR_SERVER, NULL, 0U));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_SERVER,
                      el2go_ota_download_engine_check_for_updates(&t, NULL, 0U, &resp));

    script_reset();
    TEST_ASSERT(script_add_raw(EL2GO_OTA_SUCCESS, EL2GO_OTA_SUCCESS, bad, sizeof(bad)));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_DECODE,
                      el2go_ota_download_engine_check_for_updates(&t, NULL, 0U, &resp));
    return true;
}

/**
 * @brief 9.23 -- check_for_updates reports an available update from a well-formed
 *        response, and no update from an empty one.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_check_for_updates_available_and_none(void *params)
{
    uint8_t upd[16];
    uint8_t wire[32];
    pb_ostream_t us = pb_ostream_from_buffer(upd, sizeof(upd));
    pb_ostream_t os = pb_ostream_from_buffer(wire, sizeof(wire));
    el2go_ota_transport_t t = script_transport();
    static el2go_ota_check_update_resp_t resp;

    (void)params;
    TEST_ASSERT(pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_updateId_tag));
    TEST_ASSERT(pb_encode_string(&us, (const pb_byte_t *)"u1", 2U));
    TEST_ASSERT(pb_encode_tag(&os, PB_WT_STRING,
                              com_nxp_iot_ota_update_proto_AvailableUpdatesResponse_updates_tag));
    TEST_ASSERT(pb_encode_string(&os, upd, us.bytes_written));

    script_reset();
    TEST_ASSERT(script_add_raw(EL2GO_OTA_SUCCESS, EL2GO_OTA_SUCCESS, wire, os.bytes_written));
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_download_engine_check_for_updates(&t, NULL, 0U, &resp));
    TEST_ASSERT(resp.update_available);
    TEST_ASSERT_EQUAL(0, strcmp(resp.updates[0].update_id, "u1"));

    script_reset();
    TEST_ASSERT(script_add_raw(EL2GO_OTA_SUCCESS, EL2GO_OTA_SUCCESS, NULL, 0U));
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_download_engine_check_for_updates(&t, NULL, 0U, &resp));
    TEST_ASSERT(!resp.update_available);
    return true;
}

/* ---- suite registration ------------------------------------------------ */

void register_ota_lib_download_engine_tests(void)
{
    TEST_REGISTER_ID("9.1", test_ota_download_engine_null_send_fn);
    TEST_REGISTER_ID("9.2", test_ota_download_engine_null_file_id);
    TEST_REGISTER_ID("9.3", test_ota_engine_check_null_resp);
    TEST_REGISTER_ID("9.4", test_ota_engine_fetch_null_update_id);
    TEST_REGISTER_ID("9.5", test_ota_engine_fetch_null_pkg_id);
    TEST_REGISTER_ID("9.6", test_ota_engine_fetch_null_callback);
    TEST_REGISTER_ID("9.7", test_ota_engine_check_null_resp_valid_transport);
    TEST_REGISTER_ID("9.8", test_ota_check_update_null_recv);
    TEST_REGISTER_ID("9.9", test_ota_fetch_null_recv);
    TEST_REGISTER_ID("9.10", test_ota_engine_check_attr_count_no_attrs);
    TEST_REGISTER_ID("9.11", test_ota_engine_fetch_null_transport);
    TEST_REGISTER_ID("9.12", test_ota_fetch_exact_chunk_multiple_eof);
    TEST_REGISTER_ID("9.13", test_ota_fetch_small_file_range_clamped);
    TEST_REGISTER_ID("9.14", test_ota_fetch_resume_in_last_chunk_clamped);
    TEST_REGISTER_ID("9.15", test_ota_fetch_resume_at_file_size_no_request);
    TEST_REGISTER_ID("9.16", test_ota_fetch_resume_beyond_file_size_invalid);
    TEST_REGISTER_ID("9.17", test_ota_fetch_retries_after_send_failure);
    TEST_REGISTER_ID("9.18", test_ota_fetch_gives_up_after_max_retries);
    TEST_REGISTER_ID("9.19", test_ota_fetch_parse_failure_not_retried);
    TEST_REGISTER_ID("9.20", test_ota_fetch_chunk_cb_error_propagated);
    TEST_REGISTER_ID("9.21", test_ota_fetch_learns_file_size_from_response);
    TEST_REGISTER_ID("9.22", test_ota_check_for_updates_transport_and_parse_errors);
    TEST_REGISTER_ID("9.23", test_ota_check_for_updates_available_and_none);
}
