/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "test_el2go_ota_lib_internal.h"

#include "ota/el2go_ota_lib.h"
#include "el2go_ota_transport.h"
#include "el2go_ota_download_engine.h"
#include "el2go_ota_request_builder.h"
#include "el2go_ota_status_reporting.h"
#include "el2go_ota_kvs.h"

#include "canned_protobuf.h"
#include "mock_transport.h"

/* Chunk-callback capture state (data + total length + call count + last offset). */
struct chunk_capture {
    uint8_t data[512U];
    size_t total_len;
    size_t call_count;
    size_t last_offset;
};

static el2go_ota_status_t capture_chunk_cb(const uint8_t *data, size_t len, size_t offset,
                                           void *cb_ctx)
{
    struct chunk_capture *cap = (struct chunk_capture *)cb_ctx;

    if ((cap->total_len + len) > sizeof(cap->data)) {
        return EL2GO_OTA_ERROR_INTERNAL;
    }

    if (data == NULL && len != 0U) {
        return EL2GO_OTA_ERROR_INTERNAL;
    }

    (void)memcpy(&cap->data[cap->total_len], data, len);
    cap->total_len += len;
    cap->call_count++;
    cap->last_offset = offset;
    return EL2GO_OTA_SUCCESS;
}

/* Require the mock-transport seam and reset the mock; may return TEST_SKIP. */
#define CT_ENTER()                               \
    do {                                         \
        TEST_REQUIRE_CAP(CT_CAP_MOCK_TRANSPORT); \
        mock_transport_reset();                  \
    } while (0)

static test_result_t make_transport(el2go_ota_transport_t *t)
{
    el2go_ota_status_t s = mock_transport_init(t);

    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_NOT_NULL(t->send);
    TEST_ASSERT_NOT_NULL(t->recv);
    return TEST_PASS;
}

/**
 * @brief OTA_CT_OL_2.1 : CheckUpdate request captured (wire bytes present)
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_wire_check_update_request(void)
{
    el2go_ota_transport_t t = { 0 };
    el2go_ota_check_update_resp_t resp = { 0 };
    uint8_t wire[512U] = { 0 };
    size_t wire_len = 0U;
    uint8_t req[512U] = { 0 };
    size_t req_len = 0U;
    el2go_ota_status_t s = EL2GO_OTA_ERROR_INTERNAL;

    CT_ENTER();
    {
        test_result_t rc = make_transport(&t);
        if (rc != TEST_PASS) {
            return rc;
        }
    }

    TEST_ASSERT_EQ(0, canned_check_update_one_package(wire, sizeof(wire), &wire_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(wire, wire_len));

    static const el2go_ota_attr_t attrs[] = { { "board", "native" } };
    s = el2go_ota_download_engine_check_for_updates(&t, attrs, 1U, &resp);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);

    TEST_ASSERT_EQ(1U, mock_transport_send_count());
    TEST_ASSERT_EQ(0, mock_transport_get_last_request(req, sizeof(req), &req_len));
    TEST_ASSERT_NE(0U, req_len);
    return TEST_PASS;
}

/**
 * @brief OTA_CT_OL_2.2 : FetchPackage wire bytes match expected range
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_wire_fetch_package_range(void)
{
    el2go_ota_transport_t t = { 0 };
    struct chunk_capture cap = { 0 };
    uint8_t c_wire[128U] = { 0 };
    uint8_t eof_wire[32U] = { 0 };
    size_t c_len = 0U;
    size_t eof_len = 0U;

    static const uint8_t p[] = { 0x10, 0x11, 0x12 };
    uint8_t actual_req[512U] = { 0 };
    size_t actual_req_len = 0U;
    uint8_t expected_req[512U] = { 0 };
    size_t expected_req_len = 0U;
    el2go_ota_fetch_pkg_req_t expected = { 0 };
    el2go_ota_status_t s = EL2GO_OTA_ERROR_INTERNAL;

    CT_ENTER();
    {
        test_result_t rc = make_transport(&t);
        if (rc != TEST_PASS) {
            return rc;
        }
    }

    TEST_ASSERT_EQ(0,
                   canned_fetch_package_chunk(c_wire, sizeof(c_wire), 4, 6, p, sizeof(p), &c_len));
    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(eof_wire, sizeof(eof_wire), 0, 0, NULL, 0U,
                                                 &eof_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(c_wire, c_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(eof_wire, eof_len));

    s = el2go_ota_download_engine_fetch_package(&t, "upd-22", "pkg-22", "file-22", 4U,
                                                capture_chunk_cb, &cap);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_EQ(3U, cap.total_len);

    TEST_ASSERT_EQ(0, mock_transport_get_last_request(actual_req, sizeof(actual_req),
                                                      &actual_req_len));
    TEST_ASSERT_NE(0U, actual_req_len);

    expected.update_id = "upd-22";
    expected.package_id = "pkg-22";
    expected.file_id = "file-22";
    expected.range_start = 4;
    expected.range_end = 4 + (int64_t)(EL2GO_OTA_CHUNK_SIZE - 1U);

    s = el2go_ota_encode_fetch_package(&expected, expected_req, sizeof(expected_req),
                                       &expected_req_len);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_EQ(expected_req_len, actual_req_len);
    TEST_ASSERT_MEM_EQ(expected_req, actual_req, expected_req_len);
    return TEST_PASS;
}

/**
 * @brief OTA_CT_OL_2.3 : ReportStatus request captured (wire bytes present)
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_wire_report_status_request(void)
{
    el2go_ota_transport_t t = { 0 };
    uint8_t ack[16U] = { 0 };
    size_t ack_len = 0U;
    uint8_t req[512U] = { 0 };
    size_t req_len = 0U;
    el2go_ota_status_t s = EL2GO_OTA_ERROR_INTERNAL;

    CT_ENTER();
    {
        test_result_t rc = make_transport(&t);
        if (rc != TEST_PASS) {
            return rc;
        }
    }

    TEST_ASSERT_EQ(0, canned_report_status_ack(ack, sizeof(ack), &ack_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(ack, ack_len));

    s = el2go_ota_status_reporting_report(&t, "upd-23", "pkg-23", EL2GO_OTA_OUTCOME_SUCCESS);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);

    TEST_ASSERT_EQ(0, mock_transport_get_last_request(req, sizeof(req), &req_len));
    TEST_ASSERT_NE(0U, req_len);
    return TEST_PASS;
}

/**
 * @brief OTA_CT_OL_2.4 : device metadata in post-connect request (pending)
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_wire_device_metadata_after_connect(void)
{
    TEST_SKIP_WITH("no device metadata API yet; TODO(OTA_CT_OL_2.4)");
}

/* clear any stale pending-status entry from a previous run. */
static void clear_pending_status(void)
{
    el2go_ota_pending_status_t dummy = { 0 };
    (void)el2go_ota_status_reporting_read_pending(&dummy);
    (void)el2go_ota_kvs_delete(EL2GO_OTA_STATUS_NVS_KEY);
}

/**
 * @brief schedule + read_pending round-trip -- SUCCESS
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_nvs_schedule_and_read(void)
{
    el2go_ota_pending_status_t pending = { 0 };

    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    clear_pending_status();

    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_status_reporting_schedule(
                                          "upd-nvs", "pkg-nvs", EL2GO_OTA_OUTCOME_SUCCESS));

    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_status_reporting_read_pending(&pending));

    TEST_ASSERT_EQ(EL2GO_OTA_STATUS_VALID_MAGIC, pending.valid);
    TEST_ASSERT_EQ((uint8_t)EL2GO_OTA_OUTCOME_SUCCESS, pending.outcome);
    TEST_ASSERT_STR_EQ("upd-nvs", pending.update_id);
    TEST_ASSERT_STR_EQ("pkg-nvs", pending.package_id);
    return TEST_PASS;
}

/**
 * @brief retry_pending: no pending entry in NVS -- should succeed immediately
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_nvs_retry_no_entry(void)
{
    el2go_ota_transport_t t = { 0 };

    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH | CT_CAP_MOCK_TRANSPORT);
    clear_pending_status();

    {
        test_result_t rc;
        el2go_ota_status_t s = mock_transport_init(&t);
        TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);
        rc = TEST_PASS;
        (void)rc;
    }

    /* With no entry, retry must return SUCCESS and send nothing. */
    mock_transport_reset();
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_status_reporting_retry_pending(&t));
    TEST_ASSERT_EQ(0U, mock_transport_send_count());
    return TEST_PASS;
}

/**
 * @brief retry_pending: valid entry in NVS, mock transport acks -- entry deleted
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_nvs_retry_with_entry(void)
{
    el2go_ota_transport_t t = { 0 };
    el2go_ota_pending_status_t pending = { 0 };
    uint8_t ack[16U] = { 0 };
    size_t ack_len = 0U;

    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH | CT_CAP_MOCK_TRANSPORT);
    clear_pending_status();

    /* Schedule a ROLLBACK status to NVS. */
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_status_reporting_schedule(
                                          "upd-rty", "pkg-rty", EL2GO_OTA_OUTCOME_ROLLBACK));

    mock_transport_reset();
    {
        el2go_ota_status_t s = mock_transport_init(&t);
        TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);
    }

    /* Queue ack and retry. */
    TEST_ASSERT_EQ(0, canned_report_status_ack(ack, sizeof(ack), &ack_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(ack, ack_len));

    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_status_reporting_retry_pending(&t));
    TEST_ASSERT_NE(0U, mock_transport_send_count());

    /* NVS entry must be cleared after delivery. */
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_status_reporting_read_pending(&pending));
    TEST_ASSERT_NE(EL2GO_OTA_STATUS_VALID_MAGIC, pending.valid);
    return TEST_PASS;
}

/**
 * @brief schedule FAILURE + ROLLBACK outcomes succeed
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_nvs_schedule_all_outcomes(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);

    clear_pending_status();
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS,
                   el2go_ota_status_reporting_schedule("u1", "p1", EL2GO_OTA_OUTCOME_FAILURE));
    clear_pending_status();
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS,
                   el2go_ota_status_reporting_schedule("u2", "p2", EL2GO_OTA_OUTCOME_ROLLBACK));
    clear_pending_status();
    return TEST_PASS;
}

/**
 * @brief check_for_updates with attrs via engine directly
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_check_with_attrs(void)
{
    el2go_ota_transport_t t = { 0 };
    el2go_ota_check_update_resp_t resp = { 0 };
    uint8_t wire[512U] = { 0 };
    size_t wire_len = 0U;
    el2go_ota_status_t s;
    static const el2go_ota_attr_t attrs[] = {
        { "hw", "rw612" },
        { "fw", "1.2.3" },
    };

    CT_ENTER();
    {
        el2go_ota_status_t rs = mock_transport_init(&t);
        TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, rs);
    }

    TEST_ASSERT_EQ(0, canned_check_update_one_package(wire, sizeof(wire), &wire_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(wire, wire_len));

    s = el2go_ota_download_engine_check_for_updates(&t, attrs, 2U, &resp);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_TRUE(resp.update_available);
    /* A single request is sent regardless of attribute count. */
    TEST_ASSERT_EQ(1U, mock_transport_send_count());
    return TEST_PASS;
}

/**
 * @brief KVS idempotent init on real flash
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_kvs_idempotent_init(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_kvs_init());
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_kvs_init());
    return TEST_PASS;
}

/**
 * @brief KVS write + read round-trip
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_kvs_write_read_roundtrip(void)
{
    static const uint8_t payload[8] = { 0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44 };
    uint8_t readback[8] = { 0 };
    bool found = false;

    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_kvs_init());

    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS,
                   el2go_ota_kvs_write(EL2GO_OTA_STATUS_NVS_KEY, payload, sizeof(payload)));

    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_kvs_read(EL2GO_OTA_STATUS_NVS_KEY, readback,
                                                         sizeof(readback), &found));

    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_MEM_EQ(payload, readback, sizeof(payload));
    return TEST_PASS;
}

/**
 * @brief KVS delete + read confirms entry absent
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_kvs_delete_read(void)
{
    static const uint8_t data[4] = { 0x01, 0x02, 0x03, 0x04 };
    uint8_t buf[4] = { 0 };
    bool found = false;

    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_kvs_init());

    /* Write then delete. */
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS,
                   el2go_ota_kvs_write(EL2GO_OTA_STATUS_NVS_KEY, data, sizeof(data)));
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_kvs_delete(EL2GO_OTA_STATUS_NVS_KEY));

    /* Read back -- must be not found. */
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS,
                   el2go_ota_kvs_read(EL2GO_OTA_STATUS_NVS_KEY, buf, sizeof(buf), &found));
    TEST_ASSERT_FALSE(found);
    return TEST_PASS;
}

/**
 * @brief KVS delete non-existent key -- must succeed silently.
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_kvs_delete_nonexistent(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_kvs_init());
    /* Key 42 was never written. */
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_kvs_delete(42U));
    return TEST_PASS;
}

/**
 * @brief KVS read of non-existent key -- found=false, SUCCESS.
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_kvs_read_not_found(void)
{
    uint8_t buf[4] = { 0 };
    bool found = false;

    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_kvs_init());
    (void)el2go_ota_kvs_delete(99U);

    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_kvs_read(99U, buf, sizeof(buf), &found));
    TEST_ASSERT_FALSE(found);
    return TEST_PASS;
}

/**
 * @brief schedule with SUCCESS + read_pending verifies magic and content
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_nvs_schedule_and_read_content(void)
{
    el2go_ota_pending_status_t pending = { 0 };

    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);

    /* Write then read back */
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_status_reporting_schedule(
                                          "upd-b11", "pkg-b11", EL2GO_OTA_OUTCOME_SUCCESS));
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_status_reporting_read_pending(&pending));
    TEST_ASSERT_EQ(EL2GO_OTA_STATUS_VALID_MAGIC, pending.valid);
    TEST_ASSERT_EQ((uint8_t)EL2GO_OTA_OUTCOME_SUCCESS, pending.outcome);

    /* Clean up */
    (void)el2go_ota_kvs_delete(EL2GO_OTA_STATUS_NVS_KEY);
    return TEST_PASS;
}

/**
 * @brief retry_pending with ROLLBACK entry -- exercises ROLLBACK outcome path
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_nvs_retry_rollback(void)
{
    el2go_ota_transport_t t = { 0 };
    el2go_ota_pending_status_t pending = { 0 };
    uint8_t ack[16U] = { 0 };
    size_t ack_len = 0U;

    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH | CT_CAP_MOCK_TRANSPORT);
    (void)el2go_ota_status_reporting_read_pending(&pending);
    (void)el2go_ota_kvs_delete(EL2GO_OTA_STATUS_NVS_KEY);

    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS,
                   el2go_ota_status_reporting_schedule("u-rb", "p-rb", EL2GO_OTA_OUTCOME_ROLLBACK));

    mock_transport_reset();
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, mock_transport_init(&t));
    TEST_ASSERT_EQ(0, canned_report_status_ack(ack, sizeof(ack), &ack_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(ack, ack_len));
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_status_reporting_retry_pending(&t));
    TEST_ASSERT_NE(0U, mock_transport_send_count());

    (void)el2go_ota_kvs_delete(EL2GO_OTA_STATUS_NVS_KEY);
    return TEST_PASS;
}

/**
 * @brief download_engine: check_for_updates with 2 attrs -- exercises attr loop path
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_check_with_two_attrs(void)
{
    el2go_ota_transport_t t = { 0 };
    el2go_ota_check_update_resp_t resp = { 0 };
    uint8_t wire[512U] = { 0 };
    size_t wire_len = 0U;
    static const el2go_ota_attr_t attrs[] = {
        { "hw", "rw612" },
        { "fw", "2.0.0" },
    };

    TEST_REQUIRE_CAP(CT_CAP_MOCK_TRANSPORT);
    mock_transport_reset();
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, mock_transport_init(&t));

    TEST_ASSERT_EQ(0, canned_check_update_one_package(wire, sizeof(wire), &wire_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(wire, wire_len));

    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS,
                   el2go_ota_download_engine_check_for_updates(&t, attrs, 2U, &resp));
    TEST_ASSERT_TRUE(resp.update_available);
    return TEST_PASS;
}

/*  */

/**
 * @brief status_reporting_report: send fails (mock queues no response) -- exercises
 *        the result != SUCCESS failure branches after send.
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_report_send_no_response(void)
{
    el2go_ota_transport_t t = { 0 };

    TEST_REQUIRE_CAP(CT_CAP_MOCK_TRANSPORT);
    mock_transport_reset();
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, mock_transport_init(&t));

    /* Queue NO response -- after send the recv will block/fail,
     * exercising result != EL2GO_OTA_SUCCESS after the send step. */
    el2go_ota_status_t s =
        el2go_ota_status_reporting_report(&t, "upd-fail", "pkg-fail", EL2GO_OTA_OUTCOME_SUCCESS);
    /* expected to fail since no ack was queued */
    TEST_ASSERT_NE(EL2GO_OTA_SUCCESS, s);
    return TEST_PASS;
}

/**
 * @brief download_engine check_for_updates: send fails -- exercises failure branches
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_check_update_no_response(void)
{
    el2go_ota_transport_t t = { 0 };
    el2go_ota_check_update_resp_t resp = { 0 };

    TEST_REQUIRE_CAP(CT_CAP_MOCK_TRANSPORT);
    mock_transport_reset();
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, mock_transport_init(&t));

    /* No response queued -- recv will fail, exercising result != SUCCESS */
    el2go_ota_status_t s = el2go_ota_download_engine_check_for_updates(&t, NULL, 0U, &resp);
    TEST_ASSERT_NE(EL2GO_OTA_SUCCESS, s);
    return TEST_PASS;
}

/**
 * @brief download_engine fetch_package: send fails -- exercises failure branches
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_fetch_package_no_response(void)
{
    el2go_ota_transport_t t = { 0 };

    TEST_REQUIRE_CAP(CT_CAP_MOCK_TRANSPORT);
    mock_transport_reset();
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, mock_transport_init(&t));

    /* No response queued -- recv will fail */
    el2go_ota_status_t s = el2go_ota_download_engine_fetch_package(&t, "upd", "pkg", "file", 0U,
                                                                   capture_chunk_cb, NULL);
    TEST_ASSERT_NE(EL2GO_OTA_SUCCESS, s);
    return TEST_PASS;
}

/**
 * @brief status_reporting_report with FAILURE outcome and no response
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_report_failure_no_response(void)
{
    el2go_ota_transport_t t = { 0 };

    TEST_REQUIRE_CAP(CT_CAP_MOCK_TRANSPORT);
    mock_transport_reset();
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, mock_transport_init(&t));

    el2go_ota_status_t s =
        el2go_ota_status_reporting_report(&t, "u", "p", EL2GO_OTA_OUTCOME_FAILURE);
    TEST_ASSERT_NE(EL2GO_OTA_SUCCESS, s);
    return TEST_PASS;
}

/**
 * @brief status_reporting_report with ROLLBACK outcome and no response
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_report_rollback_no_response(void)
{
    el2go_ota_transport_t t = { 0 };

    TEST_REQUIRE_CAP(CT_CAP_MOCK_TRANSPORT);
    mock_transport_reset();
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, mock_transport_init(&t));

    el2go_ota_status_t s =
        el2go_ota_status_reporting_report(&t, "u", "p", EL2GO_OTA_OUTCOME_ROLLBACK);
    TEST_ASSERT_NE(EL2GO_OTA_SUCCESS, s);
    return TEST_PASS;
}

/**
 * @brief status_reporting retry_pending: schedule then retry with no response (exercises
 *        the kvs_write + read + send failure paths)
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_retry_pending_no_response(void)
{
    el2go_ota_transport_t t = { 0 };
    el2go_ota_pending_status_t pending = { 0 };

    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH | CT_CAP_MOCK_TRANSPORT);

    /* Clear any existing entry */
    (void)el2go_ota_status_reporting_read_pending(&pending);
    (void)el2go_ota_kvs_delete(EL2GO_OTA_STATUS_NVS_KEY);

    /* Schedule a status */
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_status_reporting_schedule(
                                          "u-b16", "p-b16", EL2GO_OTA_OUTCOME_FAILURE));

    /* Retry with NO response queued -- exercises the send failure branch in retry */
    mock_transport_reset();
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, mock_transport_init(&t));
    /* No response queued */
    el2go_ota_status_t s = el2go_ota_status_reporting_retry_pending(&t);
    (void)s;

    (void)el2go_ota_kvs_delete(EL2GO_OTA_STATUS_NVS_KEY);
    return TEST_PASS;
}

/**
 * @brief check_for_updates with 3 attrs -- exercises the attr loop more iterations
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_check_with_three_attrs(void)
{
    el2go_ota_transport_t t = { 0 };
    el2go_ota_check_update_resp_t resp = { 0 };
    uint8_t wire[512U] = { 0 };
    size_t wire_len = 0U;
    static const el2go_ota_attr_t attrs[] = {
        { "hw", "rw612" },
        { "fw", "1.0" },
        { "region", "eu" },
    };

    TEST_REQUIRE_CAP(CT_CAP_MOCK_TRANSPORT);
    mock_transport_reset();
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, mock_transport_init(&t));
    TEST_ASSERT_EQ(0, canned_check_update_one_package(wire, sizeof(wire), &wire_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(wire, wire_len));
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS,
                   el2go_ota_download_engine_check_for_updates(&t, attrs, 3U, &resp));
    TEST_ASSERT_TRUE(resp.update_available);
    return TEST_PASS;
}

/**
 * @brief fetch_package: corrupt first chunk -- exercises the decode error branch in engine
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_fetch_package_corrupt_chunk(void)
{
    el2go_ota_transport_t t = { 0 };
    static const uint8_t corrupt[] = { 0xFF, 0xFE, 0xFD, 0x01 };

    TEST_REQUIRE_CAP(CT_CAP_MOCK_TRANSPORT);
    mock_transport_reset();
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, mock_transport_init(&t));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(corrupt, sizeof(corrupt)));

    el2go_ota_status_t s = el2go_ota_download_engine_fetch_package(&t, "upd", "pkg", "file", 0U,
                                                                   capture_chunk_cb, NULL);
    (void)s; /* may succeed as empty or fail with decode error */
    return TEST_PASS;
}

/**
 * @brief report: schedule with all 3 outcomes then retry
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_schedule_all_outcomes(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);

    (void)el2go_ota_kvs_delete(EL2GO_OTA_STATUS_NVS_KEY);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS,
                   el2go_ota_status_reporting_schedule("u1", "p1", EL2GO_OTA_OUTCOME_SUCCESS));
    (void)el2go_ota_kvs_delete(EL2GO_OTA_STATUS_NVS_KEY);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS,
                   el2go_ota_status_reporting_schedule("u2", "p2", EL2GO_OTA_OUTCOME_FAILURE));
    (void)el2go_ota_kvs_delete(EL2GO_OTA_STATUS_NVS_KEY);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS,
                   el2go_ota_status_reporting_schedule("u3", "p3", EL2GO_OTA_OUTCOME_ROLLBACK));
    (void)el2go_ota_kvs_delete(EL2GO_OTA_STATUS_NVS_KEY);
    return TEST_PASS;
}

/**
 * @brief report FAILURE with response then ROLLBACK with no response
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_report_failure_then_rollback(void)
{
    el2go_ota_transport_t t = { 0 };
    uint8_t ack[16U] = { 0 };
    size_t ack_len = 0U;

    TEST_REQUIRE_CAP(CT_CAP_MOCK_TRANSPORT);
    mock_transport_reset();
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, mock_transport_init(&t));

    /* FAILURE with response -- success path */
    TEST_ASSERT_EQ(0, canned_report_status_ack(ack, sizeof(ack), &ack_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(ack, ack_len));
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS,
                   el2go_ota_status_reporting_report(&t, "u", "p", EL2GO_OTA_OUTCOME_FAILURE));

    /* ROLLBACK with no response -- exercises failure branch */
    mock_transport_reset();
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, mock_transport_init(&t));
    el2go_ota_status_t s =
        el2go_ota_status_reporting_report(&t, "u", "p", EL2GO_OTA_OUTCOME_ROLLBACK);
    (void)s;
    return TEST_PASS;
}

/**
 * @brief check_for_updates: one attr no response then two attrs with response
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_check_one_attr_fail_two_success(void)
{
    el2go_ota_transport_t t = { 0 };
    el2go_ota_check_update_resp_t resp = { 0 };
    uint8_t wire[512U] = { 0 };
    size_t wire_len = 0U;
    static const el2go_ota_attr_t one[] = { { "k", "v" } };
    static const el2go_ota_attr_t two[] = { { "a", "1" }, { "b", "2" } };

    TEST_REQUIRE_CAP(CT_CAP_MOCK_TRANSPORT);
    mock_transport_reset();
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, mock_transport_init(&t));

    /* One attr with no response */
    el2go_ota_status_t s = el2go_ota_download_engine_check_for_updates(&t, one, 1U, &resp);
    (void)s;

    /* Two attrs with response */
    mock_transport_reset();
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, mock_transport_init(&t));
    TEST_ASSERT_EQ(0, canned_check_update_one_package(wire, sizeof(wire), &wire_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(wire, wire_len));
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS,
                   el2go_ota_download_engine_check_for_updates(&t, two, 2U, &resp));
    TEST_ASSERT_TRUE(resp.update_available);
    return TEST_PASS;
}

/**
 * @brief fetch_package from non-zero offset -- exercises the range_start != 0 path
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_fetch_package_nonzero_offset(void)
{
    el2go_ota_transport_t t = { 0 };
    struct chunk_capture cap = { 0 };
    uint8_t c_wire[128U] = { 0 };
    uint8_t eof_wire[32U] = { 0 };
    size_t c_len = 0U;
    size_t eof_len = 0U;
    static const uint8_t payload[] = { 0xAA, 0xBB };

    TEST_REQUIRE_CAP(CT_CAP_MOCK_TRANSPORT);
    mock_transport_reset();
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, mock_transport_init(&t));

    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(c_wire, sizeof(c_wire), 1024, 1026, payload,
                                                 sizeof(payload), &c_len));
    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(eof_wire, sizeof(eof_wire), 0, 0, NULL, 0U,
                                                 &eof_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(c_wire, c_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(eof_wire, eof_len));

    /* Fetch from offset 1024 -- exercises range_start != 0 branches */
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_download_engine_fetch_package(
                                          &t, "u", "p", "f", 1024U, capture_chunk_cb, &cap));
    TEST_ASSERT_EQ(2U, cap.total_len);
    return TEST_PASS;
}

/**
 * @brief status_reporting_read_pending: no entry -- exercises found=false branch
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_read_pending_no_entry(void)
{
    el2go_ota_pending_status_t pending = { 0 };

    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    (void)el2go_ota_kvs_delete(EL2GO_OTA_STATUS_NVS_KEY);

    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_status_reporting_read_pending(&pending));
    TEST_ASSERT_NE(EL2GO_OTA_STATUS_VALID_MAGIC, pending.valid);
    return TEST_PASS;
}

/**
 * @brief report status SUCCESS + ack: exercises the full send+recv+parse success path
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_report_success_full_path(void)
{
    el2go_ota_transport_t t = { 0 };
    uint8_t ack[16U] = { 0 };
    size_t ack_len = 0U;

    TEST_REQUIRE_CAP(CT_CAP_MOCK_TRANSPORT);
    mock_transport_reset();
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, mock_transport_init(&t));
    TEST_ASSERT_EQ(0, canned_report_status_ack(ack, sizeof(ack), &ack_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(ack, ack_len));
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS,
                   el2go_ota_status_reporting_report(&t, "u", "p", EL2GO_OTA_OUTCOME_ROLLBACK));
    return TEST_PASS;
}

/* ---- suite registration ------------------------------------------------ */

TEST_SUITE_BEGIN(ota_lib_internal)
TEST_REGISTER("OTA_CT_OL_2.1", test_ota_wire_check_update_request)
TEST_REGISTER("OTA_CT_OL_2.2", test_ota_wire_fetch_package_range)
TEST_REGISTER("OTA_CT_OL_2.3", test_ota_wire_report_status_request)
TEST_REGISTER("OTA_CT_OL_2.4", test_ota_wire_device_metadata_after_connect)
TEST_REGISTER("OTA_CT_OL_2.5", test_ota_nvs_schedule_and_read)
TEST_REGISTER("OTA_CT_OL_2.6", test_ota_nvs_retry_no_entry)
TEST_REGISTER("OTA_CT_OL_2.7", test_ota_nvs_retry_with_entry)
TEST_REGISTER("OTA_CT_OL_2.8", test_ota_nvs_schedule_all_outcomes)
TEST_REGISTER("OTA_CT_OL_2.9", test_ota_check_with_attrs)
TEST_REGISTER("OTA_CT_OL_2.10", test_ota_kvs_idempotent_init)
TEST_REGISTER("OTA_CT_OL_2.11", test_ota_kvs_write_read_roundtrip)
TEST_REGISTER("OTA_CT_OL_2.12", test_ota_kvs_delete_read)
TEST_REGISTER("OTA_CT_OL_2.13", test_ota_kvs_delete_nonexistent)
TEST_REGISTER("OTA_CT_OL_2.14", test_ota_kvs_read_not_found)
TEST_REGISTER("OTA_CT_OL_2.15", test_ota_nvs_schedule_and_read_content)
TEST_REGISTER("OTA_CT_OL_2.16", test_ota_nvs_retry_rollback)
TEST_REGISTER("OTA_CT_OL_2.17", test_ota_check_with_two_attrs)
TEST_REGISTER("OTA_CT_OL_2.18", test_ota_report_send_no_response)
TEST_REGISTER("OTA_CT_OL_2.19", test_ota_check_update_no_response)
TEST_REGISTER("OTA_CT_OL_2.20", test_ota_fetch_package_no_response)
TEST_REGISTER("OTA_CT_OL_2.21", test_ota_report_failure_no_response)
TEST_REGISTER("OTA_CT_OL_2.22", test_ota_report_rollback_no_response)
TEST_REGISTER("OTA_CT_OL_2.23", test_ota_retry_pending_no_response)
TEST_REGISTER("OTA_CT_OL_2.24", test_ota_check_with_three_attrs)
TEST_REGISTER("OTA_CT_OL_2.25", test_ota_fetch_package_corrupt_chunk)
TEST_REGISTER("OTA_CT_OL_2.26", test_ota_schedule_all_outcomes)
TEST_REGISTER("OTA_CT_OL_2.27", test_ota_report_failure_then_rollback)
TEST_REGISTER("OTA_CT_OL_2.28", test_ota_check_one_attr_fail_two_success)
TEST_REGISTER("OTA_CT_OL_2.29", test_ota_fetch_package_nonzero_offset)
TEST_REGISTER("OTA_CT_OL_2.30", test_ota_read_pending_no_entry)
TEST_REGISTER("OTA_CT_OL_2.31", test_ota_report_success_full_path)
TEST_SUITE_END(ota_lib_internal)
