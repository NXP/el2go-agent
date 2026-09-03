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

#include "canned_protobuf.h"
#include "mock_transport.h"

/* Payload used for the download chunk assertions. */
static const uint8_t k_chunk_payload[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 };

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

static el2go_ota_status_t abort_chunk_cb(const uint8_t *data, size_t len, size_t offset,
                                         void *cb_ctx)
{
    (void)data;
    (void)len;
    (void)offset;
    (void)cb_ctx;
    return EL2GO_OTA_ERROR_INTERNAL;
}

/* Per-call offset capture (used for range-advance assertions). */
struct range_capture {
    size_t offsets[8U];
    size_t call_count;
};

static el2go_ota_status_t range_capture_cb(const uint8_t *data, size_t len, size_t offset,
                                           void *cb_ctx)
{
    struct range_capture *cap = (struct range_capture *)cb_ctx;

    (void)data;
    (void)len;
    if (cap->call_count >= sizeof(cap->offsets) / sizeof(cap->offsets[0])) {
        return EL2GO_OTA_ERROR_INTERNAL;
    }
    cap->offsets[cap->call_count] = offset;
    cap->call_count++;
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

/* ---- OTA_CT_OL_1.3 : check_for_updates, update available --------------- */
static test_result_t test_ol_check_update_available(void)
{
    el2go_ota_transport_t t = { 0 };
    el2go_ota_check_update_resp_t resp = { 0 };
    uint8_t wire[512U] = { 0 };
    size_t wire_len = 0U;
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

    s = el2go_ota_download_engine_check_for_updates(&t, NULL, 0U, &resp);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);

    TEST_ASSERT_TRUE(resp.update_available);
    TEST_ASSERT_EQ(1U, resp.update_count);
    TEST_ASSERT_EQ(1U, resp.updates[0].package_count);
    TEST_ASSERT_STR_EQ("upd-1", resp.updates[0].update_id);
    TEST_ASSERT_STR_EQ("pkg-1", resp.updates[0].packages[0].package_id);
    TEST_ASSERT_STR_EQ("1.0.0", resp.updates[0].packages[0].version);
    TEST_ASSERT_EQ(1U, mock_transport_send_count());
    return TEST_PASS;
}

/* ---- OTA_CT_OL_1.4 : check_for_updates, no update ---------------------- */
static test_result_t test_ol_check_update_empty(void)
{
    el2go_ota_transport_t t = { 0 };
    el2go_ota_check_update_resp_t resp = { 0 };
    uint8_t wire[16U] = { 0 };
    size_t wire_len = 0U;
    el2go_ota_status_t s = EL2GO_OTA_ERROR_INTERNAL;

    CT_ENTER();
    {
        test_result_t rc = make_transport(&t);
        if (rc != TEST_PASS) {
            return rc;
        }
    }

    TEST_ASSERT_EQ(0, canned_check_update_empty(wire, sizeof(wire), &wire_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(wire, wire_len));

    s = el2go_ota_download_engine_check_for_updates(&t, NULL, 0U, &resp);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_FALSE(resp.update_available);
    TEST_ASSERT_EQ(0U, resp.update_count);
    return TEST_PASS;
}

/* ---- OTA_CT_OL_1.13 : malformed response -> decode error --------------- */
static test_result_t test_ol_check_update_malformed(void)
{
    el2go_ota_transport_t t = { 0 };
    el2go_ota_check_update_resp_t resp = { 0 };

    static const uint8_t truncated_varint[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    };
    el2go_ota_status_t s = EL2GO_OTA_ERROR_INTERNAL;

    CT_ENTER();
    {
        test_result_t rc = make_transport(&t);
        if (rc != TEST_PASS) {
            return rc;
        }
    }

    TEST_ASSERT_EQ(0, mock_transport_queue_response(truncated_varint, sizeof(truncated_varint)));

    s = el2go_ota_download_engine_check_for_updates(&t, NULL, 0U, &resp);
    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_DECODE, s);
    return TEST_PASS;
}

/* ---- extra negative: check_for_updates network error ------------------- */
static test_result_t test_ol_check_update_network_error(void)
{
    el2go_ota_transport_t t = { 0 };
    el2go_ota_check_update_resp_t resp = { 0 };
    el2go_ota_status_t s = EL2GO_OTA_ERROR_INTERNAL;

    CT_ENTER();
    {
        test_result_t rc = make_transport(&t);
        if (rc != TEST_PASS) {
            return rc;
        }
    }

    TEST_ASSERT_EQ(0, mock_transport_queue_network_error());

    s = el2go_ota_download_engine_check_for_updates(&t, NULL, 0U, &resp);
    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_NETWORK, s);
    return TEST_PASS;
}

/* ---- helper (no plan ID) : download, single chunk ---------------------- */
static test_result_t test_ol_download_single_chunk(void)
{
    el2go_ota_transport_t t = { 0 };
    struct chunk_capture cap = { 0 };
    uint8_t chunk_wire[128U] = { 0 };
    uint8_t eof_wire[32U] = { 0 };
    size_t chunk_len = 0U;
    size_t eof_len = 0U;
    el2go_ota_status_t s = EL2GO_OTA_ERROR_INTERNAL;

    CT_ENTER();
    {
        test_result_t rc = make_transport(&t);
        if (rc != TEST_PASS) {
            return rc;
        }
    }

    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(
                          chunk_wire, sizeof(chunk_wire), 0, (int64_t)sizeof(k_chunk_payload) - 1,
                          k_chunk_payload, sizeof(k_chunk_payload), &chunk_len));
    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(eof_wire, sizeof(eof_wire), 0, 0, NULL, 0U,
                                                 &eof_len));

    TEST_ASSERT_EQ(0, mock_transport_queue_response(chunk_wire, chunk_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(eof_wire, eof_len));

    s = el2go_ota_download_engine_fetch_package(&t, "upd-1", "pkg-1", "file-1", 0U,
                                                capture_chunk_cb, &cap);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);

    TEST_ASSERT_EQ(sizeof(k_chunk_payload), cap.total_len);
    TEST_ASSERT_MEM_EQ(k_chunk_payload, cap.data, sizeof(k_chunk_payload));
    TEST_ASSERT_EQ(0U, cap.last_offset);
    return TEST_PASS;
}

/* ---- OTA_CT_OL_1.5 : multi-chunk download, all data reassembled -------- */
static test_result_t test_ol_download_multi_chunk(void)
{
    el2go_ota_transport_t t = { 0 };
    struct chunk_capture cap = { 0 };
    uint8_t c0[128U] = { 0 };
    uint8_t c1[128U] = { 0 };
    uint8_t c2[128U] = { 0 };
    uint8_t eof[32U] = { 0 };
    size_t l0 = 0U;
    size_t l1 = 0U;
    size_t l2 = 0U;
    size_t le = 0U;

    static const uint8_t p0[] = { 0xA0, 0xA1, 0xA2, 0xA3 };
    static const uint8_t p1[] = { 0xB0, 0xB1, 0xB2, 0xB3 };
    static const uint8_t p2[] = { 0xC0, 0xC1, 0xC2, 0xC3 };
    uint8_t expected[12U] = { 0 };
    el2go_ota_status_t s = EL2GO_OTA_ERROR_INTERNAL;

    CT_ENTER();
    {
        test_result_t rc = make_transport(&t);
        if (rc != TEST_PASS) {
            return rc;
        }
    }

    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(c0, sizeof(c0), 0, 3, p0, sizeof(p0), &l0));
    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(c1, sizeof(c1), 4, 7, p1, sizeof(p1), &l1));
    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(c2, sizeof(c2), 8, 11, p2, sizeof(p2), &l2));
    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(eof, sizeof(eof), 0, 0, NULL, 0U, &le));

    TEST_ASSERT_EQ(0, mock_transport_queue_response(c0, l0));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(c1, l1));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(c2, l2));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(eof, le));

    s = el2go_ota_download_engine_fetch_package(&t, "upd-1", "pkg-1", "file-1", 0U,
                                                capture_chunk_cb, &cap);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);

    (void)memcpy(&expected[0], p0, 4U);
    (void)memcpy(&expected[4], p1, 4U);
    (void)memcpy(&expected[8], p2, 4U);

    TEST_ASSERT_EQ(12U, cap.total_len);
    TEST_ASSERT_MEM_EQ(expected, cap.data, sizeof(expected));
    TEST_ASSERT_EQ(3U, cap.call_count);
    return TEST_PASS;
}

/* ---- OTA_CT_OL_1.6 : rangeStart values in consecutive callbacks advance  */
static test_result_t test_ol_download_chunk_range_advances(void)
{
    el2go_ota_transport_t t = { 0 };
    struct range_capture rcap = { 0 };
    uint8_t c0[128U] = { 0 };
    uint8_t c1[128U] = { 0 };
    uint8_t c2[128U] = { 0 };
    uint8_t eof[32U] = { 0 };
    size_t l0 = 0U;
    size_t l1 = 0U;
    size_t l2 = 0U;
    size_t le = 0U;
    static const uint8_t p[] = { 0x10, 0x11, 0x12, 0x13 };
    el2go_ota_status_t s = EL2GO_OTA_ERROR_INTERNAL;
    size_t i;

    CT_ENTER();
    {
        test_result_t rc = make_transport(&t);
        if (rc != TEST_PASS) {
            return rc;
        }
    }

    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(c0, sizeof(c0), 0, 3, p, sizeof(p), &l0));
    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(c1, sizeof(c1), 4, 7, p, sizeof(p), &l1));
    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(c2, sizeof(c2), 8, 11, p, sizeof(p), &l2));
    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(eof, sizeof(eof), 0, 0, NULL, 0U, &le));

    TEST_ASSERT_EQ(0, mock_transport_queue_response(c0, l0));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(c1, l1));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(c2, l2));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(eof, le));

    s = el2go_ota_download_engine_fetch_package(&t, "upd-1", "pkg-1", "file-1", 0U,
                                                range_capture_cb, &rcap);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_EQ(3U, rcap.call_count);

    for (i = 1U; i < rcap.call_count; i++) {
        TEST_ASSERT_MSG(rcap.offsets[i] > rcap.offsets[i - 1U],
                        "rangeStart did not advance between consecutive chunk callbacks");
    }
    return TEST_PASS;
}

/* ---- extra negative: chunk callback abort ------------------------------ */
static test_result_t test_ol_download_callback_abort(void)
{
    el2go_ota_transport_t t = { 0 };
    uint8_t chunk_wire[128U] = { 0 };
    size_t chunk_len = 0U;
    el2go_ota_status_t s = EL2GO_OTA_ERROR_INTERNAL;

    CT_ENTER();
    {
        test_result_t rc = make_transport(&t);
        if (rc != TEST_PASS) {
            return rc;
        }
    }

    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(
                          chunk_wire, sizeof(chunk_wire), 0, (int64_t)sizeof(k_chunk_payload) - 1,
                          k_chunk_payload, sizeof(k_chunk_payload), &chunk_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(chunk_wire, chunk_len));

    s = el2go_ota_download_engine_fetch_package(&t, "upd-1", "pkg-1", "file-1", 0U, abort_chunk_cb,
                                                NULL);
    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_INTERNAL, s);
    return TEST_PASS;
}

/* ---- OTA_CT_OL_1.10 : network interruption mid-download ---------------- */
static test_result_t test_ol_download_network_interruption(void)
{
    el2go_ota_transport_t t = { 0 };
    struct chunk_capture cap = { 0 };
    uint8_t c0[128U] = { 0 };
    size_t l0 = 0U;
    static const uint8_t p0[] = { 0x10, 0x11, 0x12, 0x13 };
    el2go_ota_status_t s = EL2GO_OTA_ERROR_INTERNAL;

    CT_ENTER();
    {
        test_result_t rc = make_transport(&t);
        if (rc != TEST_PASS) {
            return rc;
        }
    }

    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(c0, sizeof(c0), 0, 3, p0, sizeof(p0), &l0));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(c0, l0));
    TEST_ASSERT_EQ(0, mock_transport_queue_network_error());

    s = el2go_ota_download_engine_fetch_package(&t, "upd-1", "pkg-1", "file-1", 0U,
                                                capture_chunk_cb, &cap);
    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_NETWORK, s);
    TEST_ASSERT_EQ(4U, cap.total_len);
    return TEST_PASS;
}

/* ---- OTA_CT_OL_1.11 : resume from offset ------------------------------- */
static test_result_t test_ol_download_resume_from_offset(void)
{
    el2go_ota_transport_t t = { 0 };
    struct chunk_capture cap = { 0 };
    uint8_t c1[128U] = { 0 };
    uint8_t eof[32U] = { 0 };
    size_t l1 = 0U;
    size_t le = 0U;
    static const uint8_t p1[] = { 0xB0, 0xB1, 0xB2, 0xB3 };
    uint8_t last_req[512U] = { 0 };
    size_t last_req_len = 0U;
    el2go_ota_status_t s = EL2GO_OTA_ERROR_INTERNAL;

    CT_ENTER();
    {
        test_result_t rc = make_transport(&t);
        if (rc != TEST_PASS) {
            return rc;
        }
    }

    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(c1, sizeof(c1), 4, 7, p1, sizeof(p1), &l1));
    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(eof, sizeof(eof), 0, 0, NULL, 0U, &le));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(c1, l1));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(eof, le));

    s = el2go_ota_download_engine_fetch_package(&t, "upd-1", "pkg-1", "file-1", 4U,
                                                capture_chunk_cb, &cap);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_EQ(4U, cap.total_len);
    TEST_ASSERT_EQ(0, mock_transport_get_last_request(last_req, sizeof(last_req), &last_req_len));
    TEST_ASSERT_NE(0U, last_req_len);
    return TEST_PASS;
}

/* ---- extra positive: schedule + read pending status (NVS fidelity) ----- */
static test_result_t test_ol_schedule_and_read_pending(void)
{
    el2go_ota_pending_status_t pending = { 0 };
    el2go_ota_status_t s = EL2GO_OTA_ERROR_INTERNAL;

    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);

    s = el2go_ota_status_reporting_schedule("upd-1", "pkg-1", EL2GO_OTA_OUTCOME_SUCCESS);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);

    s = el2go_ota_status_reporting_read_pending(&pending);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);

    TEST_ASSERT_EQ(EL2GO_OTA_STATUS_VALID_MAGIC, pending.valid);
    TEST_ASSERT_EQ((uint8_t)EL2GO_OTA_OUTCOME_SUCCESS, pending.outcome);
    TEST_ASSERT_STR_EQ("upd-1", pending.update_id);
    TEST_ASSERT_STR_EQ("pkg-1", pending.package_id);
    return TEST_PASS;
}

/* ---- OTA_CT_OL_1.7 : report_status SUCCESS acked, NVS cleared ---------- */
static test_result_t test_ol_report_status_success_ack(void)
{
    el2go_ota_transport_t t = { 0 };
    el2go_ota_pending_status_t pending = { 0 };
    uint8_t ack[16U] = { 0 };
    size_t ack_len = 0U;
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

    s = el2go_ota_status_reporting_report(&t, "upd-2", "pkg-2", EL2GO_OTA_OUTCOME_SUCCESS);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);

    s = el2go_ota_status_reporting_read_pending(&pending);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_NE(EL2GO_OTA_STATUS_VALID_MAGIC, pending.valid);
    return TEST_PASS;
}

/* ---- OTA_CT_OL_1.8 : report_status FAILURE acked ----------------------- */
static test_result_t test_ol_report_status_failure_ack(void)
{
    el2go_ota_transport_t t = { 0 };
    el2go_ota_pending_status_t pending = { 0 };
    uint8_t ack[16U] = { 0 };
    size_t ack_len = 0U;
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

    s = el2go_ota_status_reporting_report(&t, "upd-8", "pkg-8", EL2GO_OTA_OUTCOME_FAILURE);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);

    s = el2go_ota_status_reporting_read_pending(&pending);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_NE(EL2GO_OTA_STATUS_VALID_MAGIC, pending.valid);
    return TEST_PASS;
}

/* ---- OTA_CT_OL_1.9 : report_status ROLLBACK acked ---------------------- */
static test_result_t test_ol_report_status_rollback_ack(void)
{
    el2go_ota_transport_t t = { 0 };
    el2go_ota_pending_status_t pending = { 0 };
    uint8_t ack[16U] = { 0 };
    size_t ack_len = 0U;
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

    s = el2go_ota_status_reporting_report(&t, "upd-9", "pkg-9", EL2GO_OTA_OUTCOME_ROLLBACK);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);

    s = el2go_ota_status_reporting_read_pending(&pending);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_NE(EL2GO_OTA_STATUS_VALID_MAGIC, pending.valid);
    return TEST_PASS;
}

/* ---- extra negative: report retains NVS on network error --------------- */
static test_result_t test_ol_report_status_retains_on_error(void)
{
    el2go_ota_transport_t t = { 0 };
    el2go_ota_pending_status_t pending = { 0 };
    el2go_ota_status_t s = EL2GO_OTA_ERROR_INTERNAL;

    CT_ENTER();
    {
        test_result_t rc = make_transport(&t);
        if (rc != TEST_PASS) {
            return rc;
        }
    }

    TEST_ASSERT_EQ(0, mock_transport_queue_network_error());

    s = el2go_ota_status_reporting_report(&t, "upd-3", "pkg-3", EL2GO_OTA_OUTCOME_FAILURE);
    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_NETWORK, s);

    s = el2go_ota_status_reporting_read_pending(&pending);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_EQ(EL2GO_OTA_STATUS_VALID_MAGIC, pending.valid);
    TEST_ASSERT_STR_EQ("upd-3", pending.update_id);
    return TEST_PASS;
}

/* ---- OTA_CT_OL_1.12 : retry pending after N failures ------------------- */
static test_result_t test_ol_report_retry_after_failures(void)
{
    el2go_ota_transport_t t = { 0 };
    el2go_ota_pending_status_t pending = { 0 };
    uint8_t ack[16U] = { 0 };
    size_t ack_len = 0U;
    el2go_ota_status_t s = EL2GO_OTA_ERROR_INTERNAL;

    CT_ENTER();
    {
        test_result_t rc = make_transport(&t);
        if (rc != TEST_PASS) {
            return rc;
        }
    }

    TEST_ASSERT_EQ(0, mock_transport_queue_network_error());
    s = el2go_ota_status_reporting_report(&t, "upd-12", "pkg-12", EL2GO_OTA_OUTCOME_SUCCESS);
    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_NETWORK, s);

    s = el2go_ota_status_reporting_read_pending(&pending);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_EQ(EL2GO_OTA_STATUS_VALID_MAGIC, pending.valid);

    TEST_ASSERT_EQ(0, canned_report_status_ack(ack, sizeof(ack), &ack_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(ack, ack_len));
    s = el2go_ota_status_reporting_retry_pending(&t);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);

    s = el2go_ota_status_reporting_read_pending(&pending);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_NE(EL2GO_OTA_STATUS_VALID_MAGIC, pending.valid);
    return TEST_PASS;
}

/* ---- OTA_CT_OL_2.1 : CheckUpdate request captured (wire present) ------- */
static test_result_t test_ol_wire_check_update_request(void)
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

/* ---- OTA_CT_OL_2.2 : FetchPackage wire bytes match expected range ------- */
static test_result_t test_ol_wire_fetch_package_range(void)
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
    TEST_ASSERT_EQ(0, mock_transport_queue_response(c_wire, c_len));

    s = el2go_ota_download_engine_fetch_package(&t, "upd-22", "pkg-22", "file-22", 4U,
                                                capture_chunk_cb, &cap);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_EQ(3U, cap.total_len);

    TEST_ASSERT_EQ(0, mock_transport_get_last_request(actual_req, sizeof(actual_req),
                                                      &actual_req_len));
    TEST_ASSERT_NE(0U, actual_req_len);

    /*
     * el2go_ota_fetch_pkg_req_t no longer carries the has_range_start /
     * has_range_end gates or the legacy artifact_id: the current builder
     * always emits a Range submessage, and the "third-level" id is now
     * file_id (see libs/el2go_ota_lib/src/el2go_ota_request_builder.h).
     */
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

/* ---- OTA_CT_OL_2.3 : ReportStatus request captured (wire present) ------ */
static test_result_t test_ol_wire_report_status_request(void)
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

/* ---- OTA_CT_OL_2.4 : device metadata in post-connect request (pending) - */
static test_result_t test_ol_wire_device_metadata_after_connect(void)
{
    TEST_SKIP_WITH("no device metadata API yet; TODO(OTA_CT_OL_2.4)");
}

/* ---- suite table ------------------------------------------------------- */

TEST_SUITE_BEGIN(ota_lib_internal)
TEST_REGISTER("OTA_CT_OL_1.3", test_ol_check_update_available)
TEST_REGISTER("OTA_CT_OL_1.4", test_ol_check_update_empty)
TEST_REGISTER("OTA_CT_OL_1.13", test_ol_check_update_malformed)
TEST_REGISTER("-", test_ol_check_update_network_error)
TEST_REGISTER("-", test_ol_download_single_chunk)
TEST_REGISTER("OTA_CT_OL_1.5", test_ol_download_multi_chunk)
TEST_REGISTER("OTA_CT_OL_1.6", test_ol_download_chunk_range_advances)
TEST_REGISTER("-", test_ol_download_callback_abort)
TEST_REGISTER("OTA_CT_OL_1.10", test_ol_download_network_interruption)
TEST_REGISTER("OTA_CT_OL_1.11", test_ol_download_resume_from_offset)
TEST_REGISTER("-", test_ol_schedule_and_read_pending)
TEST_REGISTER("OTA_CT_OL_1.7", test_ol_report_status_success_ack)
TEST_REGISTER("OTA_CT_OL_1.8", test_ol_report_status_failure_ack)
TEST_REGISTER("OTA_CT_OL_1.9", test_ol_report_status_rollback_ack)
TEST_REGISTER("-", test_ol_report_status_retains_on_error)
TEST_REGISTER("OTA_CT_OL_1.12", test_ol_report_retry_after_failures)
TEST_REGISTER("OTA_CT_OL_2.1", test_ol_wire_check_update_request)
TEST_REGISTER("OTA_CT_OL_2.2", test_ol_wire_fetch_package_range)
TEST_REGISTER("OTA_CT_OL_2.3", test_ol_wire_report_status_request)
TEST_REGISTER("OTA_CT_OL_2.4", test_ol_wire_device_metadata_after_connect)
TEST_SUITE_END(ota_lib_internal)
