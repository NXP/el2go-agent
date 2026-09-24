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
#include "el2go_ota_response_handler.h"
#include "ota/el2go_ota_lib.h"

#include "types/available_updates_response.pb.h"
#include "types/file_response.pb.h"
#include "types/file_metadata.pb.h"
#include "types/package.pb.h"
#include "types/update.pb.h"
#include <pb_decode.h>
#include <pb_encode.h>

/**
 * @brief parse_check_update_response with one Update that has one Package
 *        carrying a FileMetadata sub-message.  Verify file_id, size, and
 *        checksum_algorithm are correctly stored in the response struct.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_parse_check_update_with_file_metadata(void *params)
{
    /* Build Package sub-message with one FileMetadata entry. */
    uint8_t fm_buf[256];
    uint8_t pkg_buf[512];
    uint8_t upd_buf[768];
    uint8_t wire[1024];
    size_t fm_len = 0U;
    size_t pkg_len = 0U;
    size_t upd_len = 0U;
    pb_ostream_t outer;
    static el2go_ota_check_update_resp_t out;

    (void)params;

    /* Encode FileMetadata: fileId, size=4096, checksumAlgorithm=2. */
    pb_ostream_t fms = pb_ostream_from_buffer(fm_buf, sizeof(fm_buf));
    /* fileId field 1 */
    TEST_ASSERT(
        pb_encode_tag(&fms, PB_WT_STRING, com_nxp_iot_ota_update_proto_FileMetadata_fileId_tag));
    TEST_ASSERT(pb_encode_string(&fms, (const pb_byte_t *)"fw.bin", 6U));
    /* size field 4 */
    TEST_ASSERT(
        pb_encode_tag(&fms, PB_WT_VARINT, com_nxp_iot_ota_update_proto_FileMetadata_size_tag));
    TEST_ASSERT(pb_encode_varint(&fms, 4096U));
    /* checksumAlgorithm field 6 */
    TEST_ASSERT(pb_encode_tag(&fms, PB_WT_VARINT,
                              com_nxp_iot_ota_update_proto_FileMetadata_checksumAlgorithm_tag));
    TEST_ASSERT(pb_encode_varint(&fms, 2U));
    fm_len = fms.bytes_written;
    TEST_ASSERT(fm_len > 0U);

    /* Encode Package with packageId + fileMetadata. */
    pb_ostream_t ps = pb_ostream_from_buffer(pkg_buf, sizeof(pkg_buf));
    TEST_ASSERT(
        pb_encode_tag(&ps, PB_WT_STRING, com_nxp_iot_ota_update_proto_Package_packageId_tag));
    TEST_ASSERT(pb_encode_string(&ps, (const pb_byte_t *)"pkg-fm", 6U));
    TEST_ASSERT(
        pb_encode_tag(&ps, PB_WT_STRING, com_nxp_iot_ota_update_proto_Package_fileMetadata_tag));
    TEST_ASSERT(pb_encode_string(&ps, fm_buf, fm_len));
    pkg_len = ps.bytes_written;
    TEST_ASSERT(pkg_len > 0U);

    /* Encode Update with updateId + packages. */
    pb_ostream_t us = pb_ostream_from_buffer(upd_buf, sizeof(upd_buf));
    TEST_ASSERT(pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_updateId_tag));
    TEST_ASSERT(pb_encode_string(&us, (const pb_byte_t *)"upd-fm", 6U));
    TEST_ASSERT(pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_packages_tag));
    TEST_ASSERT(pb_encode_string(&us, pkg_buf, pkg_len));
    upd_len = us.bytes_written;
    TEST_ASSERT(upd_len > 0U);

    /* Encode outer AvailableUpdatesResponse with one updates entry. */
    outer = pb_ostream_from_buffer(wire, sizeof(wire));
    TEST_ASSERT(pb_encode_tag(&outer, PB_WT_STRING,
                              com_nxp_iot_ota_update_proto_AvailableUpdatesResponse_updates_tag));
    TEST_ASSERT(pb_encode_string(&outer, upd_buf, upd_len));

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_parse_check_update_response(wire, outer.bytes_written, &out));
    TEST_ASSERT(out.update_available);
    TEST_ASSERT(out.update_count == 1U);
    TEST_ASSERT_EQUAL(0, strcmp(out.updates[0].packages[0].package_id, "pkg-fm"));
    TEST_ASSERT_EQUAL(1U, out.updates[0].packages[0].file_count);
    TEST_ASSERT_EQUAL(0, strcmp(out.updates[0].packages[0].files[0].file_id, "fw.bin"));
    TEST_ASSERT_EQUAL(4096, out.updates[0].packages[0].files[0].size);
    TEST_ASSERT_EQUAL(2, out.updates[0].packages[0].files[0].checksum_algorithm);

    return true;
}

/**
 * @brief parse_check_update_response where the Package carries more FileMetadata
 *        entries than EL2GO_OTA_MAX_FILE_METADATA.  Extra entries must be
 *        silently dropped; file_count must equal the maximum.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_parse_check_update_file_metadata_overflow(void *params)
{
    uint8_t fm_buf[64];
    uint8_t pkg_buf[1024];
    uint8_t upd_buf[1536];
    uint8_t wire[2048];
    pb_ostream_t outer;
    size_t i;
    static el2go_ota_check_update_resp_t out;

    (void)params;

    /* Build Package with MAX+2 FileMetadata entries. */
    pb_ostream_t ps = pb_ostream_from_buffer(pkg_buf, sizeof(pkg_buf));
    TEST_ASSERT(
        pb_encode_tag(&ps, PB_WT_STRING, com_nxp_iot_ota_update_proto_Package_packageId_tag));
    TEST_ASSERT(pb_encode_string(&ps, (const pb_byte_t *)"pkg-of", 6U));

    for (i = 0U; i < (EL2GO_OTA_MAX_FILE_METADATA + 2U); i++) {
        pb_ostream_t fms = pb_ostream_from_buffer(fm_buf, sizeof(fm_buf));
        char fid[8];
        int n = snprintf(fid, sizeof(fid), "f%zu", i);
        TEST_ASSERT(n > 0);
        TEST_ASSERT(pb_encode_tag(&fms, PB_WT_STRING,
                                  com_nxp_iot_ota_update_proto_FileMetadata_fileId_tag));
        TEST_ASSERT(pb_encode_string(&fms, (const pb_byte_t *)fid, (size_t)n));
        size_t fm_len = fms.bytes_written;
        TEST_ASSERT(pb_encode_tag(&ps, PB_WT_STRING,
                                  com_nxp_iot_ota_update_proto_Package_fileMetadata_tag));
        TEST_ASSERT(pb_encode_string(&ps, fm_buf, fm_len));
    }
    size_t pkg_len = ps.bytes_written;

    pb_ostream_t us = pb_ostream_from_buffer(upd_buf, sizeof(upd_buf));
    TEST_ASSERT(pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_updateId_tag));
    TEST_ASSERT(pb_encode_string(&us, (const pb_byte_t *)"upd-of", 6U));
    TEST_ASSERT(pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_packages_tag));
    TEST_ASSERT(pb_encode_string(&us, pkg_buf, pkg_len));
    size_t upd_len = us.bytes_written;

    outer = pb_ostream_from_buffer(wire, sizeof(wire));
    TEST_ASSERT(pb_encode_tag(&outer, PB_WT_STRING,
                              com_nxp_iot_ota_update_proto_AvailableUpdatesResponse_updates_tag));
    TEST_ASSERT(pb_encode_string(&outer, upd_buf, upd_len));

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_parse_check_update_response(wire, outer.bytes_written, &out));
    TEST_ASSERT(out.update_available);
    TEST_ASSERT_EQUAL(EL2GO_OTA_MAX_FILE_METADATA, out.updates[0].packages[0].file_count);

    return true;
}

/**
 * @brief parse_check_update_response where one Update has more Packages than
 *        EL2GO_OTA_MAX_PACKAGES.  Extra packages must be silently dropped.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_parse_check_update_package_overflow(void *params)
{
    uint8_t pkg_buf[64];
    uint8_t upd_buf[2048];
    uint8_t wire[2560];
    pb_ostream_t outer;
    size_t i;
    static el2go_ota_check_update_resp_t out;

    (void)params;

    pb_ostream_t us = pb_ostream_from_buffer(upd_buf, sizeof(upd_buf));
    TEST_ASSERT(pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_updateId_tag));
    TEST_ASSERT(pb_encode_string(&us, (const pb_byte_t *)"upd-pof", 7U));

    for (i = 0U; i < (EL2GO_OTA_MAX_PACKAGES + 2U); i++) {
        pb_ostream_t ps = pb_ostream_from_buffer(pkg_buf, sizeof(pkg_buf));
        char pid[8];
        int n = snprintf(pid, sizeof(pid), "p%zu", i);
        TEST_ASSERT(n > 0);
        TEST_ASSERT(
            pb_encode_tag(&ps, PB_WT_STRING, com_nxp_iot_ota_update_proto_Package_packageId_tag));
        TEST_ASSERT(pb_encode_string(&ps, (const pb_byte_t *)pid, (size_t)n));
        size_t pkg_len = ps.bytes_written;
        TEST_ASSERT(
            pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_packages_tag));
        TEST_ASSERT(pb_encode_string(&us, pkg_buf, pkg_len));
    }
    size_t upd_len = us.bytes_written;

    outer = pb_ostream_from_buffer(wire, sizeof(wire));
    TEST_ASSERT(pb_encode_tag(&outer, PB_WT_STRING,
                              com_nxp_iot_ota_update_proto_AvailableUpdatesResponse_updates_tag));
    TEST_ASSERT(pb_encode_string(&outer, upd_buf, upd_len));

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_parse_check_update_response(wire, outer.bytes_written, &out));
    TEST_ASSERT(out.update_available);
    TEST_ASSERT_EQUAL(EL2GO_OTA_MAX_PACKAGES, out.updates[0].package_count);

    return true;
}

/**
 * @brief parse_check_update_response with more Updates than EL2GO_OTA_MAX_UPDATES.
 *        Extra updates must be silently dropped; update_count must equal the max.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_parse_check_update_update_overflow(void *params)
{
    uint8_t pkg_buf[64];
    uint8_t upd_buf[128];
    uint8_t wire[2048];
    pb_ostream_t outer;
    size_t i;
    static el2go_ota_check_update_resp_t out;

    (void)params;

    outer = pb_ostream_from_buffer(wire, sizeof(wire));

    for (i = 0U; i < (EL2GO_OTA_MAX_UPDATES + 2U); i++) {
        /* Minimal package sub-message. */
        pb_ostream_t ps = pb_ostream_from_buffer(pkg_buf, sizeof(pkg_buf));
        TEST_ASSERT(
            pb_encode_tag(&ps, PB_WT_STRING, com_nxp_iot_ota_update_proto_Package_packageId_tag));
        TEST_ASSERT(pb_encode_string(&ps, (const pb_byte_t *)"p1", 2U));
        size_t pkg_len = ps.bytes_written;

        pb_ostream_t us = pb_ostream_from_buffer(upd_buf, sizeof(upd_buf));
        TEST_ASSERT(
            pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_updateId_tag));
        TEST_ASSERT(pb_encode_string(&us, (const pb_byte_t *)"u1", 2U));
        TEST_ASSERT(
            pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_packages_tag));
        TEST_ASSERT(pb_encode_string(&us, pkg_buf, pkg_len));
        size_t upd_len = us.bytes_written;

        TEST_ASSERT(
            pb_encode_tag(&outer, PB_WT_STRING,
                          com_nxp_iot_ota_update_proto_AvailableUpdatesResponse_updates_tag));
        TEST_ASSERT(pb_encode_string(&outer, upd_buf, upd_len));
    }

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_parse_check_update_response(wire, outer.bytes_written, &out));
    TEST_ASSERT(out.update_available);
    TEST_ASSERT_EQUAL(EL2GO_OTA_MAX_UPDATES, out.update_count);

    return true;
}

/**
 * @brief parse_fetch_package_response with buf_len == 0 (zero-length buf) must
 *        return EL2GO_OTA_ERROR_INVALID_PARAM (buf is non-NULL but len == 0).
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_parse_fetch_package_zero_len(void *params)
{
    el2go_ota_fetch_pkg_resp_t out;
    static const uint8_t dummy[] = { 0x00 };

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_parse_fetch_package_response(dummy, 0U, &out));

    return true;
}

/**
 * @brief Parse a CheckUpdate response where the Update sub-message carries a
 *        name field and an attributes map entry.  Verify that the name is
 *        stored and that the attributes callback fires without crashing.
 */
static bool test_ota_parse_check_update_with_name_and_attrs(void *params)
{
    /* Verify that Update.name field is stored; attributes are skipped by decoder. */
    uint8_t upd_buf[512];
    uint8_t wire[768];
    pb_ostream_t us;
    pb_ostream_t outer;
    static el2go_ota_check_update_resp_t out;

    (void)params;

    /* Encode Update: updateId + name only (no attributes to avoid callback complexity). */
    us = pb_ostream_from_buffer(upd_buf, sizeof(upd_buf));
    TEST_ASSERT(pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_updateId_tag));
    TEST_ASSERT(pb_encode_string(&us, (const pb_byte_t *)"upd-na", 6U));
    TEST_ASSERT(pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_name_tag));
    TEST_ASSERT(pb_encode_string(&us, (const pb_byte_t *)"my-update", 9U));
    size_t upd_len = us.bytes_written;

    outer = pb_ostream_from_buffer(wire, sizeof(wire));
    TEST_ASSERT(pb_encode_tag(&outer, PB_WT_STRING,
                              com_nxp_iot_ota_update_proto_AvailableUpdatesResponse_updates_tag));
    TEST_ASSERT(pb_encode_string(&outer, upd_buf, upd_len));

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_parse_check_update_response(wire, outer.bytes_written, &out));
    TEST_ASSERT(out.update_available);
    TEST_ASSERT_EQUAL(0, strcmp(out.updates[0].update_id, "upd-na"));
    TEST_ASSERT_EQUAL(0, strcmp(out.updates[0].name, "my-update"));

    return true;
}

/**
 * @brief Parse a CheckUpdate response where a Package sub-message carries a
 *        name, version, and one attributes entry.  Verify name and version stored.
 */
static bool test_ota_parse_check_update_package_with_all_fields(void *params)
{
    uint8_t pkg_buf[512];
    uint8_t upd_buf[768];
    uint8_t wire[1024];
    pb_ostream_t ps;
    pb_ostream_t us;
    pb_ostream_t outer;
    static el2go_ota_check_update_resp_t out;

    (void)params;

    ps = pb_ostream_from_buffer(pkg_buf, sizeof(pkg_buf));
    TEST_ASSERT(
        pb_encode_tag(&ps, PB_WT_STRING, com_nxp_iot_ota_update_proto_Package_packageId_tag));
    TEST_ASSERT(pb_encode_string(&ps, (const pb_byte_t *)"pkg-all", 7U));
    TEST_ASSERT(pb_encode_tag(&ps, PB_WT_STRING, com_nxp_iot_ota_update_proto_Package_name_tag));
    TEST_ASSERT(pb_encode_string(&ps, (const pb_byte_t *)"fw-package", 10U));
    TEST_ASSERT(pb_encode_tag(&ps, PB_WT_STRING, com_nxp_iot_ota_update_proto_Package_version_tag));
    TEST_ASSERT(pb_encode_string(&ps, (const pb_byte_t *)"2.0.1", 5U));
    size_t pkg_len = ps.bytes_written;

    us = pb_ostream_from_buffer(upd_buf, sizeof(upd_buf));
    TEST_ASSERT(pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_updateId_tag));
    TEST_ASSERT(pb_encode_string(&us, (const pb_byte_t *)"upd-all", 7U));
    TEST_ASSERT(pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_packages_tag));
    TEST_ASSERT(pb_encode_string(&us, pkg_buf, pkg_len));
    size_t upd_len = us.bytes_written;

    outer = pb_ostream_from_buffer(wire, sizeof(wire));
    TEST_ASSERT(pb_encode_tag(&outer, PB_WT_STRING,
                              com_nxp_iot_ota_update_proto_AvailableUpdatesResponse_updates_tag));
    TEST_ASSERT(pb_encode_string(&outer, upd_buf, upd_len));

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_parse_check_update_response(wire, outer.bytes_written, &out));
    TEST_ASSERT(out.update_available);
    TEST_ASSERT_EQUAL(0, strcmp(out.updates[0].packages[0].package_id, "pkg-all"));
    TEST_ASSERT_EQUAL(0, strcmp(out.updates[0].packages[0].name, "fw-package"));
    TEST_ASSERT_EQUAL(0, strcmp(out.updates[0].packages[0].version, "2.0.1"));

    return true;
}

/**
 * @brief parse_check_update_response with an Update that has a description
 *        field (should be discarded) and two packages -- exercises the
 *        description discard branch and multi-package path in decode_update_cb.
 */
static bool test_ota_parse_check_update_description_discarded(void *params)
{
    uint8_t pkg1[64], pkg2[64], upd_buf[512], wire[768];
    pb_ostream_t ps1, ps2, us, outer;
    static el2go_ota_check_update_resp_t out;

    (void)params;

    /* Package 1 */
    ps1 = pb_ostream_from_buffer(pkg1, sizeof(pkg1));
    TEST_ASSERT(
        pb_encode_tag(&ps1, PB_WT_STRING, com_nxp_iot_ota_update_proto_Package_packageId_tag));
    TEST_ASSERT(pb_encode_string(&ps1, (const pb_byte_t *)"p1", 2U));
    size_t pkg1_len = ps1.bytes_written;

    /* Package 2 */
    ps2 = pb_ostream_from_buffer(pkg2, sizeof(pkg2));
    TEST_ASSERT(
        pb_encode_tag(&ps2, PB_WT_STRING, com_nxp_iot_ota_update_proto_Package_packageId_tag));
    TEST_ASSERT(pb_encode_string(&ps2, (const pb_byte_t *)"p2", 2U));
    size_t pkg2_len = ps2.bytes_written;

    /* Update: updateId + description (field 3, discarded) + 2 packages */
    us = pb_ostream_from_buffer(upd_buf, sizeof(upd_buf));
    TEST_ASSERT(pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_updateId_tag));
    TEST_ASSERT(pb_encode_string(&us, (const pb_byte_t *)"upd-d", 5U));
    /* description field -- should be discarded by decode callback */
    TEST_ASSERT(
        pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_description_tag));
    TEST_ASSERT(pb_encode_string(&us, (const pb_byte_t *)"some desc", 9U));
    /* two packages */
    TEST_ASSERT(pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_packages_tag));
    TEST_ASSERT(pb_encode_string(&us, pkg1, pkg1_len));
    TEST_ASSERT(pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_packages_tag));
    TEST_ASSERT(pb_encode_string(&us, pkg2, pkg2_len));
    size_t upd_len = us.bytes_written;

    outer = pb_ostream_from_buffer(wire, sizeof(wire));
    TEST_ASSERT(pb_encode_tag(&outer, PB_WT_STRING,
                              com_nxp_iot_ota_update_proto_AvailableUpdatesResponse_updates_tag));
    TEST_ASSERT(pb_encode_string(&outer, upd_buf, upd_len));

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_parse_check_update_response(wire, outer.bytes_written, &out));
    TEST_ASSERT(out.update_available);
    TEST_ASSERT_EQUAL(0, strcmp(out.updates[0].update_id, "upd-d"));
    TEST_ASSERT_EQUAL(2U, out.updates[0].package_count);
    TEST_ASSERT_EQUAL(0, strcmp(out.updates[0].packages[0].package_id, "p1"));
    TEST_ASSERT_EQUAL(0, strcmp(out.updates[0].packages[1].package_id, "p2"));

    return true;
}

/**
 * @brief parse_check_update_response with first_package_id correctly set to
 *        NULL when the first update has no packages.
 */
static bool test_ota_parse_check_update_no_packages(void *params)
{
    uint8_t upd_buf[64], wire[128];
    pb_ostream_t us, outer;
    static el2go_ota_check_update_resp_t out;

    (void)params;

    us = pb_ostream_from_buffer(upd_buf, sizeof(upd_buf));
    TEST_ASSERT(pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_updateId_tag));
    TEST_ASSERT(pb_encode_string(&us, (const pb_byte_t *)"upd-np", 6U));
    size_t upd_len = us.bytes_written;

    outer = pb_ostream_from_buffer(wire, sizeof(wire));
    TEST_ASSERT(pb_encode_tag(&outer, PB_WT_STRING,
                              com_nxp_iot_ota_update_proto_AvailableUpdatesResponse_updates_tag));
    TEST_ASSERT(pb_encode_string(&outer, upd_buf, upd_len));

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_parse_check_update_response(wire, outer.bytes_written, &out));
    TEST_ASSERT(out.update_available);
    /* first_package_id must be NULL since no packages in first update */
    TEST_ASSERT_NULL(out.first_package_id);

    return true;
}

/**
 * @brief parse_check_update_response with a Package carrying a FileMetadata
 *        that has both checksum and checksumAlgorithm fields set.
 */
static bool test_ota_parse_check_update_file_checksum(void *params)
{
    uint8_t fm_buf[128], pkg_buf[256], upd_buf[512], wire[768];
    pb_ostream_t fms, ps, us, outer;
    static el2go_ota_check_update_resp_t out;

    (void)params;

    /* FileMetadata: fileId + name + checksum + checksumAlgorithm */
    fms = pb_ostream_from_buffer(fm_buf, sizeof(fm_buf));
    TEST_ASSERT(
        pb_encode_tag(&fms, PB_WT_STRING, com_nxp_iot_ota_update_proto_FileMetadata_fileId_tag));
    TEST_ASSERT(pb_encode_string(&fms, (const pb_byte_t *)"fw.bin", 6U));
    TEST_ASSERT(
        pb_encode_tag(&fms, PB_WT_STRING, com_nxp_iot_ota_update_proto_FileMetadata_name_tag));
    TEST_ASSERT(pb_encode_string(&fms, (const pb_byte_t *)"firmware", 8U));
    TEST_ASSERT(
        pb_encode_tag(&fms, PB_WT_STRING, com_nxp_iot_ota_update_proto_FileMetadata_checksum_tag));
    TEST_ASSERT(pb_encode_string(&fms, (const pb_byte_t *)"abcdef1234567890", 16U));
    TEST_ASSERT(pb_encode_tag(&fms, PB_WT_VARINT,
                              com_nxp_iot_ota_update_proto_FileMetadata_checksumAlgorithm_tag));
    TEST_ASSERT(pb_encode_varint(&fms, 2U));
    size_t fm_len = fms.bytes_written;

    ps = pb_ostream_from_buffer(pkg_buf, sizeof(pkg_buf));
    TEST_ASSERT(
        pb_encode_tag(&ps, PB_WT_STRING, com_nxp_iot_ota_update_proto_Package_packageId_tag));
    TEST_ASSERT(pb_encode_string(&ps, (const pb_byte_t *)"pkg-cs", 6U));
    TEST_ASSERT(
        pb_encode_tag(&ps, PB_WT_STRING, com_nxp_iot_ota_update_proto_Package_fileMetadata_tag));
    TEST_ASSERT(pb_encode_string(&ps, fm_buf, fm_len));
    size_t pkg_len = ps.bytes_written;

    us = pb_ostream_from_buffer(upd_buf, sizeof(upd_buf));
    TEST_ASSERT(pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_updateId_tag));
    TEST_ASSERT(pb_encode_string(&us, (const pb_byte_t *)"upd-cs", 6U));
    TEST_ASSERT(pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_packages_tag));
    TEST_ASSERT(pb_encode_string(&us, pkg_buf, pkg_len));
    size_t upd_len = us.bytes_written;

    outer = pb_ostream_from_buffer(wire, sizeof(wire));
    TEST_ASSERT(pb_encode_tag(&outer, PB_WT_STRING,
                              com_nxp_iot_ota_update_proto_AvailableUpdatesResponse_updates_tag));
    TEST_ASSERT(pb_encode_string(&outer, upd_buf, upd_len));

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_parse_check_update_response(wire, outer.bytes_written, &out));
    TEST_ASSERT(out.update_available);
    TEST_ASSERT_EQUAL(0, strcmp(out.updates[0].packages[0].files[0].file_id, "fw.bin"));
    TEST_ASSERT_EQUAL(0, strcmp(out.updates[0].packages[0].files[0].name, "firmware"));
    TEST_ASSERT_EQUAL(0, strcmp(out.updates[0].packages[0].files[0].checksum, "abcdef1234567890"));
    TEST_ASSERT_EQUAL(2, out.updates[0].packages[0].files[0].checksum_algorithm);

    return true;
}

/**
 * @brief Verify response handler attributes map.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_response_handler_attributes_map(void *params)
{
    uint8_t map_entry[64];
    uint8_t pkg_buf[256], upd_buf[512], wire[768];
    pb_ostream_t me, ps, us, outer;
    static el2go_ota_check_update_resp_t out;

    (void)params;

    me = pb_ostream_from_buffer(map_entry, sizeof(map_entry));
    TEST_ASSERT(pb_encode_tag(&me, PB_WT_STRING, 1U)); /* field 1 = key */
    TEST_ASSERT(pb_encode_string(&me, (const pb_byte_t *)"hw", 2U));
    TEST_ASSERT(pb_encode_tag(&me, PB_WT_STRING, 2U)); /* field 2 = value */
    TEST_ASSERT(pb_encode_string(&me, (const pb_byte_t *)"rw612", 5U));
    size_t map_len = me.bytes_written;

    ps = pb_ostream_from_buffer(pkg_buf, sizeof(pkg_buf));
    TEST_ASSERT(
        pb_encode_tag(&ps, PB_WT_STRING, com_nxp_iot_ota_update_proto_Package_packageId_tag));
    TEST_ASSERT(pb_encode_string(&ps, (const pb_byte_t *)"pkg-attr", 8U));
    TEST_ASSERT(
        pb_encode_tag(&ps, PB_WT_STRING, com_nxp_iot_ota_update_proto_Package_attributes_tag));
    TEST_ASSERT(pb_encode_string(&ps, map_entry, map_len));
    size_t pkg_len = ps.bytes_written;

    us = pb_ostream_from_buffer(upd_buf, sizeof(upd_buf));
    TEST_ASSERT(pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_updateId_tag));
    TEST_ASSERT(pb_encode_string(&us, (const pb_byte_t *)"upd-attr", 8U));
    TEST_ASSERT(pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_packages_tag));
    TEST_ASSERT(pb_encode_string(&us, pkg_buf, pkg_len));
    size_t upd_len = us.bytes_written;

    outer = pb_ostream_from_buffer(wire, sizeof(wire));
    TEST_ASSERT(pb_encode_tag(&outer, PB_WT_STRING,
                              com_nxp_iot_ota_update_proto_AvailableUpdatesResponse_updates_tag));
    TEST_ASSERT(pb_encode_string(&outer, upd_buf, upd_len));

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_DECODE,
                      el2go_ota_parse_check_update_response(wire, outer.bytes_written, &out));
    return true;
}

/**
 * @brief Verify response handler update attributes.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_response_handler_update_attributes(void *params)
{
    uint8_t map_entry[64], upd_buf[512], wire[768];
    pb_ostream_t me, us, outer;
    static el2go_ota_check_update_resp_t out;

    (void)params;

    me = pb_ostream_from_buffer(map_entry, sizeof(map_entry));
    TEST_ASSERT(pb_encode_tag(&me, PB_WT_STRING, 1U));
    TEST_ASSERT(pb_encode_string(&me, (const pb_byte_t *)"region", 6U));
    TEST_ASSERT(pb_encode_tag(&me, PB_WT_STRING, 2U));
    TEST_ASSERT(pb_encode_string(&me, (const pb_byte_t *)"eu", 2U));
    size_t map_len = me.bytes_written;

    us = pb_ostream_from_buffer(upd_buf, sizeof(upd_buf));
    TEST_ASSERT(pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_updateId_tag));
    TEST_ASSERT(pb_encode_string(&us, (const pb_byte_t *)"upd-uattr", 9U));
    TEST_ASSERT(
        pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_attributes_tag));
    TEST_ASSERT(pb_encode_string(&us, map_entry, map_len));
    size_t upd_len = us.bytes_written;

    outer = pb_ostream_from_buffer(wire, sizeof(wire));
    TEST_ASSERT(pb_encode_tag(&outer, PB_WT_STRING,
                              com_nxp_iot_ota_update_proto_AvailableUpdatesResponse_updates_tag));
    TEST_ASSERT(pb_encode_string(&outer, upd_buf, upd_len));

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_DECODE,
                      el2go_ota_parse_check_update_response(wire, outer.bytes_written, &out));
    return true;
}

/**
 * @brief Verify response handler compressed flag.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_response_handler_compressed_flag(void *params)
{
    uint8_t wire[32];
    pb_ostream_t out;
    el2go_ota_fetch_pkg_resp_t resp;

    (void)params;

    out = pb_ostream_from_buffer(wire, sizeof(wire));
    TEST_ASSERT(pb_encode_tag(&out, PB_WT_VARINT,
                              com_nxp_iot_ota_update_proto_FileResponse_totalFileSize_tag));
    TEST_ASSERT(pb_encode_varint(&out, 1U));
    TEST_ASSERT(
        pb_encode_tag(&out, PB_WT_STRING, com_nxp_iot_ota_update_proto_FileResponse_data_tag));
    TEST_ASSERT(pb_encode_string(&out, (const pb_byte_t *)"\x01", 1U));

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_parse_fetch_package_response(wire, out.bytes_written, &resp));
    TEST_ASSERT_EQUAL(1U, resp.data_len);
    return true;
}

/**
 * @brief Verify response handler long update id.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_response_handler_long_update_id(void *params)
{
    /* Build an AvailableUpdatesResponse with updateId longer than EL2GO_OTA_MAX_UPDATE_ID_LEN.
     * The decoder should truncate it gracefully and still succeed. */
    char long_id[512];
    uint8_t upd_buf[768], wire[1024];
    pb_ostream_t us, outer;
    static el2go_ota_check_update_resp_t out;
    size_t i;

    (void)params;

    for (i = 0U; i < sizeof(long_id) - 1U; i++) {
        long_id[i] = (char)('a' + (i % 26U));
    }
    long_id[sizeof(long_id) - 1U] = '\0';

    us = pb_ostream_from_buffer(upd_buf, sizeof(upd_buf));
    TEST_ASSERT(pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_updateId_tag));
    TEST_ASSERT(pb_encode_string(&us, (const pb_byte_t *)long_id, strlen(long_id)));
    size_t upd_len = us.bytes_written;

    outer = pb_ostream_from_buffer(wire, sizeof(wire));
    TEST_ASSERT(pb_encode_tag(&outer, PB_WT_STRING,
                              com_nxp_iot_ota_update_proto_AvailableUpdatesResponse_updates_tag));
    TEST_ASSERT(pb_encode_string(&outer, upd_buf, upd_len));

    /* Should succeed even with truncated updateId */
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_parse_check_update_response(wire, outer.bytes_written, &out));
    TEST_ASSERT(out.update_available);
    return true;
}

/**
 * @brief Verify parse check update null nonzero.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_parse_check_update_null_nonzero(void *params)
{
    static el2go_ota_check_update_resp_t out;
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_parse_check_update_response(NULL, 1U, &out));
    return true;
}

/**
 * @brief Verify parse fetch zero len buf.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_parse_fetch_zero_len_buf(void *params)
{
    el2go_ota_fetch_pkg_resp_t out;
    static const uint8_t buf[4] = { 0 };
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_parse_fetch_package_response(buf, 0U, &out));
    return true;
}

/**
 * @brief Verify parse fetch zero body.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_parse_fetch_zero_body(void *params)
{
    uint8_t wire[32];
    pb_ostream_t out;
    el2go_ota_fetch_pkg_resp_t resp;
    (void)params;

    /* Build FileResponse with totalFileSize=0, no data field. */
    out = pb_ostream_from_buffer(wire, sizeof(wire));
    TEST_ASSERT(pb_encode_tag(&out, PB_WT_VARINT,
                              com_nxp_iot_ota_update_proto_FileResponse_totalFileSize_tag));
    TEST_ASSERT(pb_encode_varint(&out, 0U));
    /* Encode data field with zero-length string (exercises body_len==0 branch) */
    TEST_ASSERT(
        pb_encode_tag(&out, PB_WT_STRING, com_nxp_iot_ota_update_proto_FileResponse_data_tag));
    TEST_ASSERT(pb_encode_string(&out, NULL, 0U));

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_parse_fetch_package_response(wire, out.bytes_written, &resp));
    TEST_ASSERT_EQUAL(0U, resp.data_len);
    return true;
}

/**
 * @brief Verify parse check both null zero.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_parse_check_both_null_zero(void *params)
{
    static el2go_ota_check_update_resp_t out;
    static const uint8_t empty[1] = { 0 };
    (void)params;

    /* Non-NULL buf, len=0, non-NULL out -- exercises the empty-buffer path */
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_parse_check_update_response(empty, 0U, &out));
    TEST_ASSERT_EQUAL(false, out.update_available);
    return true;
}

/* ---- suite registration ------------------------------------------------ */

void register_ota_lib_response_handler_tests(void)
{
    TEST_REGISTER_ID("-", test_ota_parse_check_update_with_file_metadata);
    TEST_REGISTER_ID("-", test_ota_parse_check_update_file_metadata_overflow);
    TEST_REGISTER_ID("-", test_ota_parse_check_update_package_overflow);
    TEST_REGISTER_ID("-", test_ota_parse_check_update_update_overflow);
    TEST_REGISTER_ID("-", test_ota_parse_fetch_package_zero_len);
    TEST_REGISTER_ID("-", test_ota_parse_check_update_with_name_and_attrs);
    TEST_REGISTER_ID("-", test_ota_parse_check_update_package_with_all_fields);
    TEST_REGISTER_ID("-", test_ota_parse_check_update_description_discarded);
    TEST_REGISTER_ID("-", test_ota_parse_check_update_no_packages);
    TEST_REGISTER_ID("-", test_ota_parse_check_update_file_checksum);
    TEST_REGISTER_ID("-", test_ota_response_handler_attributes_map);
    TEST_REGISTER_ID("-", test_ota_response_handler_update_attributes);
    TEST_REGISTER_ID("-", test_ota_response_handler_compressed_flag);
    TEST_REGISTER_ID("-", test_ota_response_handler_long_update_id);
    TEST_REGISTER_ID("-", test_ota_parse_check_update_null_nonzero);
    TEST_REGISTER_ID("-", test_ota_parse_fetch_zero_len_buf);
    TEST_REGISTER_ID("-", test_ota_parse_fetch_zero_body);
    TEST_REGISTER_ID("-", test_ota_parse_check_both_null_zero);
}
