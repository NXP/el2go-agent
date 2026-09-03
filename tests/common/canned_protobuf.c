/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "canned_protobuf.h"

#include <string.h>

#include <pb_encode.h>

#include "types/package.pb.h"
#include "types/update.pb.h"
#include "types/available_updates_response.pb.h"
#include "types/file_response.pb.h"
#include "types/range.pb.h"

static int encode_package(uint8_t *buf, size_t buf_size, const char *package_id, const char *name,
                          const char *version, size_t *out_len)
{
    pb_ostream_t ps = pb_ostream_from_buffer(buf, buf_size);

    if (!pb_encode_tag(&ps, PB_WT_STRING, com_nxp_iot_ota_update_proto_Package_packageId_tag) ||
        !pb_encode_string(&ps, (const pb_byte_t *)package_id, strlen(package_id))) {
        return -1;
    }
    if (!pb_encode_tag(&ps, PB_WT_STRING, com_nxp_iot_ota_update_proto_Package_name_tag) ||
        !pb_encode_string(&ps, (const pb_byte_t *)name, strlen(name))) {
        return -1;
    }
    if (!pb_encode_tag(&ps, PB_WT_STRING, com_nxp_iot_ota_update_proto_Package_version_tag) ||
        !pb_encode_string(&ps, (const pb_byte_t *)version, strlen(version))) {
        return -1;
    }

    *out_len = ps.bytes_written;
    return 0;
}

static int encode_update(uint8_t *buf, size_t buf_size, const char *update_id, const char *name,
                         const uint8_t *pkg_buf, size_t pkg_len, size_t *out_len)
{
    pb_ostream_t us = pb_ostream_from_buffer(buf, buf_size);

    if (!pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_updateId_tag) ||
        !pb_encode_string(&us, (const pb_byte_t *)update_id, strlen(update_id))) {
        return -1;
    }
    if (!pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_name_tag) ||
        !pb_encode_string(&us, (const pb_byte_t *)name, strlen(name))) {
        return -1;
    }
    if (!pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_packages_tag) ||
        !pb_encode_string(&us, pkg_buf, pkg_len)) {
        return -1;
    }

    *out_len = us.bytes_written;
    return 0;
}

int canned_check_update_one_package(uint8_t *buf, size_t buf_size, size_t *out_len)
{
    uint8_t pkg_buf[128];
    uint8_t upd_buf[256];
    size_t pkg_len = 0U;
    size_t upd_len = 0U;
    pb_ostream_t outer;

    if (buf == NULL || out_len == NULL) {
        return -1;
    }

    if (encode_package(pkg_buf, sizeof(pkg_buf), "pkg-1", "fw", "1.0.0", &pkg_len) != 0) {
        return -1;
    }
    if (encode_update(upd_buf, sizeof(upd_buf), "upd-1", "update-one", pkg_buf, pkg_len,
                      &upd_len) != 0) {
        return -1;
    }

    outer = pb_ostream_from_buffer(buf, buf_size);
    if (!pb_encode_tag(&outer, PB_WT_STRING,
                       com_nxp_iot_ota_update_proto_AvailableUpdatesResponse_updates_tag) ||
        !pb_encode_string(&outer, upd_buf, upd_len)) {
        return -1;
    }

    *out_len = outer.bytes_written;
    return 0;
}

int canned_check_update_empty(uint8_t *buf, size_t buf_size, size_t *out_len)
{
    if (buf == NULL || out_len == NULL) {
        return -1;
    }
    (void)buf_size;

    *out_len = 0U;
    return 0;
}

/*
 * Encode a Range submessage { start=range_start, end=range_end } into buf.
 * Returns 0 on success, -1 on encode failure.
 */
static int encode_range(uint8_t *buf, size_t buf_size, int64_t range_start, int64_t range_end,
                        size_t *out_len)
{
    pb_ostream_t rs = pb_ostream_from_buffer(buf, buf_size);

    if (!pb_encode_tag(&rs, PB_WT_VARINT, com_nxp_iot_ota_update_proto_Range_start_tag) ||
        !pb_encode_varint(&rs, (uint64_t)range_start)) {
        return -1;
    }
    if (!pb_encode_tag(&rs, PB_WT_VARINT, com_nxp_iot_ota_update_proto_Range_end_tag) ||
        !pb_encode_varint(&rs, (uint64_t)range_end)) {
        return -1;
    }

    *out_len = rs.bytes_written;
    return 0;
}

int canned_fetch_package_chunk(uint8_t *buf, size_t buf_size, int64_t range_start,
                               int64_t range_end, const uint8_t *data, size_t data_len,
                               size_t *out_len)
{
    uint8_t range_buf[32];
    size_t range_len = 0U;
    pb_ostream_t out;

    if (buf == NULL || out_len == NULL || (data == NULL && data_len > 0U)) {
        return -1;
    }

    /*
     * The new schema nests rangeStart/rangeEnd inside a Range submessage
     * on FileResponse.range (tag 2, length-delimited). Encode the Range
     * body into a scratch buffer first, then splice it into the outer
     * FileResponse as a length-delimited field.
     */
    if (encode_range(range_buf, sizeof(range_buf), range_start, range_end, &range_len) != 0) {
        return -1;
    }

    out = pb_ostream_from_buffer(buf, buf_size);

    if (!pb_encode_tag(&out, PB_WT_STRING, com_nxp_iot_ota_update_proto_FileResponse_range_tag) ||
        !pb_encode_string(&out, range_buf, range_len)) {
        return -1;
    }

    if (data_len > 0U) {
        if (!pb_encode_tag(&out, PB_WT_STRING,
                           com_nxp_iot_ota_update_proto_FileResponse_data_tag) ||
            !pb_encode_string(&out, data, data_len)) {
            return -1;
        }
    }

    *out_len = out.bytes_written;
    return 0;
}

int canned_report_status_ack(uint8_t *buf, size_t buf_size, size_t *out_len)
{
    if (buf == NULL || out_len == NULL) {
        return -1;
    }
    (void)buf_size;

    *out_len = 0U;
    return 0;
}
