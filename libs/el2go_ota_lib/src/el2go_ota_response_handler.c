/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>

#include <pb_decode.h>

#include "debug.h"
#include "el2go_ota_response_handler.h"
#include "types/available_updates_response.pb.h"
#include "types/update.pb.h"
#include "types/package.pb.h"
#include "types/file_metadata.pb.h"
#include "types/file_response.pb.h"

/* proto3 map<string,string> entry field numbers (wire format, RFC 3.10). */
#define MAP_ENTRY_KEY_FIELD_TAG 1U   /* field 1 = key   */
#define MAP_ENTRY_VALUE_FIELD_TAG 2U /* field 2 = value */

/* Internal helpers -- string decode callback */

typedef struct {
    char *dst;
    size_t dst_size;
} decode_str_ctx_t;

/**
 * @brief nanopb decode callback: copies a string/bytes field into a
 *        fixed-size destination buffer, null-terminating the result.
 *        Oversized strings are truncated and a warning is logged.
 */
static bool decode_str_cb(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
    decode_str_ctx_t *ctx = (decode_str_ctx_t *)(*arg);
    size_t len = stream->bytes_left;
    bool status = false;
    (void)field;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (len >= ctx->dst_size) {
        EL2GO_DBG_PRINTF(ERROR, "decode_str_cb: string too long (%zu >= %zu), truncating\n", len,
                         ctx->dst_size);
        len = ctx->dst_size - 1U;
    }

    if (!pb_read(stream, (pb_byte_t *)ctx->dst, len)) {
        goto exit;
    }
    /* Drain any remaining bytes if we truncated. */
    if (stream->bytes_left > 0U) {
        if (!pb_read(stream, NULL, stream->bytes_left)) {
            goto exit;
        }
    }
    ctx->dst[len] = '\0';
    status = true;

exit:
    return status;
}

/* Internal helpers -- map<string,string> attribute callback (log + discard) */

/**
 * @brief Decode one map-entry sub-message, log the key/value pair, then
 *        discard.  Used for all map<string,string> attribute fields.
 */
static bool decode_attr_map_cb(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
    char key[128] = { 0 };
    char value[256] = { 0 };
    pb_istream_t sub = { 0 };
    pb_istream_t fld = { 0 };
    uint32_t tag = 0U;
    pb_wire_type_t wire_type = PB_WT_VARINT;
    bool eof = false;
    char *dest = NULL;
    size_t dest_max = 0U;
    size_t len = 0U;
    bool status = false;
    (void)field;
    (void)arg;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!pb_make_string_substream(stream, &sub)) {
        goto exit; /* sub not open -- skip close_sub */
    }

    while (sub.bytes_left > 0U) {
        if (!pb_decode_tag(&sub, &wire_type, &tag, &eof)) {
            break;
        }
        if (eof) {
            break;
        }

        if (wire_type == PB_WT_STRING &&
            (tag == MAP_ENTRY_KEY_FIELD_TAG || tag == MAP_ENTRY_VALUE_FIELD_TAG)) {
            if (!pb_make_string_substream(&sub, &fld)) {
                goto close_sub;
            }
            dest = (tag == MAP_ENTRY_KEY_FIELD_TAG) ? key : value;
            dest_max = (tag == MAP_ENTRY_KEY_FIELD_TAG) ? (sizeof(key) - 1U) : (sizeof(value) - 1U);
            len = fld.bytes_left < dest_max ? fld.bytes_left : dest_max;
            if (!pb_read(&fld, (pb_byte_t *)dest, len)) {
                (void)pb_close_string_substream(&sub, &fld);
                goto close_sub;
            }
            dest[len] = '\0';
            if (!pb_close_string_substream(&sub, &fld)) {
                goto close_sub;
            }
        } else {
            if (!pb_skip_field(&sub, wire_type)) {
                goto close_sub;
            }
        }
    }

    EL2GO_DBG_PRINTF(INFO, "attribute: \"%s\" = \"%s\"\n", key, value);
    status = true;

close_sub:
    (void)pb_close_string_substream(stream, &sub);

exit:
    return status;
}

/* Internal helpers -- FileMetadata decode callback */

typedef struct {
    el2go_ota_package_info_t *pkg;
} decode_file_metadata_ctx_t;

/**
 * @brief nanopb decode callback called once per FileMetadata entry inside
 *        a Package sub-message.  Stores up to EL2GO_OTA_MAX_FILE_METADATA
 *        entries; extras are silently drained.
 */
static bool decode_file_metadata_cb(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
    decode_file_metadata_ctx_t *ctx = (decode_file_metadata_ctx_t *)(*arg);
    el2go_ota_file_metadata_t *fm = NULL;
    decode_str_ctx_t fid_ctx = { 0 };
    decode_str_ctx_t name_ctx = { 0 };
    decode_str_ctx_t cks_ctx = { 0 };
    com_nxp_iot_ota_update_proto_FileMetadata fmsg =
        com_nxp_iot_ota_update_proto_FileMetadata_init_zero;
    bool status = false;
    (void)field;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (ctx->pkg->file_count >= EL2GO_OTA_MAX_FILE_METADATA) {
        EL2GO_DBG_PRINTF(ERROR, "decode_file_metadata_cb: "
                                "too many FileMetadata entries, skipping extra\n");
        /* Drain the remaining bytes that nanopb handed us. */
        if (!pb_read(stream, NULL, stream->bytes_left)) {
            goto exit;
        }
        status = true;
        goto exit;
    }

    fm = &ctx->pkg->files[ctx->pkg->file_count];

    fid_ctx.dst = fm->file_id;
    fid_ctx.dst_size = EL2GO_OTA_MAX_FILE_ID_LEN;
    name_ctx.dst = fm->name;
    name_ctx.dst_size = EL2GO_OTA_MAX_NAME_LEN;
    cks_ctx.dst = fm->checksum;
    cks_ctx.dst_size = EL2GO_OTA_MAX_CHECKSUM_LEN;

    fmsg.fileId.funcs.decode = decode_str_cb;
    fmsg.fileId.arg = &fid_ctx;
    fmsg.name.funcs.decode = decode_str_cb;
    fmsg.name.arg = &name_ctx;
    fmsg.description.funcs.decode = NULL; /* discard */
    fmsg.checksum.funcs.decode = decode_str_cb;
    fmsg.checksum.arg = &cks_ctx;
    fmsg.attributes.funcs.decode = decode_attr_map_cb;
    fmsg.attributes.arg = NULL;

    /* nanopb already consumed the length prefix and passed us a substream
     * containing exactly the FileMetadata message bytes -- decode directly. */
    if (!pb_decode(stream, com_nxp_iot_ota_update_proto_FileMetadata_fields, &fmsg)) {
        EL2GO_DBG_PRINTF(ERROR, "decode_file_metadata_cb: pb_decode failed: %s\n",
                         PB_GET_ERROR(stream));
        goto exit;
    }

    fm->size = fmsg.size;
    fm->checksum_algorithm = fmsg.checksumAlgorithm;
    ctx->pkg->file_count++;
    status = true;

exit:
    return status;
}

/* Internal helpers -- Package decode callback */

typedef struct {
    el2go_ota_update_info_t *upd;
} decode_package_ctx_t;

/**
 * @brief nanopb decode callback called once per Package entry inside an
 *        Update sub-message.  Stores up to EL2GO_OTA_MAX_PACKAGES entries;
 *        extras are silently drained.
 */
static bool decode_package_cb(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
    decode_package_ctx_t *ctx = (decode_package_ctx_t *)(*arg);
    el2go_ota_package_info_t *pkg = NULL;
    decode_str_ctx_t pid_ctx = { 0 };
    decode_str_ctx_t name_ctx = { 0 };
    decode_str_ctx_t ver_ctx = { 0 };
    decode_file_metadata_ctx_t fm_ctx = { 0 };
    com_nxp_iot_ota_update_proto_Package pmsg = com_nxp_iot_ota_update_proto_Package_init_zero;
    bool status = false;
    (void)field;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (ctx->upd->package_count >= EL2GO_OTA_MAX_PACKAGES) {
        EL2GO_DBG_PRINTF(ERROR, "decode_package_cb: "
                                "too many Package entries, skipping extra\n");
        if (!pb_read(stream, NULL, stream->bytes_left)) {
            goto exit;
        }
        status = true;
        goto exit;
    }

    pkg = &ctx->upd->packages[ctx->upd->package_count];

    pid_ctx.dst = pkg->package_id;
    pid_ctx.dst_size = EL2GO_OTA_MAX_PACKAGE_ID_LEN;
    name_ctx.dst = pkg->name;
    name_ctx.dst_size = EL2GO_OTA_MAX_NAME_LEN;
    ver_ctx.dst = pkg->version;
    ver_ctx.dst_size = EL2GO_OTA_MAX_VERSION_LEN;

    fm_ctx.pkg = pkg;

    pmsg.packageId.funcs.decode = decode_str_cb;
    pmsg.packageId.arg = &pid_ctx;
    pmsg.name.funcs.decode = decode_str_cb;
    pmsg.name.arg = &name_ctx;
    pmsg.description.funcs.decode = NULL; /* discard */
    pmsg.version.funcs.decode = decode_str_cb;
    pmsg.version.arg = &ver_ctx;
    pmsg.attributes.funcs.decode = decode_attr_map_cb;
    pmsg.attributes.arg = NULL;
    pmsg.fileMetadata.funcs.decode = decode_file_metadata_cb;
    pmsg.fileMetadata.arg = &fm_ctx;

    /* nanopb already consumed the length prefix and passed us a substream. */
    if (!pb_decode(stream, com_nxp_iot_ota_update_proto_Package_fields, &pmsg)) {
        EL2GO_DBG_PRINTF(ERROR, "decode_package_cb: pb_decode failed: %s\n", PB_GET_ERROR(stream));
        goto exit;
    }

    ctx->upd->package_count++;
    status = true;

exit:
    return status;
}

/* Internal helpers -- Update decode callback */

typedef struct {
    el2go_ota_check_update_resp_t *resp;
} decode_update_ctx_t;

/**
 * @brief nanopb decode callback called once per Update entry in the
 *        AvailableUpdatesResponse.  Stores up to EL2GO_OTA_MAX_UPDATES
 *        entries; extras are silently drained.
 */
static bool decode_update_cb(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
    decode_update_ctx_t *ctx = (decode_update_ctx_t *)(*arg);
    el2go_ota_update_info_t *upd = NULL;
    decode_str_ctx_t uid_ctx = { 0 };
    decode_str_ctx_t name_ctx = { 0 };
    decode_package_ctx_t pkg_ctx = { 0 };
    com_nxp_iot_ota_update_proto_Update umsg = com_nxp_iot_ota_update_proto_Update_init_zero;
    bool status = false;
    (void)field;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (ctx->resp->update_count >= EL2GO_OTA_MAX_UPDATES) {
        EL2GO_DBG_PRINTF(ERROR, "decode_update_cb: "
                                "too many Update entries, skipping extra\n");
        if (!pb_read(stream, NULL, stream->bytes_left)) {
            goto exit;
        }
        status = true;
        goto exit;
    }

    upd = &ctx->resp->updates[ctx->resp->update_count];

    uid_ctx.dst = upd->update_id;
    uid_ctx.dst_size = EL2GO_OTA_MAX_UPDATE_ID_LEN;
    name_ctx.dst = upd->name;
    name_ctx.dst_size = EL2GO_OTA_MAX_NAME_LEN;

    pkg_ctx.upd = upd;

    umsg.updateId.funcs.decode = decode_str_cb;
    umsg.updateId.arg = &uid_ctx;
    umsg.name.funcs.decode = decode_str_cb;
    umsg.name.arg = &name_ctx;
    umsg.description.funcs.decode = NULL; /* discard */
    umsg.attributes.funcs.decode = decode_attr_map_cb;
    umsg.attributes.arg = NULL;
    umsg.packages.funcs.decode = decode_package_cb;
    umsg.packages.arg = &pkg_ctx;

    /* nanopb already consumed the length prefix and passed us a substream. */
    if (!pb_decode(stream, com_nxp_iot_ota_update_proto_Update_fields, &umsg)) {
        EL2GO_DBG_PRINTF(ERROR, "decode_update_cb: pb_decode failed: %s\n", PB_GET_ERROR(stream));
        goto exit;
    }

    ctx->resp->update_count++;
    status = true;

exit:
    return status;
}

/* Internal helpers -- FileResponse data callback (zero-copy) */

typedef struct {
    const uint8_t **data_ptr;
    size_t *data_len;
} decode_data_ctx_t;

/**
 * @brief nanopb decode callback for the FileResponse.data bytes field.
 *
 * Zero-copy: captures the pointer into the backing wire buffer and the
 * length, then drains the stream without copying the bytes.
 */
static bool decode_data_cb(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
    decode_data_ctx_t *ctx = (decode_data_ctx_t *)(*arg);
    bool status = false;
    (void)field;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    /* For pb_istream_from_buffer() streams, stream->state points to the
     * next byte to be read.  Capture it before draining. */
    *ctx->data_ptr = (const uint8_t *)stream->state;
    *ctx->data_len = stream->bytes_left;

    if (!pb_read(stream, NULL, stream->bytes_left)) {
        goto exit;
    }
    status = true;

exit:
    return status;
}

/* Public API */

el2go_ota_status_t el2go_ota_parse_check_update_response(const uint8_t *buf, size_t buf_len,
                                                         el2go_ota_check_update_resp_t *out)
{
    decode_update_ctx_t upd_ctx = { 0 };
    com_nxp_iot_ota_update_proto_AvailableUpdatesResponse msg =
        com_nxp_iot_ota_update_proto_AvailableUpdatesResponse_init_zero;
    pb_istream_t stream = { 0 };
    el2go_ota_status_t status = EL2GO_OTA_ERROR_DECODE;

    EL2GO_DBG_TRACE_API_CALL;

    if (out == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "parse_check_update_response: out is NULL\n");
        status = EL2GO_OTA_ERROR_INVALID_PARAM;
        goto exit;
    }

    memset(out, 0, sizeof(*out));

    /* An empty wire buffer means the server returned no updates. */
    if (buf_len == 0U) {
        out->update_available = false;
        status = EL2GO_OTA_SUCCESS;
        goto exit;
    }

    if (buf == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "parse_check_update_response: buf is NULL\n");
        status = EL2GO_OTA_ERROR_INVALID_PARAM;
        goto exit;
    }

    upd_ctx.resp = out;

    msg.updates.funcs.decode = decode_update_cb;
    msg.updates.arg = &upd_ctx;

    stream = pb_istream_from_buffer(buf, buf_len);

    if (!pb_decode(&stream, com_nxp_iot_ota_update_proto_AvailableUpdatesResponse_fields, &msg)) {
        EL2GO_DBG_PRINTF(ERROR, "parse_check_update_response: pb_decode failed: %s\n",
                         PB_GET_ERROR(&stream));
        goto exit;
    }

    out->update_available = (out->update_count > 0U);

    if (out->update_count > 0U) {
        out->first_update_id = out->updates[0].update_id;
        if (out->updates[0].package_count > 0U) {
            out->first_package_id = out->updates[0].packages[0].package_id;
        }
    }

    status = EL2GO_OTA_SUCCESS;

exit:
    return status;
}

el2go_ota_status_t el2go_ota_parse_fetch_package_response(const uint8_t *buf, size_t buf_len,
                                                          el2go_ota_fetch_pkg_resp_t *out)
{
    decode_data_ctx_t data_ctx = { 0 };
    com_nxp_iot_ota_update_proto_FileResponse msg =
        com_nxp_iot_ota_update_proto_FileResponse_init_zero;
    pb_istream_t stream = { 0 };
    el2go_ota_status_t status = EL2GO_OTA_ERROR_DECODE;

    EL2GO_DBG_TRACE_API_CALL;

    if ((buf == NULL) || (out == NULL) || (buf_len == 0U)) {
        EL2GO_DBG_PRINTF(ERROR, "parse_fetch_package_response: invalid arguments\n");
        status = EL2GO_OTA_ERROR_INVALID_PARAM;
        goto exit;
    }

    memset(out, 0, sizeof(*out));

    data_ctx.data_ptr = &out->data_ptr;
    data_ctx.data_len = &out->data_len;

    msg.data.funcs.decode = decode_data_cb;
    msg.data.arg = &data_ctx;

    stream = pb_istream_from_buffer(buf, buf_len);

    if (!pb_decode(&stream, com_nxp_iot_ota_update_proto_FileResponse_fields, &msg)) {
        EL2GO_DBG_PRINTF(ERROR, "parse_fetch_package_response: pb_decode failed: %s\n",
                         PB_GET_ERROR(&stream));
        goto exit;
    }

    out->total_file_size = msg.totalFileSize;
    out->range_start = msg.range.start;
    out->range_end = msg.range.end;
    status = EL2GO_OTA_SUCCESS;

exit:
    return status;
}

el2go_ota_status_t el2go_ota_parse_report_status_response(const uint8_t *buf, size_t buf_len)
{
    EL2GO_DBG_TRACE_API_CALL;

    /* The response for ReportUpdateStatus is google.protobuf.Empty,
     * which encodes to zero bytes on the wire. Accept and ignore any
     * non-zero length payload (forward compatibility). */
    (void)buf;
    (void)buf_len;

    return EL2GO_OTA_SUCCESS;
}
