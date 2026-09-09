/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/* Logging backend: console mirror plus a circular log on a dedicated flash
 * partition. Records are fixed size and carry a monotonic sequence number for
 * ordering; a sector is erased before it is reused on wrap. The log survives
 * reboot, power loss and rollback and is dumped oldest to newest.
 *
 * Satisfies requirements AGT-052 and AGT-014. */

#include "el2go_app_compiler.h"
#include "el2go_ota_diag.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/sys/printk.h>

/* Lines longer than this are truncated. */
#define EL2GO_OTA_DIAG_LINE_MAX 160U

/* Flash partition that backs the log. */
#define LOG_PARTITION log_partition
#define LOG_PARTITION_ID FIXED_PARTITION_ID(LOG_PARTITION)

#define LOG_RECORD_MAGIC 0x474C4F45U

#define LOG_RECORD_SIZE 256U
#define LOG_RECORD_TEXT_MAX (LOG_RECORD_SIZE - 16U)

/** @brief On-flash log record, one per fixed-size slot. */
typedef struct {
    uint32_t magic;                 /**< LOG_RECORD_MAGIC when the slot holds a valid record */
    uint32_t seq;                   /**< Monotonic sequence number used for ordering */
    uint32_t level;                 /**< el2go_ota_diag_level_t value */
    uint32_t len;                   /**< Length of text in bytes, excluding the terminator */
    char text[LOG_RECORD_TEXT_MAX]; /**< NUL-terminated log line */
} log_record_t;

BUILD_ASSERT(sizeof(log_record_t) == LOG_RECORD_SIZE, "log record size mismatch");

/*
 * Opened and cached once for lifetime of process. On the successful,
 * steady-state path the area is intentionally never closed. If init fails
 * after the open succeeds, the area is closed and the handle cleared so a
 * later retry does not leak or double-open. flash_area_close is currently a
 * nop in flash_map.h as per Zephyr Docs, but it is called for correctness and
 * forward compatibility.
 */
static const struct flash_area *s_fa;

static const struct device *s_flash_dev;
static uint32_t s_sector_size;
static uint32_t s_records_per_sector;
static uint32_t s_num_records;
static uint32_t s_write_index;
static uint32_t s_next_seq;
static bool s_ready;

/**
 * @brief Prepares the ring buffer for reading and writing
 *
 * Idempotent. Opens the log flash area, validates its geometry against the
 * record size, then scans all slots to locate the highest sequence number so
 * that writes resume after the most recent record and new sequence numbers
 * continue monotonically. On an empty log, writing starts at slot 0 with
 * sequence number 1.
 *
 * @retval 0 on success
 * @retval negative errno if the flash area cannot be opened or its geometry is
 *   incompatible with the record size
 */
static int ringbuf_init(void)
{
    struct flash_pages_info info = { 0 };
    log_record_t rec = { 0 };
    uint32_t max_seq = 0U;
    uint32_t max_idx = 0U;
    bool any = false;
    int rc = -1;

    if (s_ready) {
        return 0;
    }

    rc = flash_area_open(LOG_PARTITION_ID, &s_fa);
    if (rc != 0) {
        return rc;
    }

    s_flash_dev = flash_area_get_device(s_fa);
    if (s_flash_dev == NULL || !device_is_ready(s_flash_dev)) {
        rc = -ENODEV;
        goto flash_close;
    }

    rc = flash_get_page_info_by_offs(s_flash_dev, s_fa->fa_off, &info);
    if (rc != 0) {
        goto flash_close;
    }

    s_sector_size = (uint32_t)info.size;
    if (s_sector_size == 0U || (s_sector_size % LOG_RECORD_SIZE) != 0U) {
        rc = -EINVAL;
        goto flash_close;
    }

    s_records_per_sector = s_sector_size / LOG_RECORD_SIZE;
    s_num_records = (uint32_t)(s_fa->fa_size / LOG_RECORD_SIZE);
    if (s_num_records == 0U) {
        rc = -EINVAL;
        goto flash_close;
    }

    /* next write goes to slot after it */
    for (uint32_t i = 0U; i < s_num_records; i++) {
        rc = flash_area_read(s_fa, (off_t)(i * LOG_RECORD_SIZE), &rec, sizeof(rec));
        if (rc != 0) {
            goto flash_close;
        }
        if (rec.magic == LOG_RECORD_MAGIC && rec.seq != 0U) {
            any = true;
            if (rec.seq >= max_seq) {
                max_seq = rec.seq;
                max_idx = i;
            }
        }
    }

    if (any) {
        s_write_index = (max_idx + 1U) % s_num_records;
        s_next_seq = max_seq + 1U;
    } else {
        s_write_index = 0U;
        s_next_seq = 1U;
    }

    s_ready = true;
    return 0;

flash_close:
    /* Close the area opened above so a later retry does not leak or
     * double-open. flash_area_close is currently a nop but is called for
     * correctness and forward compatibility. */
    flash_area_close(s_fa);
    s_fa = NULL;
    return rc;
}

/**
 * @brief Appends one line to the circular flash log
 *
 * Ensures the ring buffer is initialized, truncates the line to fit a record,
 * and writes it to the current slot. When the slot is the first of a sector
 * the sector is erased first, which recycles the oldest records on wrap. The
 * write index and sequence number advance on success; failures are silently
 * dropped so logging never blocks the caller.
 *
 * @param[in] level Severity level stored in the record
 * @param[in] line  Line text to store
 * @param[in] len   Length of line in bytes
 */
static void ringbuf_append(el2go_ota_diag_level_t level, const char *line, size_t len)
{
    log_record_t rec;
    off_t sector_off = 0;
    off_t rec_off = 0;

    if (ringbuf_init() != 0) {
        return;
    }

    if (len >= LOG_RECORD_TEXT_MAX) {
        len = LOG_RECORD_TEXT_MAX - 1U;
    }

    memset(&rec, 0, sizeof(rec));

    rec.magic = LOG_RECORD_MAGIC;
    rec.seq = s_next_seq;
    rec.level = (uint32_t)level;
    rec.len = (uint32_t)len;
    memcpy(rec.text, line, len);
    rec.text[len] = '\0';

    /* erase before first record, on wrap recycles oldest */
    if ((s_write_index % s_records_per_sector) == 0U) {
        sector_off = (off_t)(s_write_index * LOG_RECORD_SIZE);
        if (flash_area_erase(s_fa, sector_off, s_sector_size) != 0) {
            return;
        }
    }

    rec_off = (off_t)(s_write_index * LOG_RECORD_SIZE);
    if (flash_area_write(s_fa, rec_off, &rec, sizeof(rec)) != 0) {
        return;
    }

    s_write_index = (s_write_index + 1U) % s_num_records;
    s_next_seq++;
}

/**
 * @brief Formats a log line, mirrors it to the console and stores it in flash.
 *
 * Ring buffer backend implementation of el2go_ota_diag_emit(). Formats fmt
 * with the variadic arguments into a fixed stack buffer, mirrors the result
 * to the console via printk for the HIL test runner, then appends it to the
 * flash ring buffer when its level is at least CONFIG_EL2GO_OTA_DIAG_MIN_LEVEL.
 *
 * @param[in] level  Severity level for the line.
 * @param[in] fmt    printf-style format string.
 * @param[in] ...    Arguments for fmt.
 */
void el2go_ota_diag_emit(el2go_ota_diag_level_t level, const char *fmt, ...)
{
    char line[EL2GO_OTA_DIAG_LINE_MAX];
    va_list ap;
    int n = -1;
    size_t len = 0U;

    va_start(ap, fmt);
    n = vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

    if (n < 0) {
        return;
    }

    len = (size_t)n;
    if (len >= sizeof(line)) {
        len = sizeof(line) - 1U;
    }

    /* mirror to console for HIL test runner */
    printk("%s", line);

    if ((int)level < CONFIG_EL2GO_OTA_DIAG_MIN_LEVEL) {
        return;
    }

    ringbuf_append(level, line, len);
}

/**
 * @brief Dumps the stored log to the console, oldest to newest
 *
 * Ring buffer backend variant of el2go_ota_diag_dump(). Walks all slots
 * starting from the oldest, skips empty or invalid records, and prints each
 * stored line via printk, followed by a summary count. Prints a short notice
 * instead if the log is unavailable.
 */
void el2go_ota_diag_dump(void)
{
    log_record_t rec;
    uint32_t count = 0U;

    if (ringbuf_init() != 0) {
        printk("[INFO] diag log unavailable\n");
        return;
    }

    printk("[INFO] ---- diag log dump begin ----\n");

    for (uint32_t n = 0U; n < s_num_records; n++) {
        uint32_t idx = (s_write_index + n) % s_num_records;

        if (flash_area_read(s_fa, (off_t)(idx * LOG_RECORD_SIZE), &rec, sizeof(rec)) != 0) {
            continue;
        }
        if (rec.magic != LOG_RECORD_MAGIC || rec.seq == 0U) {
            continue;
        }
        if (rec.len >= LOG_RECORD_TEXT_MAX) {
            rec.len = LOG_RECORD_TEXT_MAX - 1U;
        }
        rec.text[rec.len] = '\0';
        printk("%s", rec.text);
        count++;
    }

    printk("[INFO] ---- diag log dump end (%u records) ----\n", count);
}

/**
 * @brief Replays the persistent log at boot when enabled
 *
 * Ring buffer backend variant of el2go_ota_diag_boot_replay(). Dumps the records
 * persisted before the last reboot or rollback to the console when
 * CONFIG_EL2GO_OTA_DIAG_DUMP_ON_BOOT is set, and does nothing otherwise. The
 * replay-on-boot policy is owned by the backend so callers can invoke this
 * unconditionally.
 */
void el2go_ota_diag_boot_replay(void)
{
    if (IS_ENABLED(CONFIG_EL2GO_OTA_DIAG_DUMP_ON_BOOT)) {
        el2go_ota_diag_dump();
    }
}
