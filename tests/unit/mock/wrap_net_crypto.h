/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef EL2GO_TEST_WRAP_NET_CRYPTO_H
#define EL2GO_TEST_WRAP_NET_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "common/el2go_status.h"

#include <psa/error.h>

/** Clear the inbound (server -> client) byte queue and read fail-on-call counter. */
void mock_net_rx_reset(void);

/**
 * @brief Append bytes to the inbound queue served by __wrap_net_crypto_read().
 *
 * Bytes are handed back frame-by-frame honouring the caller's requested
 * length exactly, so partial-read loops in el2go_ota_tls_read() are
 * exercised naturally.
 *
 * @return 0 on success, -1 if the queue would overflow or args are invalid.
 */
int mock_net_rx_push(const uint8_t *bytes, size_t len);

/** Clear the outbound (client -> server) capture buffer and write fail-on-call counter. */
void mock_net_tx_reset(void);

/**
 * @brief Retrieve everything captured by __wrap_net_crypto_write() so far.
 *
 * @param[out] out      Pointer to the internal capture buffer (valid until
 *                       the next mock_net_tx_reset()).
 * @param[out] out_len  Number of valid bytes in *out.
 * @return 0 on success, -1 if args are invalid.
 */
int mock_net_tx_data(const uint8_t **out, size_t *out_len);

/** Fail the Nth call to __wrap_net_crypto_read() (1-based). 0 = never fail. */
extern unsigned int g_wrap_net_crypto_read_fail_on_call;

/** Fail the Nth call to __wrap_net_crypto_write() (1-based). 0 = never fail. */
extern unsigned int g_wrap_net_crypto_write_fail_on_call;

/* Per-call return-code control variables for every __wrap_net_crypto_*() stub. */
extern int g_wrap_net_crypto_new_rc;
extern int g_wrap_net_crypto_configure_rc;
extern int g_wrap_net_crypto_set_server_cert_rc;
extern int g_wrap_net_crypto_set_cli_cert_rc;
extern int g_wrap_net_crypto_set_cipher_suites_rc;
extern int g_wrap_net_crypto_set_curves_rc;
extern int g_wrap_net_crypto_set_alpn_rc;
extern int g_wrap_net_crypto_associate_key_rc;
extern int g_wrap_net_crypto_connect_rc;
extern el2go_status_t g_wrap_net_crypto_connect_status;
extern int g_wrap_net_crypto_disconnect_rc;
extern int g_wrap_net_crypto_write_rc;
extern int g_wrap_net_crypto_read_rc;

extern psa_status_t g_wrap_psa_get_key_attributes_rc;
extern psa_status_t g_wrap_psa_export_key_rc;
extern psa_status_t g_wrap_psa_its_get_info_rc;
extern psa_status_t g_wrap_psa_its_get_rc;
extern size_t g_wrap_psa_its_cert_size;

/**
 * @brief Reset every g_wrap_* control variable (net_crypto_* and PSA-ITS)
 *        back to its safe default, plus clear the RX/TX byte queues.
 *
 * Wired as the ZTEST_SUITE "before" hook in ztest_unit_main.c so every
 * top-level test starts from a known-clean mock state.
 */
void wrap_net_crypto_reset_all(void);

#endif /* EL2GO_TEST_WRAP_NET_CRYPTO_H */
