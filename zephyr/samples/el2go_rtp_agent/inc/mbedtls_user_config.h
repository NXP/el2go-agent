/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __MBEDTLS_USER_CONFIG_H__
#define __MBEDTLS_USER_CONFIG_H__

/** @defgroup el2go_rtp_agent_mbedtls_cfg RTP Agent Sample mbedTLS Config
 * @brief mbedTLS feature configuration for the EL2GO RTP agent Zephyr sample.
 * @{
 */
/* Defines which cannot be specified in prj.conf */
#define MBEDTLS_SSL_SERVER_NAME_INDICATION
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE
#define MBEDTLS_X509_CREATE_C
#define MBEDTLS_X509_CRT_WRITE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_X509_CRL_PARSE_C
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED

/** @} */ /* end of el2go_rtp_agent_mbedtls_cfg */

#endif /* __MBEDTLS_USER_CONFIG_H__ */
