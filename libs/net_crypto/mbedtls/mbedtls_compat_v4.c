/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <psa/crypto.h>
#include <mbedtls/x509_crt.h>

#include "builtin_macros.h"
#include "osal.h"

#include "mbedtls_compat.h"

/**
 * @addtogroup mbedtls_compat_v4
 * @{
 */

/* ========================================================================== */
/* RNG Context Structure                                                       */
/* ========================================================================== */

/**
 * @brief RNG context for mbedTLS 4.x.
 *
 * In mbedTLS 4.x PSA crypto handles RNG internally, so no explicit
 * RNG context is needed. This struct exists only to satisfy the C
 * requirement that structs cannot be empty.
 */
struct mbedtls_compat_rng_context {
	int dummy; /**< Unused - PSA crypto handles RNG internally. */
};

/* ========================================================================== */
/* Cipher Suite Mapping                                                        */
/* ========================================================================== */

/**
 * @brief Mapping from el2go_cipher_suite_t to mbedTLS 4.x cipher suite IDs.
 *
 * Index corresponds to @ref el2go_cipher_suite_t value.
 * 0 means not supported in mbedTLS 4.x.
 *
 * @note Must stay in sync with @ref el2go_cipher_suite_t in plat_crypto_params.h.
 */
static const int cipher_suite_map[] = {
	/* EL2GO_CIPHER_ECDHE_ECDSA_AES128_CBC_SHA256 */
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	/* EL2GO_CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256 */
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	/* EL2GO_CIPHER_ECDHE_ECDSA_AES256_CBC_SHA384 */
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
	/* EL2GO_CIPHER_ECDHE_ECDSA_AES256_GCM_SHA384 */
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	/* EL2GO_CIPHER_ECDH_ECDSA_AES128_CBC_SHA256  */
	0, /* not supported in mbedTLS 4.x */
	/* EL2GO_CIPHER_ECDH_ECDSA_AES128_GCM_SHA256  */
	0, /* not supported in mbedTLS 4.x */
	/* EL2GO_CIPHER_ECDH_ECDSA_AES256_CBC_SHA384  */
	0, /* not supported in mbedTLS 4.x */
	/* EL2GO_CIPHER_ECDH_ECDSA_AES256_GCM_SHA384  */
	0, /* not supported in mbedTLS 4.x */
	/* EL2GO_CIPHER_ECDHE_RSA_AES128_CBC_SHA256   */
	MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	/* EL2GO_CIPHER_ECDHE_RSA_AES128_GCM_SHA256   */
	MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	/* EL2GO_CIPHER_ECDHE_RSA_AES256_CBC_SHA384   */
	MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
	/* EL2GO_CIPHER_ECDHE_RSA_AES256_GCM_SHA384   */
	MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	/* EL2GO_CIPHER_ECDH_RSA_AES128_CBC_SHA256    */
	0, /* not supported in mbedTLS 4.x */
	/* EL2GO_CIPHER_ECDH_RSA_AES128_GCM_SHA256    */
	0, /* not supported in mbedTLS 4.x */
	/* EL2GO_CIPHER_ECDH_RSA_AES256_CBC_SHA384    */
	0, /* not supported in mbedTLS 4.x */
	/* EL2GO_CIPHER_ECDH_RSA_AES256_GCM_SHA384    */
	0, /* not supported in mbedTLS 4.x */
};

/* ========================================================================== */
/* Curve Mapping                                                               */
/* ========================================================================== */

// clang-format off
/**
 * @brief Curve mapping table from platform-agnostic curve IDs to mbedTLS 4.x format.
 *
 * Uses IANA TLS group IDs (uint16_t).
 *
 * @note SECP224R1 is not supported in mbedTLS 4.x.
 * @note Order must match @ref el2go_curve_id_t enum in plat_crypto_params.h.
 * @note Size must match @ref EL2GO_CURVE_MAX.
 */
static const mbedtls_compat_group_id_t curve_map[] = {
	0,                                    /* EL2GO_CURVE_SECP224R1 - not supported in v4 */
	MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1, /* EL2GO_CURVE_SECP256R1 */
	MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1, /* EL2GO_CURVE_SECP384R1 */
	MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1, /* EL2GO_CURVE_SECP521R1 */
};
// clang-format on

/* Functions are documented in mbedtls_compat.h */

int mbedtls_compat_cipher_suite_to_id(el2go_cipher_suite_t suite)
{
	if (suite >= ARRAY_SIZE(cipher_suite_map))
		return 0;

	return cipher_suite_map[suite];
}

size_t mbedtls_compat_cipher_suite_map_size(void)
{
	return ARRAY_SIZE(cipher_suite_map);
}

size_t mbedtls_compat_curve_map_size(void)
{
	return ARRAY_SIZE(curve_map);
}

mbedtls_compat_group_id_t mbedtls_compat_curve_to_id(el2go_curve_id_t curve)
{
	if (curve >= ARRAY_SIZE(curve_map))
		return MBEDTLS_COMPAT_CURVE_SENTINEL;

	return curve_map[curve];
}

/* ========================================================================== */
/* RNG Functions (v4-specific)                                                */
/* ========================================================================== */

int mbedtls_compat_rng_init(mbedtls_compat_rng_context **ctx,
			    const unsigned char *pers, size_t pers_len)
{
	(void)pers;
	(void)pers_len;

	if (!ctx)
		return -1;

	/* mbedTLS 4.x uses PSA crypto - no RNG context needed */
	*ctx = NULL;
	return 0;
}

void mbedtls_compat_rng_free(mbedtls_compat_rng_context *ctx)
{
	/* Nothing to free - context is NULL */
	(void)ctx;
}

int mbedtls_compat_ssl_conf_rng(mbedtls_ssl_config *conf,
				mbedtls_compat_rng_context *rng_ctx)
{
	(void)conf;
	(void)rng_ctx;
	/* mbedTLS 4.x configures RNG automatically via PSA */
	return 0;
}

/* ========================================================================== */
/* PK Functions (v4-specific)                                                 */
/* ========================================================================== */

int mbedtls_compat_pk_setup_key(mbedtls_pk_context *pk, uint32_t key_id)
{
	mbedtls_svc_key_id_t svc_key_id;

	if (!pk)
		return MBEDTLS_ERR_PK_BAD_INPUT_DATA;

	/* Convert uint32_t to mbedtls_svc_key_id_t */
	svc_key_id = mbedtls_svc_key_id_make(0, key_id);

	return mbedtls_pk_wrap_psa(pk, svc_key_id);
}

int mbedtls_compat_pk_has_key(const mbedtls_pk_context *pk)
{
	return mbedtls_pk_get_key_type(pk) != PSA_KEY_TYPE_NONE;
}

/* ========================================================================== */
/* X.509 Certificate Functions (v4-specific)                                  */
/* ========================================================================== */

int mbedtls_compat_x509write_crt_set_serial(mbedtls_x509write_cert *ctx,
					    const unsigned char *serial,
					    size_t serial_len)
{
	return mbedtls_x509write_crt_set_serial_raw(ctx, serial, serial_len);
}

int mbedtls_compat_x509write_crt_der(mbedtls_x509write_cert *ctx,
				     unsigned char *buf, size_t size,
				     mbedtls_compat_rng_context *rng_ctx)
{
	(void)rng_ctx;
	/* mbedTLS 4.x doesn't require RNG parameter */
	return mbedtls_x509write_crt_der(ctx, buf, size);
}

/* ========================================================================== */
/* SSL Configuration Functions                                                 */
/* ========================================================================== */

void mbedtls_compat_ssl_conf_groups(mbedtls_ssl_config *conf,
				    const mbedtls_compat_group_id_t *groups)
{
	mbedtls_ssl_conf_groups(conf, groups);
}

/** @} */ /* end of mbedtls_compat_v4 */
