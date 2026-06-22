/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "net_crypto.h"
#include "compiler.h"

/* Weak implementations - can be overridden by specific transport implementations */

__weak el2go_status_t net_crypto_init(void)
{
	/* only some implementations may need initialization */
	return EL2GO_STATUS_SUCCESS;
}

__weak el2go_status_t net_crypto_set_server_cert(net_crypto_ctx_t *ctx,
						 const uint8_t *ca_cert_pem,
						 size_t ca_cert_len)
{
	(void)ctx;
	(void)ca_cert_pem;
	(void)ca_cert_len;

	return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t net_crypto_set_cli_cert(net_crypto_ctx_t *ctx,
					      const uint8_t *cert_pem,
					      size_t cert_len)
{
	(void)ctx;
	(void)cert_pem;
	(void)cert_len;

	return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t /* force clang formating */
net_crypto_set_cipher_suites(net_crypto_ctx_t *ctx,
			     const el2go_cipher_list_t *cipher_suites)
{
	(void)ctx;
	(void)cipher_suites;

	return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t /* force clang formating */
net_crypto_set_curves(net_crypto_ctx_t *ctx,
		      const el2go_curve_list_t *curve_list)
{
	(void)ctx;
	(void)curve_list;

	return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t net_crypto_associate_key(net_crypto_ctx_t *ctx,
					       uint32_t object_id)
{
	(void)ctx;
	(void)object_id;

	return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t /*force clang formating */
net_crypto_self_signed_cert(const char *subject, uint32_t key_id,
			    const uint8_t *device_uuid, size_t device_uuid_len,
			    uint8_t *cert_out, size_t *cert_out_len)
{
	(void)subject;
	(void)key_id;
	(void)device_uuid;
	(void)device_uuid_len;
	(void)cert_out;
	(void)cert_out_len;

	return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t net_crypto_new(net_crypto_ctx_t **ctx)
{
	(void)ctx;

	return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t net_crypto_configure(net_crypto_ctx_t *ctx,
					   const net_crypto_config_t *config)
{
	(void)ctx;
	(void)config;

	return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t net_crypto_connect(net_crypto_ctx_t *ctx)
{
	(void)ctx;

	return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t net_crypto_verify_cert(net_crypto_ctx_t *ctx,
					     const uint8_t *crl_pem,
					     size_t crl_len)
{
	(void)ctx;
	(void)crl_pem;
	(void)crl_len;

	return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak int net_crypto_read(net_crypto_ctx_t *ctx, uint8_t *buffer, size_t len)
{
	(void)ctx;
	(void)buffer;
	(void)len;

	return -1;
}

__weak int net_crypto_write(net_crypto_ctx_t *ctx, const uint8_t *buffer,
			    size_t len)
{
	(void)ctx;
	(void)buffer;
	(void)len;

	return -1;
}

__weak void net_crypto_free(net_crypto_ctx_t **ctx)
{
	(void)ctx;
}

__weak void net_crypto_cleanup(void)
{
}

__weak el2go_status_t net_crypto_disconnect(net_crypto_ctx_t *ctx)
{
	(void)ctx;

	return EL2GO_STATUS_NOT_IMPLEMENTED;
}
