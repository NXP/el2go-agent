/*
 * Copyright 2018-2021, 2023-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#ifndef _NXP_IOT_AGENT_PLATFORM_NETWORK_MBEDTLS_H_
#define _NXP_IOT_AGENT_PLATFORM_NETWORK_MBEDTLS_H_

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <ws2tcpip.h>
#endif

#if defined(NXP_IOT_AGENT_HAVE_PSA_IMPL_SMW) && (NXP_IOT_AGENT_HAVE_PSA_IMPL_SMW == 1) 
#include <psa/crypto_types.h>
typedef psa_key_id_t mbedtls_svc_key_id_t;
#endif

#include <network.h>

#include <mbedtls/platform.h>
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/version.h>
#if defined(MBEDTLS_VERSION_NUMBER) && (MBEDTLS_VERSION_NUMBER < 0x04000000)
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#endif //#if defined(MBEDTLS_VERSION_NUMBER) && (MBEDTLS_VERSION_NUMBER < 0x04000000)

#ifdef __cplusplus
extern "C" {
#endif


typedef struct mbedtls_network_config_t
{
    const char* hostname;
	int port;
	mbedtls_x509_crt clicert;
	mbedtls_x509_crt ca_chain;
} mbedtls_network_config_t;


typedef struct mbedtls_network_context_t
{
    mbedtls_network_config_t network_config;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_pk_context	pkey;
	mbedtls_net_context server_fd;
#if defined(MBEDTLS_VERSION_NUMBER) && (MBEDTLS_VERSION_NUMBER < 0x04000000)
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
#endif //#if defined(MBEDTLS_VERSION_NUMBER) && (MBEDTLS_VERSION_NUMBER < 0x04000000)

} mbedtls_network_context_t;

int network_pk_wrap_psa_key(mbedtls_pk_context *pk,
                                           mbedtls_svc_key_id_t key_id);

#ifdef __cplusplus
}
#endif

#endif // _NXP_IOT_AGENT_PLATFORM_NETWORK_MBEDTLS_H_

