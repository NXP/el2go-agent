/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2018-2026 NXP
 */

#ifndef __EL2GO_RTP_CONFIG_H__
#define __EL2GO_RTP_CONFIG_H__

/**
 * @file el2go_rtp_config.h
 * @brief EdgeLock 2GO RTP (Remote Trust Provisioning) configuration
 *
 * This file contains configuration parameters for connecting to the
 * EdgeLock 2GO cloud service, including datastore/keystore limits,
 * server connection settings, and trusted CA certificates.
 */

/**
 * @defgroup el2go_rtp_config RTP Configuration
 * @brief Configuration parameters for EdgeLock 2GO Remote Trust Provisioning
 * @{
 */

#include "rtp/el2go_rtp_certificates.h"

/**
 * @brief Maximum number of datastores
 *
 * Can be configured at compile time to adjust memory usage.
 */
#ifndef EL2GO_RTP_MAX_DATASTORES
#define EL2GO_RTP_MAX_DATASTORES 1
#endif

/**
 * @brief Maximum number of keystores
 *
 * Can be configured at compile time to adjust memory usage.
 */
#ifndef EL2GO_RTP_MAX_KEYSTORES
#define EL2GO_RTP_MAX_KEYSTORES 1
#endif

/**
 * @brief Special datastore for EdgeLock 2GO server connection
 *
 * This is a reserved datastore identifier used to store EdgeLock 2GO server
 * connection information including hostname, port, TLS certificates.
 * The datastore holds the configuration required to establish secure
 * communication with the EdgeLock 2GO cloud service during device provisioning.
 */
#define EL2GO_RTP_DATASTORE_EDGELOCK_ID 0x70000000

/**
 * @brief Keystore for EdgeLock 2GO credentials
 *
 * When connecting to the EdgeLock 2GO cloud service, for the client
 * authentication a private key is required. This key is expected to be in a
 * keystore which is registered to the EdgeLock 2GO agent.
 *
 * In case there is a datastore which holds the information how to connect to
 * the EdgeLock 2GO cloud service this datastore also holds the information
 * where to get the private key.
 *
 * In case the EdgeLock 2GO agent needs to fall back to compile-time constant
 * connection information, it does assume that the private key for the client
 * authentication is stored in a keystore that is registered with this ID.
 */
#define EL2GO_RTP_EDGELOCK2GO_KEYSTORE_ID 0x70000010U

#ifndef EL2GO_RTP_EDGELOCK2GO_HOSTNAME
/**
 * @brief The hostname to use for the connection to the EdgeLock 2GO cloud service
 *
 * This is specific to your customer account, the needed value can be obtained in the GUI of the
 * EdgeLock 2GO cloud service in the company settings of the account.
 */
#define EL2GO_RTP_EDGELOCK2GO_HOSTNAME \
	"CHANGE THIS! - company specific hostname"
#endif

#ifndef EL2GO_RTP_EDGELOCK2GO_PORT
/**
 * @brief The port to use for the communication to the EdgeLock 2GO cloud service
 */
#define EL2GO_RTP_EDGELOCK2GO_PORT 443U
#endif

#ifdef EL2GO_RTP_ENABLE_SANDBOX_TEST
/* Test / Sandbox certificates */

/**
 * @brief Trusted root CA certificates for sandbox environment
 *
 * Array of DER-encoded certificates used to verify EdgeLock 2GO server
 * in sandbox/test environment.
 */
#define EL2GO_RTP_TRUSTED_ROOT_CA_CERTIFICATES                     \
	{                                                          \
		EL2GO_RTP_TRUSTED_ROOT_CA_CERT_RSA_SANDBOX,        \
			EL2GO_RTP_TRUSTED_ROOT_CA_CERT_ECC_SANDBOX \
	}

/**
 * @brief Total size of trusted root CA certificates for sandbox
 *
 * Combined size of all certificates in EL2GO_RTP_TRUSTED_ROOT_CA_CERTIFICATES.
 */
#define EL2GO_RTP_TRUSTED_ROOT_CA_CERTIFICATES_SIZE       \
	EL2GO_RTP_TRUSTED_ROOT_CA_CERT_RSA_SANDBOX_SIZE + \
		EL2GO_RTP_TRUSTED_ROOT_CA_CERT_ECC_SANDBOX_SIZE
#else
/* Production certificates */

/**
 * @brief Trusted root CA certificates for production environment
 *
 * Array of DER-encoded certificates used to verify EdgeLock 2GO server
 * in production environment.
 */
#define EL2GO_RTP_TRUSTED_ROOT_CA_CERTIFICATES                  \
	{                                                       \
		EL2GO_RTP_TRUSTED_ROOT_CA_CERT_RSA_PROD,        \
			EL2GO_RTP_TRUSTED_ROOT_CA_CERT_ECC_PROD \
	}

/**
 * @brief Total size of trusted root CA certificates for production
 *
 * Combined size of all certificates in EL2GO_RTP_TRUSTED_ROOT_CA_CERTIFICATES.
 * This must match the certificates configured above.
 */
#define EL2GO_RTP_TRUSTED_ROOT_CA_CERTIFICATES_SIZE    \
	EL2GO_RTP_TRUSTED_ROOT_CA_CERT_RSA_PROD_SIZE + \
		EL2GO_RTP_TRUSTED_ROOT_CA_CERT_ECC_PROD_SIZE
#endif

/** @} */ /* end of el2go_rtp_config */

#endif /* __EL2GO_RTP_CONFIG_H__ */
