/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
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
#define EL2GO_RTP_EDGELOCK2GO_HOSTNAME "CHANGE THIS! - company specific hostname"
#endif

#ifndef EL2GO_RTP_EDGELOCK2GO_PORT
/**
 * @brief The port to use for the communication to the EdgeLock 2GO cloud service
 */
#define EL2GO_RTP_EDGELOCK2GO_PORT 443U
#endif

/** @brief Maximum size of the self-signed client certificate in bytes */
#ifndef EL2GO_RTP_CLIENT_CERT_MAX_SIZE
#define EL2GO_RTP_CLIENT_CERT_MAX_SIZE 1024U
#endif

/** @brief Certificate subject used for client certificate generation */
#ifndef EL2GO_RTP_SUBJECT
#define EL2GO_RTP_SUBJECT "CN=EdgeLock2GO,O=NXP"
#endif

/**
 * @brief Request a Certificate Revocation List from EdgeLock 2GO during provisioning.
 *
 * When set to 1, the agent requests a CRL from the EdgeLock 2GO cloud service
 * during the provisioning session. Set to 0 to disable CRL retrieval.
 */
#ifndef EL2GO_RTP_REQUEST_CRL
#define EL2GO_RTP_REQUEST_CRL 1
#endif

/** @} */ /* end of el2go_rtp_config */

#endif /* __EL2GO_RTP_CONFIG_H__ */
