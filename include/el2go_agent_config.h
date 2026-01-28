/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2018-2026 NXP
 */

#ifndef __EL2GO_AGENT_CONFIG_H__
#define __EL2GO_AGENT_CONFIG_H__

/*
 * Maximum number of datastores and keystores
 * Can be configured at compile time
 */
#ifndef EL2GO_AGENT_MAX_DATASTORES
#define EL2GO_AGENT_MAX_DATASTORES 1
#endif

#ifndef EL2GO_AGENT_MAX_KEYSTORES
#define EL2GO_AGENT_MAX_KEYSTORES 1
#endif

/*
 * EL2GO_AGENT_DATASTORE_EDGELOCK_ID - Special datastore for EdgeLock 2GO server connection
 *
 * This is a reserved datastore identifier used to store EdgeLock 2GO server
 * connection information including hostname, port, TLS certificates.
 * The datastore holds the configuration required to establish secure
 * communication with the EdgeLock 2GO cloud service during device provisioning.
 */
#define EL2GO_AGENT_DATASTORE_EDGELOCK_ID 0x70000000

/*
 * EL2GO_AGENT_EDGELOCK2GO_KEYSTORE_ID - Keystore for EdgeLock 2GO credentials
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
#define EL2GO_AGENT_EDGELOCK2GO_KEYSTORE_ID                 0x70000010U

#endif /* __EL2GO_AGENT_CONFIG_H__ */
