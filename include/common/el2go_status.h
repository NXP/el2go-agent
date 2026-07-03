/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_STATUS_H__
#define __EL2GO_STATUS_H__

/**
 * @defgroup el2go_status Status Codes
 * @brief Library status and error codes
 * @{
 */

/**
 * @enum el2go_status_t
 * @brief Library return type
 */
typedef enum el2go_status_t {
    EL2GO_STATUS_SUCCESS = 0,              /**< Operation completed successfully */
    EL2GO_STATUS_FAILURE,                  /**< Generic operation failure */
    EL2GO_STATUS_FILE_OPEN_ERROR,          /**< Failed to open a file */
    EL2GO_STATUS_FILE_CLOSE_ERROR,         /**< Failed to close a file */
    EL2GO_STATUS_FILE_WRITE_ERROR,         /**< Failed to write or flush a file */
    EL2GO_STATUS_FILE_SEEK_ERROR,          /**< Failed to seek within a file */
    EL2GO_STATUS_INVALID_POINTER,          /**< A required pointer is NULL or invalid */
    EL2GO_STATUS_ALLOCATION_ERROR,         /**< Memory allocation failed */
    EL2GO_STATUS_BUFFER_TOO_SMALL,         /**< Provided buffer is too small for the output */
    EL2GO_STATUS_INVALID_PARAMETER,        /**< One or more parameters are invalid */
    EL2GO_STATUS_INVALID_STATE,            /**< Operation not valid in the current state */
    EL2GO_STATUS_ARITHMETIC_OVERFLOW,      /**< An arithmetic overflow was detected */
    EL2GO_STATUS_NOT_IMPLEMENTED,          /**< Requested functionality is not implemented */
    EL2GO_STATUS_PLATFORM_INIT_FAILED,     /**< Platform initialization failed */
    EL2GO_STATUS_PLATFORM_SMW_ERROR,       /**< SMW platform operation failed */
    EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED, /**< Network crypto configuration failed */
    EL2GO_STATUS_NET_CRYPTO_INVALID_KEY, /**< Key is invalid or not available for network crypto */
    EL2GO_STATUS_NET_CRYPTO_CONNECT_FAILED,     /**< TCP connection to server failed */
    EL2GO_STATUS_NET_CRYPTO_SSL_CONFIG_FAILED,  /**< SSL/TLS configuration failed */
    EL2GO_STATUS_NET_CRYPTO_SSL_SETUP_FAILED,   /**< SSL/TLS context setup failed */
    EL2GO_STATUS_NET_CRYPTO_HANDSHAKE_FAILED,   /**< SSL/TLS handshake with server failed */
    EL2GO_STATUS_NET_CRYPTO_CERT_VERIFY_FAILED, /**< Server certificate verification failed */
    EL2GO_STATUS_NET_CRYPTO_HOSTNAME_FAILED,    /**< Failed to set SNI hostname */
    EL2GO_STATUS_NET_CRYPTO_INVALID_CERT,  /**< Certificate is invalid or could not be parsed */
    EL2GO_STATUS_NET_CRYPTO_SHA_ERROR,     /**< SHA hashing operation failed */
    EL2GO_STATUS_NET_CRYPTO_NOT_CONNECTED, /**< Network crypto connection not established */
    EL2GO_STATUS_CERT_NOT_AVAILABLE,       /**< Certificate is not available */
    EL2GO_STATUS_CHECKSUM_MISMATCH,        /**< Checksum verification failed */
    EL2GO_STATUS_INVALID_DATA,             /**< Data is invalid or malformed */
    EL2GO_STATUS_INCOMPLETE_DATA,          /**< Operation completed but data is incomplete */
    EL2GO_STATUS_RESOURCE_LIMIT,           /**< Resource limit reached */
    EL2GO_STATUS_ALREADY_EXISTS,           /**< Resource already exists */
    EL2GO_STATUS_NOT_FOUND,                /**< Resource not found */
    EL2GO_STATUS_INCOMPLETE_WRITE,         /**< Write operation incomplete */
    EL2GO_STATUS_INCOMPLETE_READ,          /**< Read operation incomplete */
    EL2GO_STATUS_UNSUPPORTED_OPERATION,    /**< Operation is not supported */
    EL2GO_STATUS_INVALID_REQUEST,          /**< Request is invalid */
    EL2GO_STATUS_PSA_ERROR,                /**< A function in the PSA API returned an error */
    EL2GO_STATUS_INVALID_DATASTORE         /**< Datastore is invalid or corrupted */
} el2go_status_t;

/**
 * @enum el2go_verbosity_t
 * @brief Status report verbosity levels
 */
typedef enum {
    EL2GO_STATUS_SILENT,   /**< Do not print status report */
    EL2GO_STATUS_ON_ERROR, /**< Print status report only on error */
    EL2GO_STATUS_ALWAYS    /**< Always print status report */
} el2go_verbosity_t;
/** @} */ /* end of el2go_status */

#endif /* __EL2GO_STATUS_H__ */
