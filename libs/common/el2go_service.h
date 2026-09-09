/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#ifndef __EL2GO_SERVICE_H__
#define __EL2GO_SERVICE_H__

#include <stddef.h>
#include <stdint.h>

#include "compiler.h"

#include "common/el2go_datastore.h"
#include "common/el2go_status.h"
#include "ServiceDescriptor.pb.h"

/**
 * @defgroup el2go_service Service Descriptor Internal API
 * @brief Internal interface for parsing and validating EL2GO service descriptors.
 * @{
 */

/** @brief Safe equivalent of PB_SIZE_MAX for protobuf size calculations. */
#define EL2GO_PB_SIZE_MAX (~(pb_size_t)0U)

/** @brief Size of SHA-256 checksum in bytes. */
#define EL2GO_SHA256_CHECKSUM_SIZE 32U

/**
 * @brief Configuration data header structure.
 *
 * Written at the beginning of the datastore to describe the stored
 * configuration data. The checksum covers all data after the checksum
 * field itself.
 */
typedef struct {
    /** @brief SHA-256 checksum of all data after this field. */
    uint8_t checksum[EL2GO_SHA256_CHECKSUM_SIZE];

    /** @brief Total length of the stored data (incl. all fields of config_data_hdr_t). */
    uint32_t length;

    /** @brief Version of the configuration data format. */
    uint32_t version;

    /** @brief Number of services stored in the datastore. */
    uint32_t number_of_services;
} __packed __aligned(1) config_data_hdr_t;

/**
 * @brief Version of the configuration data format.
 *
 * Increment this value when the format of the configuration data changes
 * in a backwards incompatible way.
 */
#define EL2GO_CONFIGURATION_DATA_VERSION (0U)

/* ========================================================================== */
/* Service Functions                                                           */
/* ========================================================================== */

/**
 * @brief Get the number of services in the datastore.
 *
 * @param[in] datastore Pointer to the datastore.
 *
 * @return Number of services, or 0 on error.
 */
size_t srv_get_number_of_services(el2go_datastore_t *datastore);

/**
 * @brief Get service descriptor by index.
 *
 * @param[in] datastore           Pointer to the datastore.
 * @param[in] index               Index of the service to retrieve.
 * @param[out] offset              Pointer to store the offset of the service descriptor.
 * @param[out] service_descriptor  Pointer to store the decoded service descriptor.
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t srv_get_service_by_index(el2go_datastore_t *datastore, size_t index, size_t *offset,
                                        nxp_iot_ServiceDescriptor *service_descriptor);

/**
 * @brief Get service descriptor by service ID.
 *
 * @param[in] datastore           Pointer to the datastore.
 * @param[in] service_id          Service ID to search for.
 * @param[out] offset              Pointer to store the offset of the service descriptor.
 * @param[out] service_descriptor  Pointer to store the decoded service descriptor.
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t srv_get_service_by_id(el2go_datastore_t *datastore, uint64_t service_id,
                                     size_t *offset, nxp_iot_ServiceDescriptor *service_descriptor);

/**
 * @brief Validate configuration data checksum.
 *
 * @param[in] datastore Pointer to the datastore.
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t srv_validate_configuration_data(el2go_datastore_t *datastore);

/** @} */ /* end of el2go_service */

#endif /* __EL2GO_SERVICE_H__ */
