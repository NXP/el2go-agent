/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2026 NXP
 */

#ifndef __RTP_TEST_UTILS_H__
#define __RTP_TEST_UTILS_H__

#include "common/el2go_status.h"
#include "common/el2go_datastore.h"
#include "ServiceDescriptor.pb.h"

/**
 * @brief Add a service descriptor to a datastore
 *
 * If the datastore already contains services, the header is updated to
 * reflect the new number of services. If the datastore is empty, a new
 * header is created.
 *
 * @param[in] datastore Pointer to the datastore
 * @param[in] service_descriptor Pointer to the service descriptor to add
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t srv_add_service(el2go_datastore_t *datastore,
                               const nxp_iot_ServiceDescriptor *service_descriptor);

#endif /* __RTP_TEST_UTILS_H__ */