/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "osal.h"
#include "debug.h"

#include "pb.h"
#include "pb_decode.h"
#include "ServiceDescriptor.pb.h"

#include "common/el2go_datastore.h"
#include "common/el2go_status.h"
#include "el2go_service.h"
#include "rtp/el2go_rtp_config.h"

#include "test_framework.h"
#include "rtp_test_utils.h"

/** @defgroup test_el2go_service_internal Internal Service Tests
 * @brief Unit tests for the internal el2go_service module.
 * @{
 */

/* ========================================================================== */
/* Test params                                                                 */
/* ========================================================================== */

/**
 * @brief Parameters passed to each test function.
 */
typedef struct {
    el2go_datastore_type_t type; /**< Datastore type to use */
    const char *name_suffix;     /**< Suffix appended to datastore name */
} datastore_test_params_t;

static const datastore_test_params_t plain_params = { .type = EL2GO_DATASTORE_TYPE_PLAIN,
                                                      .name_suffix = "plain" };

static const datastore_test_params_t fs_params = { .type = EL2GO_DATASTORE_TYPE_FS,
                                                   .name_suffix = "fs" };

/* ========================================================================== */
/* Test helpers                                                               */
/* ========================================================================== */

/**
 * @brief Initialize a datastore for testing using the type from params.
 */
static el2go_status_t init_test_datastore(el2go_datastore_t *datastore, const char *base_name,
                                          const datastore_test_params_t *p)
{
    char name[64] = { 0 };

    (void)osal_snprintf(name, sizeof(name), "%s_%s", base_name, p->name_suffix);

    return el2go_datastore_init(EL2GO_RTP_DATASTORE_EDGELOCK_ID, name, p->type, datastore, NULL);
}

/**
 * @brief Fill a service descriptor with test data.
 */
static void fill_service_descriptor(nxp_iot_ServiceDescriptor *sd, uint64_t identifier,
                                    const char *hostname, uint16_t port,
                                    nxp_iot_ServiceType service_type)
{
    *sd = (nxp_iot_ServiceDescriptor)nxp_iot_ServiceDescriptor_init_default;
    sd->identifier = identifier;
    sd->hostname = (char *)hostname;
    sd->has_port = true;
    sd->port = port;
    sd->has_service_type = true;
    sd->service_type = service_type;
}

/* ========================================================================== */
/* srv_get_number_of_services Tests                                           */
/* ========================================================================== */
/**
 * @brief Test srv_get_number_of_services() with NULL datastore.
 *
 * Verifies that srv_get_number_of_services() returns 0 when
 * NULL is passed as the datastore.
 */
static bool test_srv_get_number_of_services_null(void *params)
{
    size_t count = 0;
    bool test_status = true;

    (void)params;

    count = srv_get_number_of_services(NULL);
    TEST_ASSERT_EQUAL_CONTINUE(0, count);

    return test_status;
}

/**
 * @brief Test srv_get_number_of_services() on an empty datastore.
 *
 * Verifies that srv_get_number_of_services() returns 0 when
 * called on a freshly initialized datastore with no services added.
 */
static bool test_srv_get_number_of_services_empty(void *params)
{
    const datastore_test_params_t *p = (const datastore_test_params_t *)params;
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    size_t count = 0;
    bool test_status = true;

    status = init_test_datastore(&datastore, "test_srv_count_empty", p);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    count = srv_get_number_of_services(&datastore);
    TEST_ASSERT_EQUAL_GOTO(0, count, cleanup);

    TEST_PRINT_INFO("[%s] Empty datastore has 0 services as expected", p->name_suffix);

cleanup:
    (void)el2go_datastore_free(&datastore);

exit:
    return test_status;
}

/**
 * @brief Test srv_get_number_of_services() after adding multiple services.
 *
 * Verifies that srv_get_number_of_services() correctly reflects the number
 * of services after each successive call to srv_add_service(), incrementing
 * from 1 to 3.
 */
static bool test_srv_get_number_of_services_after_add(void *params)
{
    const datastore_test_params_t *p = (const datastore_test_params_t *)params;
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    nxp_iot_ServiceDescriptor sd = nxp_iot_ServiceDescriptor_init_default;
    size_t count = 0;
    bool test_status = true;

    status = init_test_datastore(&datastore, "test_srv_count_add", p);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Add first service */
    fill_service_descriptor(&sd, 1001, "host1.example.com", 443, nxp_iot_ServiceType_EL2GOSERVICE);
    status = srv_add_service(&datastore, &sd);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);

    count = srv_get_number_of_services(&datastore);
    TEST_ASSERT_EQUAL_GOTO(1, count, cleanup);
    TEST_PRINT_INFO("[%s] 1 service added, count verified: %zu", p->name_suffix, count);

    /* Add second service */
    fill_service_descriptor(&sd, 1002, "host2.example.com", 8443, nxp_iot_ServiceType_EL2GOSERVICE);
    status = srv_add_service(&datastore, &sd);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);

    count = srv_get_number_of_services(&datastore);
    TEST_ASSERT_EQUAL_GOTO(2, count, cleanup);
    TEST_PRINT_INFO("[%s] 2 services added, count verified: %zu", p->name_suffix, count);

    /* Add third service */
    fill_service_descriptor(&sd, 1003, "host3.example.com", 9443, nxp_iot_ServiceType_EL2GOSERVICE);
    status = srv_add_service(&datastore, &sd);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);

    count = srv_get_number_of_services(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(3, count);
    TEST_PRINT_INFO("[%s] 3 services added, count verified: %zu", p->name_suffix, count);

cleanup:
    (void)el2go_datastore_free(&datastore);

exit:
    return test_status;
}

/* ========================================================================== */
/* srv_get_service_by_index Tests                                             */
/* ========================================================================== */

/**
 * @brief Test srv_get_service_by_index() with NULL parameters.
 *
 * Verifies that srv_get_service_by_index() returns
 * EL2GO_STATUS_INVALID_PARAMETER when NULL is passed as the datastore,
 * offset, or service descriptor.
 */
static bool test_srv_get_service_by_index_null(void *params)
{
    const datastore_test_params_t *p = (const datastore_test_params_t *)params;
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    nxp_iot_ServiceDescriptor sd = nxp_iot_ServiceDescriptor_init_default;
    size_t offset = 0;
    bool test_status = true;

    /* NULL datastore */
    status = srv_get_service_by_index(NULL, 0, &offset, &sd);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = init_test_datastore(&datastore, "test_srv_by_index_null", p);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* NULL offset */
    status = srv_get_service_by_index(&datastore, 0, NULL, &sd);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, cleanup);

    /* NULL service descriptor */
    status = srv_get_service_by_index(&datastore, 0, &offset, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

cleanup:
    (void)el2go_datastore_free(&datastore);

exit:
    return test_status;
}

/**
 * @brief Test srv_get_service_by_index() on an empty datastore.
 *
 * Verifies that srv_get_service_by_index() returns
 * EL2GO_STATUS_NOT_FOUND when called on a datastore with no services.
 */
static bool test_srv_get_service_by_index_empty(void *params)
{
    const datastore_test_params_t *p = (const datastore_test_params_t *)params;
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    nxp_iot_ServiceDescriptor sd = nxp_iot_ServiceDescriptor_init_default;
    size_t offset = 0;
    bool test_status = true;

    status = init_test_datastore(&datastore, "test_srv_by_index_empty", p);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = srv_get_service_by_index(&datastore, 0, &offset, &sd);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_NOT_FOUND, status);

    TEST_PRINT_INFO("[%s] Empty datastore returns NOT_FOUND as expected", p->name_suffix);

    (void)el2go_datastore_free(&datastore);

exit:
    return test_status;
}

/**
 * @brief Test srv_get_service_by_index() with an out-of-bounds index.
 *
 * Verifies that srv_get_service_by_index() returns
 * EL2GO_STATUS_NOT_FOUND when the requested index exceeds the number
 * of services stored in the datastore.
 */
static bool test_srv_get_service_by_index_out_of_bounds(void *params)
{
    const datastore_test_params_t *p = (const datastore_test_params_t *)params;
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    nxp_iot_ServiceDescriptor sd = nxp_iot_ServiceDescriptor_init_default;
    size_t offset = 0;
    bool test_status = true;

    status = init_test_datastore(&datastore, "test_srv_by_index_oob", p);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    fill_service_descriptor(&sd, 1001, "host1.example.com", 443, nxp_iot_ServiceType_EL2GOSERVICE);
    status = srv_add_service(&datastore, &sd);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);

    sd = (nxp_iot_ServiceDescriptor)nxp_iot_ServiceDescriptor_init_default;
    status = srv_get_service_by_index(&datastore, 1, &offset, &sd);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_NOT_FOUND, status);

    TEST_PRINT_INFO("[%s] Out of bounds index returns NOT_FOUND as expected", p->name_suffix);

cleanup:
    pb_release(nxp_iot_ServiceDescriptor_fields, &sd);
    (void)el2go_datastore_free(&datastore);

exit:
    return test_status;
}

/**
 * @brief Test srv_get_service_by_index() with multiple services.
 *
 * Verifies that srv_get_service_by_index() correctly retrieves each
 * service by its index and that all fields including identifier, hostname,
 * port, and service type match the originally stored values.
 */
static bool test_srv_get_service_by_index_multiple(void *params)
{
    const datastore_test_params_t *p = (const datastore_test_params_t *)params;
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    nxp_iot_ServiceDescriptor sd = nxp_iot_ServiceDescriptor_init_default;
    nxp_iot_ServiceDescriptor sd_read = nxp_iot_ServiceDescriptor_init_default;
    size_t offset = 0;
    bool test_status = true;

    const char *hostnames[] = { "host1.example.com", "host2.example.com", "host3.example.com" };
    const uint16_t ports[] = { 443, 8443, 9443 };
    const uint64_t identifiers[] = { 1001, 1002, 1003 };
    const size_t num_services = 3;

    status = init_test_datastore(&datastore, "test_srv_by_index_multiple", p);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Add all services */
    for (size_t i = 0; i < num_services; i++) {
        fill_service_descriptor(&sd, identifiers[i], hostnames[i], ports[i],
                                nxp_iot_ServiceType_EL2GOSERVICE);
        status = srv_add_service(&datastore, &sd);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
        TEST_PRINT_INFO("[%s] Added service %zu: %s:%u", p->name_suffix, i, hostnames[i], ports[i]);
    }

    /* Verify count */
    TEST_ASSERT_EQUAL_GOTO(num_services, srv_get_number_of_services(&datastore), cleanup);

    /* Read back each service by index and verify */
    for (size_t i = 0; i < num_services; i++) {
        sd_read = (nxp_iot_ServiceDescriptor)nxp_iot_ServiceDescriptor_init_default;
        offset = 0;

        status = srv_get_service_by_index(&datastore, i, &offset, &sd_read);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);

        TEST_ASSERT_EQUAL_GOTO(identifiers[i], sd_read.identifier, cleanup);
        TEST_ASSERT_NOT_NULL_GOTO(sd_read.hostname, cleanup);
        TEST_ASSERT_EQUAL_GOTO(0, strcmp(sd_read.hostname, hostnames[i]), cleanup);
        TEST_ASSERT_EQUAL_GOTO(true, sd_read.has_port, cleanup);
        TEST_ASSERT_EQUAL_GOTO(ports[i], sd_read.port, cleanup);
        TEST_ASSERT_EQUAL_GOTO(true, sd_read.has_service_type, cleanup);
        TEST_ASSERT_EQUAL_GOTO(nxp_iot_ServiceType_EL2GOSERVICE, sd_read.service_type, cleanup);

        TEST_PRINT_INFO("[%s] Service %zu verified: id=%llu host=%s port=%u", p->name_suffix, i,
                        (unsigned long long)sd_read.identifier, sd_read.hostname, sd_read.port);

        pb_release(nxp_iot_ServiceDescriptor_fields, &sd_read);
    }

cleanup:
    pb_release(nxp_iot_ServiceDescriptor_fields, &sd_read);
    (void)el2go_datastore_free(&datastore);

exit:
    return test_status;
}

/* ========================================================================== */
/* srv_get_service_by_id Tests                                               */
/* ========================================================================== */

/**
 * @brief Test srv_get_service_by_id() with NULL parameters.
 *
 * Verifies that srv_get_service_by_id() returns
 * EL2GO_STATUS_INVALID_PARAMETER when NULL is passed as the datastore,
 * offset, or service descriptor.
 */
static bool test_srv_get_service_by_id_null(void *params)
{
    const datastore_test_params_t *p = (const datastore_test_params_t *)params;
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    nxp_iot_ServiceDescriptor sd = nxp_iot_ServiceDescriptor_init_default;
    size_t offset = 0;
    bool test_status = true;

    /* NULL datastore */
    status = srv_get_service_by_id(NULL, 1001, &offset, &sd);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = init_test_datastore(&datastore, "test_srv_by_id_null", p);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* NULL offset */
    status = srv_get_service_by_id(&datastore, 1001, NULL, &sd);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, cleanup);

    /* NULL service descriptor */
    status = srv_get_service_by_id(&datastore, 1001, &offset, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

cleanup:
    (void)el2go_datastore_free(&datastore);

exit:
    return test_status;
}

/**
 * @brief Test srv_get_service_by_id() when the requested ID does not exist.
 *
 * Verifies that srv_get_service_by_id() returns EL2GO_STATUS_NOT_FOUND
 * when searching for a service ID that is not present in the datastore.
 */
static bool test_srv_get_service_by_id_not_found(void *params)
{
    const datastore_test_params_t *p = (const datastore_test_params_t *)params;
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    nxp_iot_ServiceDescriptor sd = nxp_iot_ServiceDescriptor_init_default;
    size_t offset = 0;
    bool test_status = true;

    status = init_test_datastore(&datastore, "test_srv_by_id_not_found", p);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    fill_service_descriptor(&sd, 1001, "host1.example.com", 443, nxp_iot_ServiceType_EL2GOSERVICE);
    status = srv_add_service(&datastore, &sd);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);

    sd = (nxp_iot_ServiceDescriptor)nxp_iot_ServiceDescriptor_init_default;
    status = srv_get_service_by_id(&datastore, 9999, &offset, &sd);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_NOT_FOUND, status);

    TEST_PRINT_INFO("[%s] Non-existent service ID returns NOT_FOUND as expected", p->name_suffix);

cleanup:
    pb_release(nxp_iot_ServiceDescriptor_fields, &sd);
    (void)el2go_datastore_free(&datastore);

exit:
    return test_status;
}

/**
 * @brief Test srv_get_service_by_id() with multiple services.
 *
 * Verifies that srv_get_service_by_id() correctly retrieves each service
 * by its unique identifier and that all fields including hostname and port
 * match the originally stored values.
 */
static bool test_srv_get_service_by_id_multiple(void *params)
{
    const datastore_test_params_t *p = (const datastore_test_params_t *)params;
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    nxp_iot_ServiceDescriptor sd = nxp_iot_ServiceDescriptor_init_default;
    nxp_iot_ServiceDescriptor sd_read = nxp_iot_ServiceDescriptor_init_default;
    size_t offset = 0;
    bool test_status = true;

    const char *hostnames[] = { "host1.example.com", "host2.example.com", "host3.example.com" };
    const uint16_t ports[] = { 443, 8443, 9443 };
    const uint64_t identifiers[] = { 1001, 1002, 1003 };
    const size_t num_services = 3;

    status = init_test_datastore(&datastore, "test_srv_by_id_multiple", p);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Add all services */
    for (size_t i = 0; i < num_services; i++) {
        fill_service_descriptor(&sd, identifiers[i], hostnames[i], ports[i],
                                nxp_iot_ServiceType_EL2GOSERVICE);
        status = srv_add_service(&datastore, &sd);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
        TEST_PRINT_INFO("[%s] Added service %zu: id=%llu %s:%u", p->name_suffix, i,
                        (unsigned long long)identifiers[i], hostnames[i], ports[i]);
    }

    /* Read back each service by ID and verify */
    for (size_t i = 0; i < num_services; i++) {
        sd_read = (nxp_iot_ServiceDescriptor)nxp_iot_ServiceDescriptor_init_default;
        offset = 0;

        status = srv_get_service_by_id(&datastore, identifiers[i], &offset, &sd_read);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);

        TEST_ASSERT_EQUAL_GOTO(identifiers[i], sd_read.identifier, cleanup);
        TEST_ASSERT_NOT_NULL_GOTO(sd_read.hostname, cleanup);
        TEST_ASSERT_EQUAL_GOTO(0, strcmp(sd_read.hostname, hostnames[i]), cleanup);
        TEST_ASSERT_EQUAL_GOTO(true, sd_read.has_port, cleanup);
        TEST_ASSERT_EQUAL_GOTO(ports[i], sd_read.port, cleanup);

        TEST_PRINT_INFO("[%s] Service by ID %llu verified: host=%s port=%u", p->name_suffix,
                        (unsigned long long)identifiers[i], sd_read.hostname, sd_read.port);

        pb_release(nxp_iot_ServiceDescriptor_fields, &sd_read);
    }

cleanup:
    pb_release(nxp_iot_ServiceDescriptor_fields, &sd_read);
    (void)el2go_datastore_free(&datastore);

exit:
    return test_status;
}

/* ========================================================================== */
/* srv_validate_configuration_data Tests                                      */
/* ========================================================================== */

/**
 * @brief Test srv_validate_configuration_data() with NULL datastore.
 *
 * Verifies that srv_validate_configuration_data() returns
 * EL2GO_STATUS_INVALID_PARAMETER when NULL is passed as the datastore.
 */
static bool test_srv_validate_configuration_data_null(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = srv_validate_configuration_data(NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

    return test_status;
}

/**
 * @brief Test srv_validate_configuration_data() on a datastore with a valid service.
 *
 * Verifies that srv_validate_configuration_data() returns
 * EL2GO_STATUS_SUCCESS when the datastore contains a correctly written
 * and checksummed service descriptor.
 */
static bool test_srv_validate_configuration_data_valid(void *params)
{
    const datastore_test_params_t *p = (const datastore_test_params_t *)params;
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    nxp_iot_ServiceDescriptor sd = nxp_iot_ServiceDescriptor_init_default;
    bool test_status = true;

    status = init_test_datastore(&datastore, "test_srv_validate_valid", p);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    fill_service_descriptor(&sd, 1001, "host1.example.com", 443, nxp_iot_ServiceType_EL2GOSERVICE);
    status = srv_add_service(&datastore, &sd);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);

    status = srv_validate_configuration_data(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    TEST_PRINT_INFO("[%s] Configuration data validated successfully", p->name_suffix);

cleanup:
    (void)el2go_datastore_free(&datastore);

exit:
    return test_status;
}
/* ========================================================================== */
/* Test Registration                                                          */
/* ========================================================================== */

void register_el2go_service_tests(bool include_fs_tests)
{
    TEST_REGISTER(test_srv_get_number_of_services_null);
    TEST_REGISTER_WITH_PARAMS(test_srv_get_number_of_services_empty, (void *)&plain_params);
    TEST_REGISTER_WITH_PARAMS(test_srv_get_number_of_services_after_add, (void *)&plain_params);
    TEST_REGISTER_WITH_PARAMS(test_srv_get_service_by_index_null, (void *)&plain_params);
    TEST_REGISTER_WITH_PARAMS(test_srv_get_service_by_index_empty, (void *)&plain_params);
    TEST_REGISTER_WITH_PARAMS(test_srv_get_service_by_index_out_of_bounds, (void *)&plain_params);
    TEST_REGISTER_WITH_PARAMS(test_srv_get_service_by_index_multiple, (void *)&plain_params);
    TEST_REGISTER_WITH_PARAMS(test_srv_get_service_by_id_null, (void *)&plain_params);
    TEST_REGISTER_WITH_PARAMS(test_srv_get_service_by_id_not_found, (void *)&plain_params);
    TEST_REGISTER_WITH_PARAMS(test_srv_get_service_by_id_multiple, (void *)&plain_params);
    TEST_REGISTER(test_srv_validate_configuration_data_null);

    /* run FS tests only if requested - not all platforms implement FS datastores */
    if (include_fs_tests) {
        TEST_REGISTER_WITH_PARAMS(test_srv_validate_configuration_data_valid,
                                  (void *)&plain_params);
        TEST_REGISTER_WITH_PARAMS(test_srv_validate_configuration_data_valid, (void *)&fs_params);
        TEST_REGISTER_WITH_PARAMS(test_srv_get_number_of_services_empty, (void *)&fs_params);
        TEST_REGISTER_WITH_PARAMS(test_srv_get_number_of_services_after_add, (void *)&fs_params);
        TEST_REGISTER_WITH_PARAMS(test_srv_get_service_by_index_empty, (void *)&fs_params);
        TEST_REGISTER_WITH_PARAMS(test_srv_get_service_by_index_out_of_bounds, (void *)&fs_params);
        TEST_REGISTER_WITH_PARAMS(test_srv_get_service_by_index_multiple, (void *)&fs_params);
        TEST_REGISTER_WITH_PARAMS(test_srv_get_service_by_id_not_found, (void *)&fs_params);
        TEST_REGISTER_WITH_PARAMS(test_srv_get_service_by_id_multiple, (void *)&fs_params);
    }
}

/** @} */ /* end of test_el2go_service_internal */
