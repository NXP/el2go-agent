/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "test_framework.h"
#include "test_suites.h"
#include <getopt.h>

static void print_usage(const char *prog_name)
{
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("Options:\n");
    printf("  -s, --suite=<name>    Run only tests from specified suite\n");
    printf("                        (el2go_rtp, datastore, keystore, platform,\n");
    printf("                         net_crypto, fwual, ota_lib, ota_agent_core,\n");
    printf("                         ota_agent_advanced)\n");
    printf("  -k, --skip=<list>     Comma-separated list of suites to skip\n");
    printf("  -a, --all             Run all tests (default)\n");
    printf("  -h, --help            Show this help message\n");
}

static bool suite_is_skipped(const char *skip_list, const char *suite_name)
{
    bool found = false;

    if (!skip_list || !suite_name)
        return false;

    /* Duplicate so that strtok does not modify the caller's string. */
    char *copy = malloc(strlen(skip_list) + 1U);
    if (!copy)
        return false;
    (void)strcpy(copy, skip_list);

    char *token = strtok(copy, ",");
    while (token) {
        if (strcmp(token, suite_name) == 0) {
            found = true;
            break;
        }
        token = strtok(NULL, ",");
    }

    free(copy);
    return found;
}

int main(int argc, char **argv)
{
    const char *suite = NULL;
    const char *skip = NULL;
    int opt = 0;

    static struct option long_options[] = { { "suite", required_argument, 0, 's' },
                                            { "skip", required_argument, 0, 'k' },
                                            { "all", no_argument, 0, 'a' },
                                            { "help", no_argument, 0, 'h' },
                                            { 0, 0, 0, 0 } };

    /* Parse command line arguments */
    while (opt != -1) {
        opt = getopt_long(argc, argv, "s:k:ah", long_options, NULL);
        switch (opt) {
        case 's':
            suite = optarg;
            break;
        case 'k':
            skip = optarg;
            break;
        case 'a':
            suite = NULL;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        case -1:
            break;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Warn when the selected suite is also in the skip list - no tests will run. */
    if (suite && suite_is_skipped(skip, suite))
        TEST_PRINT_WARN("--suite=%s is also in --skip list; no tests will run.", suite);

    /* Initialize test framework */
    test_framework_init();

    /* Register tests based on suite filter and skip list */
    if ((!suite || strcmp(suite, "el2go_rtp") == 0) && !suite_is_skipped(skip, "el2go_rtp"))
        register_el2go_rtp_tests(true);

    if ((!suite || strcmp(suite, "datastore") == 0) && !suite_is_skipped(skip, "datastore"))
        register_datastore_tests(true);

    if ((!suite || strcmp(suite, "keystore") == 0) && !suite_is_skipped(skip, "keystore"))
        register_keystore_tests();

    if ((!suite || strcmp(suite, "platform") == 0) && !suite_is_skipped(skip, "platform"))
        register_platform_tests();

    if ((!suite || strcmp(suite, "net_crypto") == 0) && !suite_is_skipped(skip, "net_crypto"))
        register_net_crypto_tests();

/*
 * To enable OTA, pass -DBUILD_OTA=ON at CMake configure time.
 */
#if BUILD_OTA
    if ((!suite || strcmp(suite, "fwual") == 0) && !suite_is_skipped(skip, "fwual"))
        register_fwual_tests();

    if ((!suite || strcmp(suite, "ota_lib") == 0) && !suite_is_skipped(skip, "ota_lib"))
        register_ota_lib_tests();

#ifdef BUILD_INTERNAL_TESTS
    if ((!suite || strcmp(suite, "ota_lib") == 0) && !suite_is_skipped(skip, "ota_lib"))
        register_ota_lib_internal_all_tests();
#endif

#endif /* BUILD_OTA */

    /* Run all registered tests */
    return test_framework_run();
}
