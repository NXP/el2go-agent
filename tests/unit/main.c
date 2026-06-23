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
    printf("                        (el2go_rtp, datastore, net_crypto)\n");
    printf("  -a, --all             Run all tests (default)\n");
    printf("  -h, --help            Show this help message\n");
}

int main(int argc, char **argv)
{
    const char *suite = NULL;
    int opt = 0;

    static struct option long_options[] = { { "suite", required_argument, 0, 's' },
                                            { "all", no_argument, 0, 'a' },
                                            { "help", no_argument, 0, 'h' },
                                            { 0, 0, 0, 0 } };

    /* Parse command line arguments */
    while (opt != -1) {
        opt = getopt_long(argc, argv, "s:ah", long_options, NULL);
        switch (opt) {
        case 's':
            suite = optarg;
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

    /* Initialize test framework */
    test_framework_init();

    /* Register tests based on suite filter */
    if (!suite || strcmp(suite, "el2go_rtp") == 0)
        register_el2go_rtp_tests();

    if (!suite || strcmp(suite, "datastore") == 0)
        register_datastore_tests();

    if (!suite || strcmp(suite, "net_crypto") == 0)
        register_net_crypto_tests();

    /* Run all registered tests */
    return test_framework_run();
}
