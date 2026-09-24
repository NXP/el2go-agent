/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * Workaround for a redefinition clash between priv/compiler.h and 
 * picolibc <sys/cdefs.h> on native_sim.
 */

#ifndef TEST_EL2GO_OTA_COMPAT_SHIM_H
#define TEST_EL2GO_OTA_COMPAT_SHIM_H

#include <stdio.h>

#undef __weak
#undef __packed
#undef __aligned
#undef __fallthrough

#endif /* TEST_EL2GO_OTA_COMPAT_SHIM_H */
