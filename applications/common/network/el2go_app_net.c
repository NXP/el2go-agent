/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * Network module weak default. No-op that reports success so builds without
 * a concrete backend link. See the zephyr/ backends for the real behavior.
 */

#include "el2go_app_compiler.h"
#include "el2go_app_net.h"

/**
 * @copydoc el2go_app_net_init
 *
 * Weak default. No-op that reports success so a build links without a
 * concrete network backend. See the zephyr/ backends for the real behavior.
 */
__weak int el2go_app_net_init(void)
{
    return 0;
}
