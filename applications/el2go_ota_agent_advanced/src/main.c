/* Same as core for now — advanced logic added in a future ticket. */
// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2026 NXP
 */

#include "fwual/fwual.h"
#include "ota/el2go_ota_lib.h"

int main(void)
{
	fwual_init();
	el2go_ota_lib_init();
	return 0;
}
