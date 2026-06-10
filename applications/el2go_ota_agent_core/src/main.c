// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2026 NXP
 */

#include "fwual/fwual.h"
#include "ota/el2go_ota_lib.h"

int main(void)
{
	if (fwual_init() != EL2GO_STATUS_SUCCESS)
		return 1;
	if (el2go_ota_lib_init() != EL2GO_STATUS_SUCCESS)
		return 1;
	return 0;
}
