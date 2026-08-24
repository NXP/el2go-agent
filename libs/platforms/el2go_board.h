/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef EL2GO_BOARD_H
#define EL2GO_BOARD_H

/**
 * el2go_board_init - Initialize board hardware.
 *
 * A __weak no-op is provided for platforms (e.g. Zephyr) where board
 * initialization is handled outside the application. Platform-specific
 * builds (e.g. MCUXpresso SDK) override this with BOARD_InitHardware().
 */
void el2go_board_init(void);

#endif /* EL2GO_BOARD_H */
