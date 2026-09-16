/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_VERSION_H__
#define __EL2GO_VERSION_H__

/**
 * @defgroup el2go_version Version
 * @brief Compile-time version macros shared by all simw-devicelink libraries.
 *
 * All three libraries (RTP, OTA, FWUAL) expose a get_version() function that
 * fills output pointers with these values.
 *
 * Shared across RTP, OTA and FWUAL -- split into per-library macros when
 * the libraries start releasing independently.
 *
 * Update these three values when releasing a new version.
 * @{
 */

#define EL2GO_LIB_VERSION_MAJOR 7U /**< Major version number */
#define EL2GO_LIB_VERSION_MINOR 0U /**< Minor version number */
#define EL2GO_LIB_VERSION_PATCH 0U /**< Patch version number */

/** @} */ /* end of el2go_version */

#endif /* __EL2GO_VERSION_H__ */
