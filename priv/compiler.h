/*
 * Copyright 2020-2021, 2024, 2026 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __COMPILER_H__
#define __COMPILER_H__

/** @defgroup priv_compiler Private Compiler Helpers
 * @brief Internal compiler attribute macros (visibility, export, inline, etc.).
 * @{
 */

#ifndef __weak
#define __weak __attribute__((weak))
#endif
#ifndef __export
#if defined(__ZEPHYR__)
#define __export
#elif defined(__GNUC__) || defined(__clang__)
#define __export __attribute__((visibility("default")))
#else
#define __export
#endif
#endif
#ifndef __maybe_unused
#define __maybe_unused __attribute__((unused))
#endif
#ifndef __packed
#define __packed __attribute__((packed))
#endif
#ifndef __aligned
#define __aligned(n) __attribute__((aligned(n)))
#endif
#ifndef __fallthrough
#define __fallthrough __attribute__((fallthrough))
#endif

/** @} */ /* end of priv_compiler */

#endif /* __COMPILER_H__ */
