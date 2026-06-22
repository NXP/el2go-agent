/*
 * Copyright 2020-2021, 2024, 2026 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __COMPILER_H__
#define __COMPILER_H__

#define __weak	       __attribute__((weak))
#if defined(__ZEPHYR__)
#define __export
#elif defined(__GNUC__) || defined(__clang__)
#define __export       __attribute__((visibility("default")))
#else
#define __export
#endif
#define __maybe_unused __attribute__((unused))
#define __packed       __attribute__((packed))
#define __fallthrough  __attribute__((fallthrough))

#endif /* __COMPILER_H__ */
