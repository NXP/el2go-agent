/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __EL2GO_RTP_AGENT_CONFIG_H__
#define __EL2GO_RTP_AGENT_CONFIG_H__

/**
 * @file el2go_rtp_agent_config.h
 * @brief Compile-time feature flags for the EL2GO RTP Agent demo.
 *
 * Maps Kconfig symbols (Zephyr) or CMake definitions (Linux) to plain C
 * integer macros. Use these in application code instead of scattered
 * #if defined(CONFIG_*) guards. The compiler eliminates dead branches at
 * -O1 or higher, so there is zero runtime cost when a feature is disabled.
 */

/** Claimcode injection from flash before provisioning. */
#if defined(CONFIG_EL2GO_RTP_CLAIMCODE_INJECT)
#define EL2GO_RTP_CLAIMCODE_INJECT_ENABLED 1
#else
#define EL2GO_RTP_CLAIMCODE_INJECT_ENABLED 0
#endif

/** MQTT connectivity verification after provisioning. */
#if defined(CONFIG_EL2GO_RTP_MQTT_VERIFY)
#define EL2GO_RTP_MQTT_VERIFY_ENABLED 1
#else
#define EL2GO_RTP_MQTT_VERIFY_ENABLED 0
#endif

/* Delay between successive provisioning runs (2 s). */
#define AGENT_LOOP_DELAY_MS (2U * 1000U)

#endif /* __EL2GO_RTP_AGENT_CONFIG_H__ */