/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/**
 * @file el2go_app_time.h
 * @brief Wall-clock time abstraction.
 *
 * Declares the interface used by the OTA agent to synchronize and query
 * wall-clock time (for example to enforce an update time window). This header
 * defines the generic contract that every backend must honor; the symbols
 * carry weak defaults so a build links without a concrete backend. Concrete
 * backends differ substantially (for example SNTP vs. an on-chip RTC) and
 * override the weak definitions with the real behavior.
 *
 * @defgroup el2go_app_time Wall-clock Time Abstraction
 * @brief Wall-clock time synchronization and query contract.
 * @{
 */

#ifndef __EL2GO_APP_TIME_H__
#define __EL2GO_APP_TIME_H__

/**
 * @brief Synchronize the time source.
 *
 * Synchronizes the backend time source so subsequent queries return a valid
 * wall-clock time. When using a network time source (for example SNTP) this
 * must be called after the network is up.
 */
void el2go_app_time_sync(void);

/**
 * @brief Get the current UTC hour of day.
 *
 * @return Current UTC hour of day in the range 0-23, or -1 if the time is not
 *         known (for example not yet synchronized).
 */
int el2go_app_time_get_hour_of_day(void);

#endif /* __EL2GO_APP_TIME_H__ */

/** @} */ /* end of el2go_app_time */
