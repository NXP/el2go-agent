/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *  Copyright 2026 NXP
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef __EL2GO_CSR_MBEDTLS_USER_CONFIG_BOARD_H__
#define __EL2GO_CSR_MBEDTLS_USER_CONFIG_BOARD_H__

/* RW61x requires ASN.1 write support for X.509 CSR generation. */
#ifndef MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_ASN1_WRITE_C
#endif

#pragma GCC diagnostic ignored "-Wunused-function"

#endif /* __EL2GO_CSR_MBEDTLS_USER_CONFIG_BOARD_H__ */
