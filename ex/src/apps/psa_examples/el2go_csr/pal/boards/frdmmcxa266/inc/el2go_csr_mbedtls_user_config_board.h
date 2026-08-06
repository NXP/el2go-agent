/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
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
/* Copyright 2026 NXP
 */

/* clang-format off */

#ifndef __MBEDTLS_USER_CONFIG_BOARD_H__
#define __MBEDTLS_USER_CONFIG_BOARD_H__

#ifdef MBEDTLS_ENTROPY_C
    #undef MBEDTLS_ENTROPY_C
#endif 

#ifdef MBEDTLS_PSA_CRYPTO_STORAGE_C
    #undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#endif 

#ifdef MBEDTLS_CIPHER_C
    #undef MBEDTLS_CIPHER_C
#endif

#ifdef MBEDTLS_PLATFORM_MEMORY
    #undef MBEDTLS_PLATFORM_MEMORY
#endif



#endif /* __MBEDTLS_USER_CONFIG_BOARD_H__ */