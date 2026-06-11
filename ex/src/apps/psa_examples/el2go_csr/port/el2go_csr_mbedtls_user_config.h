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

#ifndef __MBEDTLS_USER_CONFIG_H__
#define __MBEDTLS_USER_CONFIG_H__

#ifndef MBEDTLS_PLATFORM_MEMORY
    #define MBEDTLS_PLATFORM_MEMORY
#endif 

#ifndef MBEDTLS_USE_PSA_CRYPTO
    #define MBEDTLS_USE_PSA_CRYPTO
#endif

#ifndef MBEDTLS_PSA_CRYPTO_CONFIG
    #define MBEDTLS_PSA_CRYPTO_CONFIG
#endif 

#ifndef MBEDTLS_PSA_CRYPTO_C
    #define MBEDTLS_PSA_CRYPTO_C
#endif 

#ifndef MBEDTLS_PSA_CRYPTO_STORAGE_C
    #define MBEDTLS_PSA_CRYPTO_STORAGE_C
#endif 

#ifndef MBEDTLS_BASE64_C
    #define MBEDTLS_BASE64_C
#endif 

#ifndef MBEDTLS_CIPHER_C
    #define MBEDTLS_CIPHER_C
#endif 

#ifndef MBEDTLS_ENTROPY_C
    #define MBEDTLS_ENTROPY_C
#endif 

#ifndef MBEDTLS_PEM_WRITE_C
    #define MBEDTLS_PEM_WRITE_C
#endif 

#ifndef MBEDTLS_PLATFORM_C
    #define MBEDTLS_PLATFORM_C
#endif 

#ifndef MBEDTLS_VERSION_C
    #define MBEDTLS_VERSION_C
#endif 

#ifndef MBEDTLS_X509_USE_C
    #define MBEDTLS_X509_USE_C
#endif 

#ifndef MBEDTLS_X509_CRT_PARSE_C
    #define MBEDTLS_X509_CRT_PARSE_C
#endif 

#ifndef MBEDTLS_X509_CREATE_C
    #define MBEDTLS_X509_CREATE_C
#endif 

#ifndef MBEDTLS_X509_CSR_WRITE_C
    #define MBEDTLS_X509_CSR_WRITE_C
#endif 

#include "el2go_csr_mbedtls_user_config_board.h"

#endif /* __MBEDTLS_USER_CONFIG_H__ */

