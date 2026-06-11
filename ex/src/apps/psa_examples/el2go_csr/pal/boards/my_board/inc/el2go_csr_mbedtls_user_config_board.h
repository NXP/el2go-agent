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

#ifndef MBEDTLS_AES_C
    #define MBEDTLS_AES_C
#endif

#ifndef MBEDTLS_SHA256_C
    #define MBEDTLS_SHA256_C
#endif

#ifndef MBEDTLS_MD_C
    #define MBEDTLS_MD_C
#endif

#ifndef MBEDTLS_BIGNUM_C
    #define MBEDTLS_BIGNUM_C
#endif

#ifndef MBEDTLS_ECP_C
    #define MBEDTLS_ECP_C
#endif

#ifndef MBEDTLS_PKCS5_C    
    #define MBEDTLS_PKCS5_C
#endif

#ifndef MBEDTLS_ECDSA_C
    #define MBEDTLS_ECDSA_C
#endif

#ifndef MBEDTLS_PK_C
    #define MBEDTLS_PK_C
#endif

#ifndef MBEDTLS_PK_PARSE_C
    #define MBEDTLS_PK_PARSE_C
#endif

#ifndef MBEDTLS_PK_WRITE_C
    #define MBEDTLS_PK_WRITE_C
#endif

#ifndef MBEDTLS_ASN1_PARSE_C
    #define MBEDTLS_ASN1_PARSE_C
#endif

#ifndef MBEDTLS_ASN1_WRITE_C
    #define MBEDTLS_ASN1_WRITE_C
#endif

#ifndef MBEDTLS_OID_C
    #define MBEDTLS_OID_C
#endif

#ifndef MBEDTLS_ECP_DP_SECP256R1_ENABLED
    #define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#endif

#ifndef MBEDTLS_NO_PLATFORM_ENTROPY
    #define MBEDTLS_NO_PLATFORM_ENTROPY
#endif

#ifndef MBEDTLS_ENTROPY_HARDWARE_ALT
    #define MBEDTLS_ENTROPY_HARDWARE_ALT
#endif

#endif /* __MBEDTLS_USER_CONFIG_BOARD_H__ */