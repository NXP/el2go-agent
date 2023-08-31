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
/* Copyright 2021-2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* !!!!!!!!!!!!!!!!!!!!!!!!!!!!! */
/* GENERATED FILE. DO NOT EDIT!! */
/* !!!!!!!!!!!!!!!!!!!!!!!!!!!!! */

/* clang-format off */

#ifndef __MBEDTLS_USER_CONFIG_H__
#define __MBEDTLS_USER_CONFIG_H__

/* Generated by sss_x86_mbedtls_config.py */

#ifndef MBEDTLS_CMAC_C
    #define MBEDTLS_CMAC_C
#endif // MBEDTLS_CMAC_C

/*
 * When replacing the elliptic curve module, pleace consider, that it is
 * implemented with two .c files:
 *      - ecp.c
 *      - ecp_curves.c
 * You can replace them very much like all the other MBEDTLS__MODULE_NAME__ALT
 * macros as described above. The only difference is that you have to make sure
 * that you provide functionality for both .c files.
 */
#ifndef MBEDTLS_ECP_ALT
    //#define MBEDTLS_ECP_ALT
#endif // MBEDTLS_ECP_ALT

/**
 * - MBEDTLS_ECDSA_VERIFY_ALT
 * To use SE for all public key ecdsa verify operation, enable MBEDTLS_ECDSA_VERIFY_ALT
 */
// #ifndef MBEDTLS_ECDSA_VERIFY_ALT
//     #define MBEDTLS_ECDSA_VERIFY_ALT
// #endif // MBEDTLS_ECDSA_VERIFY_ALT

#ifndef MBEDTLS_ECDH_ALT
    //#define MBEDTLS_ECDH_ALT
#endif // MBEDTLS_ECDH_ALT

#ifndef MBEDTLS_ECDH_GEN_PUBLIC_ALT
    //#define MBEDTLS_ECDH_GEN_PUBLIC_ALT
#endif // MBEDTLS_ECDH_GEN_PUBLIC_ALT

#ifndef MBEDTLS_ECDH_COMPUTE_SHARED_ALT
    //#define MBEDTLS_ECDH_COMPUTE_SHARED_ALT
#endif // MBEDTLS_ECDH_COMPUTE_SHARED_ALT

#if SSS_HAVE_RSA
#ifndef MBEDTLS_RSA_ALT
    //#define MBEDTLS_RSA_ALT
#endif // MBEDTLS_RSA_ALT
#endif //  SSS_HAVE_RSA

#ifndef MBEDTLS_NIST_KW_C
    #define MBEDTLS_NIST_KW_C
#endif // MBEDTLS_NIST_KW_C

#if SSS_HAVE_MBEDTLS_ALT_PSA
#ifndef MBEDTLS_PSA_CRYPTO_DRIVERS
    //#define MBEDTLS_PSA_CRYPTO_DRIVERS
#endif // MBEDTLS_PSA_CRYPTO_DRIVERS
#endif //  SSS_HAVE_MBEDTLS_ALT_PSA

#ifndef MBEDTLS_USE_PSA_CRYPTO
    #define MBEDTLS_USE_PSA_CRYPTO
#endif // MBEDTLS_USE_PSA_CRYPTO


#if defined(MBEDTLS_SELF_TEST)
    #undef MBEDTLS_SELF_TEST
#endif // MBEDTLS_SELF_TEST

#ifndef MBEDTLS_PSA_CRYPTO_C
    #define MBEDTLS_PSA_CRYPTO_C
#endif // MBEDTLS_PSA_CRYPTO_C

#if !defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
    #define MBEDTLS_ECP_DP_SECP192R1_ENABLED
#endif // MBEDTLS_ECP_DP_SECP192R1_ENABLED

#if !defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
    #define MBEDTLS_ECP_DP_SECP224R1_ENABLED
#endif // MBEDTLS_ECP_DP_SECP224R1_ENABLED

#if !defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
    #define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#endif // MBEDTLS_ECP_DP_SECP384R1_ENABLED

#if !defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
    #define MBEDTLS_ECP_DP_SECP521R1_ENABLED
#endif // MBEDTLS_ECP_DP_SECP521R1_ENABLED

#if defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)
    #undef MBEDTLS_ECP_DP_SECP192K1_ENABLED
#endif // MBEDTLS_ECP_DP_SECP192K1_ENABLED

#if defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)
    #undef MBEDTLS_ECP_DP_SECP224K1_ENABLED
#endif // MBEDTLS_ECP_DP_SECP224K1_ENABLED

#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
    #undef MBEDTLS_ECP_DP_SECP256K1_ENABLED
#endif // MBEDTLS_ECP_DP_SECP256K1_ENABLED

#if defined(MBEDTLS_ECP_DP_BP256R1_ENABLED)
    #undef MBEDTLS_ECP_DP_BP256R1_ENABLED
#endif // MBEDTLS_ECP_DP_BP256R1_ENABLED

#if defined(MBEDTLS_ECP_DP_BP384R1_ENABLED)
    #undef MBEDTLS_ECP_DP_BP384R1_ENABLED
#endif // MBEDTLS_ECP_DP_BP384R1_ENABLED

#if defined(MBEDTLS_ECP_DP_BP512R1_ENABLED)
    #undef MBEDTLS_ECP_DP_BP512R1_ENABLED
#endif // MBEDTLS_ECP_DP_BP512R1_ENABLED

#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
    #undef MBEDTLS_ECP_DP_CURVE25519_ENABLED
#endif // MBEDTLS_ECP_DP_CURVE25519_ENABLED

#if defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
    #undef MBEDTLS_ECP_DP_CURVE448_ENABLED
#endif // MBEDTLS_ECP_DP_CURVE448_ENABLED

#ifndef MBEDTLS_PLATFORM_MEMORY
    #define MBEDTLS_PLATFORM_MEMORY
#endif // MBEDTLS_PLATFORM_MEMORY

#if defined(MBEDTLS_PLATFORM_STD_CALLOC)
    #undef MBEDTLS_PLATFORM_STD_CALLOC
#endif // MBEDTLS_PLATFORM_STD_CALLOC

#if defined(MBEDTLS_PLATFORM_STD_FREE)
    #undef MBEDTLS_PLATFORM_STD_FREE
#endif // MBEDTLS_PLATFORM_STD_FREE

/*#if defined(MBEDTLS_PLATFORM_CALLOC_MACRO)
    #undef MBEDTLS_PLATFORM_CALLOC_MACRO
#endif // MBEDTLS_PLATFORM_CALLOC_MACRO

#if defined(MBEDTLS_PLATFORM_FREE_MACRO)
    #undef MBEDTLS_PLATFORM_FREE_MACRO
#endif // MBEDTLS_PLATFORM_FREE_MACRO
*/
#if defined(FD_SETSIZE)
    #undef FD_SETSIZE
#endif // FD_SETSIZE
#define FD_SETSIZE 1024

#define MBEDTLS_PSA_CRYPTO_STORAGE_C

#if defined(MBEDTLS_HAVE_TIME)
#undef MBEDTLS_HAVE_TIME
#endif

#if defined(MBEDTLS_HAVE_TIME_DATE)
#undef MBEDTLS_HAVE_TIME_DATE
#endif

#endif /* __MBEDTLS_USER_CONFIG_H__ */
