/*
 *
 * Copyright 2018-2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SSS_APIS_INC_FSL_SSS_FTR_H_
#define SSS_APIS_INC_FSL_SSS_FTR_H_

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

/* clang-format off */


/* # CMake Features : Start */

/** PTMW_HostCrypto : Counterpart Crypto on Host
 *
 * What is being used as a cryptographic library on the host.
 * As of now only OpenSSL / mbedTLS is supported
 */

/** Use mbedTLS as host crypto */
#define SSS_HAVE_HOSTCRYPTO_MBEDTLS 1

/** Use OpenSSL as host crypto */
#define SSS_HAVE_HOSTCRYPTO_OPENSSL 0

/** User Implementation of Host Crypto
 * e.g. Files at ``sss/src/user/crypto`` have low level AES/CMAC primitives.
 * The files at ``sss/src/user`` use those primitives.
 * This becomes an example for users with their own AES Implementation
 * This then becomes integration without mbedTLS/OpenSSL for SCP03 / AESKey.
 *
 * .. note:: ECKey abstraction is not implemented/available yet. */
#define SSS_HAVE_HOSTCRYPTO_USER 0

/** NO Host Crypto
 * Note, this is unsecure and only provided for experimentation
 * on platforms that do not have an mbedTLS PORT
 * Many :ref:`sssftr-control` have to be disabled to have a valid build. */
#define SSS_HAVE_HOSTCRYPTO_NONE 0

#if (( 0                             \
    + SSS_HAVE_HOSTCRYPTO_MBEDTLS    \
    + SSS_HAVE_HOSTCRYPTO_OPENSSL    \
    + SSS_HAVE_HOSTCRYPTO_USER       \
    + SSS_HAVE_HOSTCRYPTO_NONE       \
    ) > 1)
#        error "Enable only one of 'PTMW_HostCrypto'"
#endif


#if (( 0                             \
    + SSS_HAVE_HOSTCRYPTO_MBEDTLS    \
    + SSS_HAVE_HOSTCRYPTO_OPENSSL    \
    + SSS_HAVE_HOSTCRYPTO_USER       \
    + SSS_HAVE_HOSTCRYPTO_NONE       \
    ) == 0)
#        error "Enable at-least one of 'PTMW_HostCrypto'"
#endif



/** PTMW_mbedTLS_ALT : ALT Engine implementation for mbedTLS
 *
 * When set to None, mbedTLS would not use ALT Implementation to connect to / use Secure Element.
 * This needs to be set to SSS for Cloud Demos over SSS APIs
 */

/** Use SSS Layer ALT implementation */
#define SSS_HAVE_MBEDTLS_ALT_SSS 0

/** Legacy implementation */
#define SSS_HAVE_MBEDTLS_ALT_A71CH 0

/** Enable TF-M based on PSA as ALT */
#define SSS_HAVE_MBEDTLS_ALT_PSA 1

/** Not using any mbedTLS_ALT
 *
 * When this is selected, cloud demos can not work with mbedTLS */
#define SSS_HAVE_MBEDTLS_ALT_NONE 0

#if (( 0                             \
    + SSS_HAVE_MBEDTLS_ALT_SSS       \
    + SSS_HAVE_MBEDTLS_ALT_A71CH     \
    + SSS_HAVE_MBEDTLS_ALT_PSA       \
    + SSS_HAVE_MBEDTLS_ALT_NONE      \
    ) > 1)
#        error "Enable only one of 'PTMW_mbedTLS_ALT'"
#endif


#if (( 0                             \
    + SSS_HAVE_MBEDTLS_ALT_SSS       \
    + SSS_HAVE_MBEDTLS_ALT_A71CH     \
    + SSS_HAVE_MBEDTLS_ALT_PSA       \
    + SSS_HAVE_MBEDTLS_ALT_NONE      \
    ) == 0)
#        error "Enable at-least one of 'PTMW_mbedTLS_ALT'"
#endif

/* ========= Calculated values : END ======================== */

/* clang-format on */

#endif /* SSS_APIS_INC_FSL_SSS_FTR_H_ */
