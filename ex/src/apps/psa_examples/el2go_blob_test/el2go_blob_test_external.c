/*
 * Copyright 2023 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "el2go_blob_test.h"
#include "el2go_blob_test_psa.h"
#include "el2go_blob_test_external.h"
#include "mcuxClPsaDriver_Oracle_Macros.h"

/* BINARY */

static void el2go_blob_test_external_2000(struct test_result_t *ret)
{
    psa_blob_export_test(
        PSA_KEY_TYPE_RAW_DATA, 1 * 8, PSA_ALG_NONE,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_DATA, 0x3D000000,
        EXTERNAL_BIN1B_EXPORT_NONE, sizeof(EXTERNAL_BIN1B_EXPORT_NONE), ret
    );
}

static void el2go_blob_test_external_2001(struct test_result_t *ret)
{
    psa_blob_export_test(
        PSA_KEY_TYPE_RAW_DATA, 256 * 8, PSA_ALG_NONE,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_DATA, 0x3D000001,
        EXTERNAL_BIN256B_EXPORT_NONE, sizeof(EXTERNAL_BIN256B_EXPORT_NONE), ret
    );
}

static void el2go_blob_test_external_2002(struct test_result_t *ret)
{
    psa_blob_export_test(
        PSA_KEY_TYPE_RAW_DATA, 512 * 8, PSA_ALG_NONE,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_DATA, 0x3D000002,
        EXTERNAL_BIN512B_EXPORT_NONE, sizeof(EXTERNAL_BIN512B_EXPORT_NONE), ret
    );
}

static void el2go_blob_test_external_2003(struct test_result_t *ret)
{
    psa_blob_export_test(
        PSA_KEY_TYPE_RAW_DATA, 1024 * 8, PSA_ALG_NONE,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_DATA, 0x3D000003,
        EXTERNAL_BIN1KB_EXPORT_NONE, sizeof(EXTERNAL_BIN1KB_EXPORT_NONE), ret
    );
}

static void el2go_blob_test_external_2004(struct test_result_t *ret)
{
    psa_blob_export_test(
        PSA_KEY_TYPE_RAW_DATA, 8 * 1024 * 8, PSA_ALG_NONE,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_DATA, 0x3D000004,
        EXTERNAL_BIN8KB_EXPORT_NONE, sizeof(EXTERNAL_BIN8KB_EXPORT_NONE), ret
    );
}

static void el2go_blob_test_external_2005(struct test_result_t *ret)
{
    psa_blob_export_test(
        PSA_KEY_TYPE_RAW_DATA, 16 * 1024 * 8, PSA_ALG_NONE,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_DATA, 0x3D000005,
        EXTERNAL_BIN16KB_EXPORT_NONE, sizeof(EXTERNAL_BIN16KB_EXPORT_NONE), ret
    );
}

static void el2go_blob_test_external_2006(struct test_result_t *ret)
{
    psa_blob_export_test(
        PSA_KEY_TYPE_RAW_DATA, 32 * 1024 * 8, PSA_ALG_NONE,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_DATA, 0x3D000006,
        EXTERNAL_BIN32KB_EXPORT_NONE, sizeof(EXTERNAL_BIN32KB_EXPORT_NONE), ret
    );
}

/* NIST */

static void el2go_blob_test_external_2010(struct test_result_t *ret)
{
    psa_blob_sigmsg_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 192, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000010,
        EXTERNAL_NISTP192_SIGMSG_ECDSASHA256, sizeof(EXTERNAL_NISTP192_SIGMSG_ECDSASHA256), ret
    );
}

static void el2go_blob_test_external_2011(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 192, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000011,
        EXTERNAL_NISTP192_SIGHASH_ECDSASHA256, sizeof(EXTERNAL_NISTP192_SIGHASH_ECDSASHA256), ret
    );
}

static void el2go_blob_test_external_2012(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 192, PSA_ALG_ECDSA_ANY,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000012,
        EXTERNAL_NISTP192_SIGHASH_ECDSAANY, sizeof(EXTERNAL_NISTP192_SIGHASH_ECDSAANY), ret
    );
}

static void el2go_blob_test_external_2013(struct test_result_t *ret)
{
    psa_blob_keyexch_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 192, PSA_ALG_ECDH,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000013,
        EXTERNAL_NISTP192_KEYEXCH_ECDH, sizeof(EXTERNAL_NISTP192_KEYEXCH_ECDH), ret
    );
}

static void el2go_blob_test_external_2020(struct test_result_t *ret)
{
    psa_blob_sigmsg_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 224, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000020,
        EXTERNAL_NISTP224_SIGMSG_ECDSASHA256, sizeof(EXTERNAL_NISTP224_SIGMSG_ECDSASHA256), ret
    );
}

static void el2go_blob_test_external_2021(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 224, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000021,
        EXTERNAL_NISTP224_SIGHASH_ECDSASHA256, sizeof(EXTERNAL_NISTP224_SIGHASH_ECDSASHA256), ret
    );
}

static void el2go_blob_test_external_2022(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 224, PSA_ALG_ECDSA_ANY,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000022,
        EXTERNAL_NISTP224_SIGHASH_ECDSAANY, sizeof(EXTERNAL_NISTP224_SIGHASH_ECDSAANY), ret
    );
}

static void el2go_blob_test_external_2023(struct test_result_t *ret)
{
    psa_blob_keyexch_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 224, PSA_ALG_ECDH,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000023,
        EXTERNAL_NISTP224_KEYEXCH_ECDH, sizeof(EXTERNAL_NISTP224_KEYEXCH_ECDH), ret
    );
}

static void el2go_blob_test_external_2030(struct test_result_t *ret)
{
    psa_blob_sigmsg_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 384, PSA_ALG_ECDSA(PSA_ALG_SHA_384),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000030,
        EXTERNAL_NISTP384_SIGMSG_ECDSASHA384, sizeof(EXTERNAL_NISTP384_SIGMSG_ECDSASHA384), ret
    );
}

static void el2go_blob_test_external_2031(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 384, PSA_ALG_ECDSA(PSA_ALG_SHA_384),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000031,
        EXTERNAL_NISTP384_SIGHASH_ECDSASHA384, sizeof(EXTERNAL_NISTP384_SIGHASH_ECDSASHA384), ret
    );
}

static void el2go_blob_test_external_2032(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 384, PSA_ALG_ECDSA_ANY,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000032,
        EXTERNAL_NISTP384_SIGHASH_ECDSAANY, sizeof(EXTERNAL_NISTP384_SIGHASH_ECDSAANY), ret
    );
}

static void el2go_blob_test_external_2033(struct test_result_t *ret)
{
    psa_blob_keyexch_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 384, PSA_ALG_ECDH,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000033,
        EXTERNAL_NISTP384_KEYEXCH_ECDH, sizeof(EXTERNAL_NISTP384_KEYEXCH_ECDH), ret
    );
}

static void el2go_blob_test_external_2040(struct test_result_t *ret)
{
    psa_blob_sigmsg_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 521, PSA_ALG_ECDSA(PSA_ALG_SHA_512),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000040,
        EXTERNAL_NISTP521_SIGMSG_ECDSASHA512, sizeof(EXTERNAL_NISTP521_SIGMSG_ECDSASHA512), ret
    );
}

static void el2go_blob_test_external_2041(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 521, PSA_ALG_ECDSA(PSA_ALG_SHA_512),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000041,
        EXTERNAL_NISTP521_SIGHASH_ECDSASHA512, sizeof(EXTERNAL_NISTP521_SIGHASH_ECDSASHA512), ret
    );
}

static void el2go_blob_test_external_2042(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 521, PSA_ALG_ECDSA_ANY,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000042,
        EXTERNAL_NISTP521_SIGHASH_ECDSAANY, sizeof(EXTERNAL_NISTP521_SIGHASH_ECDSAANY), ret
    );
}

static void el2go_blob_test_external_2043(struct test_result_t *ret)
{
    psa_blob_keyexch_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 521, PSA_ALG_ECDH,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000043,
        EXTERNAL_NISTP521_KEYEXCH_ECDH, sizeof(EXTERNAL_NISTP521_KEYEXCH_ECDH), ret
    );
}

/* BRAINPOOL */

static void el2go_blob_test_external_2050(struct test_result_t *ret)
{
    psa_blob_sigmsg_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 192, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000050,
        EXTERNAL_BRAINPOOLP192R1_SIGMSG_ECDSASHA256, sizeof(EXTERNAL_BRAINPOOLP192R1_SIGMSG_ECDSASHA256), ret
    );
}

static void el2go_blob_test_external_2051(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 192, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000051,
        EXTERNAL_BRAINPOOLP192R1_SIGHASH_ECDSASHA256, sizeof(EXTERNAL_BRAINPOOLP192R1_SIGHASH_ECDSASHA256), ret
    );
}

static void el2go_blob_test_external_2052(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 192, PSA_ALG_ECDSA_ANY,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000052,
        EXTERNAL_BRAINPOOLP192R1_SIGHASH_ECDSAANY, sizeof(EXTERNAL_BRAINPOOLP192R1_SIGHASH_ECDSAANY), ret
    );
}

static void el2go_blob_test_external_2053(struct test_result_t *ret)
{
    psa_blob_keyexch_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 192, PSA_ALG_ECDH,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000053,
        EXTERNAL_BRAINPOOLP192R1_KEYEXCH_ECDH, sizeof(EXTERNAL_BRAINPOOLP192R1_KEYEXCH_ECDH), ret
    );
}

static void el2go_blob_test_external_2060(struct test_result_t *ret)
{
    psa_blob_sigmsg_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 224, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000060,
        EXTERNAL_BRAINPOOLP224R1_SIGMSG_ECDSASHA256, sizeof(EXTERNAL_BRAINPOOLP224R1_SIGMSG_ECDSASHA256), ret
    );
}

static void el2go_blob_test_external_2061(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 224, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000061,
        EXTERNAL_BRAINPOOLP224R1_SIGHASH_ECDSASHA256, sizeof(EXTERNAL_BRAINPOOLP224R1_SIGHASH_ECDSASHA256), ret
    );
}

static void el2go_blob_test_external_2062(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 224, PSA_ALG_ECDSA_ANY,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000062,
        EXTERNAL_BRAINPOOLP224R1_SIGHASH_ECDSAANY, sizeof(EXTERNAL_BRAINPOOLP224R1_SIGHASH_ECDSAANY), ret
    );
}

static void el2go_blob_test_external_2063(struct test_result_t *ret)
{
    psa_blob_keyexch_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 224, PSA_ALG_ECDH,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000063,
        EXTERNAL_BRAINPOOLP224R1_KEYEXCH_ECDH, sizeof(EXTERNAL_BRAINPOOLP224R1_KEYEXCH_ECDH), ret
    );
}

static void el2go_blob_test_external_2070(struct test_result_t *ret)
{
    psa_blob_sigmsg_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 256, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000070,
        EXTERNAL_BRAINPOOLP256R1_SIGMSG_ECDSASHA256, sizeof(EXTERNAL_BRAINPOOLP256R1_SIGMSG_ECDSASHA256), ret
    );
}

static void el2go_blob_test_external_2071(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 256, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000071,
        EXTERNAL_BRAINPOOLP256R1_SIGHASH_ECDSASHA256, sizeof(EXTERNAL_BRAINPOOLP256R1_SIGHASH_ECDSASHA256), ret
    );
}

static void el2go_blob_test_external_2072(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 256, PSA_ALG_ECDSA_ANY,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000072,
        EXTERNAL_BRAINPOOLP256R1_SIGHASH_ECDSAANY, sizeof(EXTERNAL_BRAINPOOLP256R1_SIGHASH_ECDSAANY), ret
    );
}

static void el2go_blob_test_external_2073(struct test_result_t *ret)
{
    psa_blob_keyexch_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 256, PSA_ALG_ECDH,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000073,
        EXTERNAL_BRAINPOOLP256R1_KEYEXCH_ECDH, sizeof(EXTERNAL_BRAINPOOLP256R1_KEYEXCH_ECDH), ret
    );
}

static void el2go_blob_test_external_2080(struct test_result_t *ret)
{
    psa_blob_sigmsg_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 320, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000080,
        EXTERNAL_BRAINPOOLP320R1_SIGMSG_ECDSASHA256, sizeof(EXTERNAL_BRAINPOOLP320R1_SIGMSG_ECDSASHA256), ret
    );
}

static void el2go_blob_test_external_2081(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 320, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000081,
        EXTERNAL_BRAINPOOLP320R1_SIGHASH_ECDSASHA256, sizeof(EXTERNAL_BRAINPOOLP320R1_SIGHASH_ECDSASHA256), ret
    );
}

static void el2go_blob_test_external_2082(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 320, PSA_ALG_ECDSA_ANY,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000082,
        EXTERNAL_BRAINPOOLP320R1_SIGHASH_ECDSAANY, sizeof(EXTERNAL_BRAINPOOLP320R1_SIGHASH_ECDSAANY), ret
    );
}

static void el2go_blob_test_external_2083(struct test_result_t *ret)
{
    psa_blob_keyexch_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 320, PSA_ALG_ECDH,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000083,
        EXTERNAL_BRAINPOOLP320R1_KEYEXCH_ECDH, sizeof(EXTERNAL_BRAINPOOLP320R1_KEYEXCH_ECDH), ret
    );
}

static void el2go_blob_test_external_2090(struct test_result_t *ret)
{
    psa_blob_sigmsg_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 384, PSA_ALG_ECDSA(PSA_ALG_SHA_384),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000090,
        EXTERNAL_BRAINPOOLP384R1_SIGMSG_ECDSASHA384, sizeof(EXTERNAL_BRAINPOOLP384R1_SIGMSG_ECDSASHA384), ret
    );
}

static void el2go_blob_test_external_2091(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 384, PSA_ALG_ECDSA(PSA_ALG_SHA_384),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000091,
        EXTERNAL_BRAINPOOLP384R1_SIGHASH_ECDSASHA384, sizeof(EXTERNAL_BRAINPOOLP384R1_SIGHASH_ECDSASHA384), ret
    );
}

static void el2go_blob_test_external_2092(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 384, PSA_ALG_ECDSA_ANY,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000092,
        EXTERNAL_BRAINPOOLP384R1_SIGHASH_ECDSAANY, sizeof(EXTERNAL_BRAINPOOLP384R1_SIGHASH_ECDSAANY), ret
    );
}

static void el2go_blob_test_external_2093(struct test_result_t *ret)
{
    psa_blob_keyexch_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 384, PSA_ALG_ECDH,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000093,
        EXTERNAL_BRAINPOOLP384R1_KEYEXCH_ECDH, sizeof(EXTERNAL_BRAINPOOLP384R1_KEYEXCH_ECDH), ret
    );
}

static void el2go_blob_test_external_2100(struct test_result_t *ret)
{
    psa_blob_sigmsg_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 512, PSA_ALG_ECDSA(PSA_ALG_SHA_512),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000100,
        EXTERNAL_BRAINPOOLP512R1_SIGMSG_ECDSASHA512, sizeof(EXTERNAL_BRAINPOOLP512R1_SIGMSG_ECDSASHA512), ret
    );
}

static void el2go_blob_test_external_2101(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 512, PSA_ALG_ECDSA(PSA_ALG_SHA_512),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000101,
        EXTERNAL_BRAINPOOLP512R1_SIGHASH_ECDSASHA512, sizeof(EXTERNAL_BRAINPOOLP512R1_SIGHASH_ECDSASHA512), ret
    );
}

static void el2go_blob_test_external_2102(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 512, PSA_ALG_ECDSA_ANY,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000102,
        EXTERNAL_BRAINPOOLP512R1_SIGHASH_ECDSAANY, sizeof(EXTERNAL_BRAINPOOLP512R1_SIGHASH_ECDSAANY), ret
    );
}

static void el2go_blob_test_external_2103(struct test_result_t *ret)
{
    psa_blob_keyexch_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1), 512, PSA_ALG_ECDH,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000103,
        EXTERNAL_BRAINPOOLP512R1_KEYEXCH_ECDH, sizeof(EXTERNAL_BRAINPOOLP512R1_KEYEXCH_ECDH), ret
    );
}

/* KOBLITZ */

static void el2go_blob_test_external_2110(struct test_result_t *ret)
{
    psa_blob_sigmsg_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1), 192, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000110,
        EXTERNAL_KOBLITZ192_SIGMSG_ECDSASHA256, sizeof(EXTERNAL_KOBLITZ192_SIGMSG_ECDSASHA256), ret
    );
}

static void el2go_blob_test_external_2111(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1), 192, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000111,
        EXTERNAL_KOBLITZ192_SIGHASH_ECDSASHA256, sizeof(EXTERNAL_KOBLITZ192_SIGHASH_ECDSASHA256), ret
    );
}

static void el2go_blob_test_external_2112(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1), 192, PSA_ALG_ECDSA_ANY,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000112,
        EXTERNAL_KOBLITZ192_SIGHASH_ECDSAANY, sizeof(EXTERNAL_KOBLITZ192_SIGHASH_ECDSAANY), ret
    );
}

static void el2go_blob_test_external_2113(struct test_result_t *ret)
{
    psa_blob_keyexch_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1), 192, PSA_ALG_ECDH,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000113,
        EXTERNAL_KOBLITZ192_KEYEXCH_ECDH, sizeof(EXTERNAL_KOBLITZ192_KEYEXCH_ECDH), ret
    );
}

static void el2go_blob_test_external_2120(struct test_result_t *ret)
{
    psa_blob_sigmsg_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1), 224, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000120,
        EXTERNAL_KOBLITZ224_SIGMSG_ECDSASHA256, sizeof(EXTERNAL_KOBLITZ224_SIGMSG_ECDSASHA256), ret
    );
}

static void el2go_blob_test_external_2121(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1), 224, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000121,
        EXTERNAL_KOBLITZ224_SIGHASH_ECDSASHA256, sizeof(EXTERNAL_KOBLITZ224_SIGHASH_ECDSASHA256), ret
    );
}

static void el2go_blob_test_external_2122(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1), 224, PSA_ALG_ECDSA_ANY,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000122,
        EXTERNAL_KOBLITZ224_SIGHASH_ECDSAANY, sizeof(EXTERNAL_KOBLITZ224_SIGHASH_ECDSAANY), ret
    );
}

static void el2go_blob_test_external_2123(struct test_result_t *ret)
{
    psa_blob_keyexch_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1), 224, PSA_ALG_ECDH,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000123,
        EXTERNAL_KOBLITZ224_KEYEXCH_ECDH, sizeof(EXTERNAL_KOBLITZ224_KEYEXCH_ECDH), ret
    );
}

static void el2go_blob_test_external_2130(struct test_result_t *ret)
{
    psa_blob_sigmsg_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1), 256, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000130,
        EXTERNAL_KOBLITZ256_SIGMSG_ECDSASHA256, sizeof(EXTERNAL_KOBLITZ256_SIGMSG_ECDSASHA256), ret
    );
}

static void el2go_blob_test_external_2131(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1), 256, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000131,
        EXTERNAL_KOBLITZ256_SIGHASH_ECDSASHA256, sizeof(EXTERNAL_KOBLITZ256_SIGHASH_ECDSASHA256), ret
    );
}

static void el2go_blob_test_external_2132(struct test_result_t *ret)
{
    psa_blob_sighash_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1), 256, PSA_ALG_ECDSA_ANY,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000132,
        EXTERNAL_KOBLITZ256_SIGHASH_ECDSAANY, sizeof(EXTERNAL_KOBLITZ256_SIGHASH_ECDSAANY), ret
    );
}

static void el2go_blob_test_external_2133(struct test_result_t *ret)
{
    psa_blob_keyexch_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1), 256, PSA_ALG_ECDH,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000133,
        EXTERNAL_KOBLITZ256_KEYEXCH_ECDH, sizeof(EXTERNAL_KOBLITZ256_KEYEXCH_ECDH), ret
    );
}

/* MONTGOMERY */

static void el2go_blob_test_external_2140(struct test_result_t *ret)
{
    psa_blob_keyexch_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY), 256, PSA_ALG_ECDH,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000140,
        EXTERNAL_MONTDH25519_KEYEXCH_ECDH, sizeof(EXTERNAL_MONTDH25519_KEYEXCH_ECDH), ret
    );
}

static void el2go_blob_test_external_2150(struct test_result_t *ret)
{
    psa_blob_keyexch_test(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY), 448, PSA_ALG_ECDH,
        PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY, 0x3D000150,
        EXTERNAL_MONTDH448_KEYEXCH_ECDH, sizeof(EXTERNAL_MONTDH448_KEYEXCH_ECDH), ret
    );
}

/* TEST SUITE */

static struct test_t blob_external_tests[] = {
    {&el2go_blob_test_external_2000, "EL2GO_BLOB_TEST_EXTERNAL_2000",
     "External BIN1B EXPORT NONE"},
    {&el2go_blob_test_external_2001, "EL2GO_BLOB_TEST_EXTERNAL_2001",
     "External BIN256B EXPORT NONE"},
    {&el2go_blob_test_external_2002, "EL2GO_BLOB_TEST_EXTERNAL_2002",
     "External BIN512B EXPORT NONE"},
    {&el2go_blob_test_external_2003, "EL2GO_BLOB_TEST_EXTERNAL_2003",
     "External BIN1KB EXPORT NONE"},
    {&el2go_blob_test_external_2004, "EL2GO_BLOB_TEST_EXTERNAL_2004",
     "External BIN8KB EXPORT NONE"},
    {&el2go_blob_test_external_2005, "EL2GO_BLOB_TEST_EXTERNAL_2005",
     "External BIN16KB EXPORT NONE"},
    {&el2go_blob_test_external_2006, "EL2GO_BLOB_TEST_EXTERNAL_2006",
     "External BIN32KB EXPORT NONE"},

    {&el2go_blob_test_external_2010, "EL2GO_BLOB_TEST_EXTERNAL_2010",
     "External NISTP192 SIGMSG ECDSASHA256"},
    {&el2go_blob_test_external_2011, "EL2GO_BLOB_TEST_EXTERNAL_2011",
     "External NISTP192 SIGHASH ECDSASHA256"},
    {&el2go_blob_test_external_2012, "EL2GO_BLOB_TEST_EXTERNAL_2012",
     "External NISTP192 SIGHASH ECDSAANY"},
    {&el2go_blob_test_external_2013, "EL2GO_BLOB_TEST_EXTERNAL_2013",
     "External NISTP192 KEYEXCH ECDH"},
    {&el2go_blob_test_external_2020, "EL2GO_BLOB_TEST_EXTERNAL_2020",
     "External NISTP224 SIGMSG ECDSASHA256"},
    {&el2go_blob_test_external_2021, "EL2GO_BLOB_TEST_EXTERNAL_2021",
     "External NISTP224 SIGHASH ECDSASHA256"},
    {&el2go_blob_test_external_2022, "EL2GO_BLOB_TEST_EXTERNAL_2022",
     "External NISTP224 SIGHASH ECDSAANY"},
    {&el2go_blob_test_external_2023, "EL2GO_BLOB_TEST_EXTERNAL_2023",
     "External NISTP224 KEYEXCH ECDH"},
    {&el2go_blob_test_external_2030, "EL2GO_BLOB_TEST_EXTERNAL_2030",
     "External NISTP384 SIGMSG ECDSASHA384"},
    {&el2go_blob_test_external_2031, "EL2GO_BLOB_TEST_EXTERNAL_2031",
     "External NISTP384 SIGHASH ECDSASHA384"},
    {&el2go_blob_test_external_2032, "EL2GO_BLOB_TEST_EXTERNAL_2032",
     "External NISTP384 SIGHASH ECDSAANY"},
    {&el2go_blob_test_external_2033, "EL2GO_BLOB_TEST_EXTERNAL_2033",
     "External NISTP384 KEYEXCH ECDH"},
    {&el2go_blob_test_external_2040, "EL2GO_BLOB_TEST_EXTERNAL_2040",
     "External NISTP521 SIGMSG ECDSASHA512"},
    {&el2go_blob_test_external_2041, "EL2GO_BLOB_TEST_EXTERNAL_2041",
     "External NISTP521 SIGHASH ECDSASHA512"},
    {&el2go_blob_test_external_2042, "EL2GO_BLOB_TEST_EXTERNAL_2042",
     "External NISTP521 SIGHASH ECDSAANY"},
    {&el2go_blob_test_external_2043, "EL2GO_BLOB_TEST_EXTERNAL_2043",
     "External NISTP521 KEYEXCH ECDH"},

    {&el2go_blob_test_external_2050, "EL2GO_BLOB_TEST_EXTERNAL_2050",
     "External BRAINPOOLP192R1 SIGMSG ECDSASHA256"},
    {&el2go_blob_test_external_2051, "EL2GO_BLOB_TEST_EXTERNAL_2051",
     "External BRAINPOOLP192R1 SIGHASH ECDSASHA256"},
    {&el2go_blob_test_external_2052, "EL2GO_BLOB_TEST_EXTERNAL_2052",
     "External BRAINPOOLP192R1 SIGHASH ECDSAANY"},
    {&el2go_blob_test_external_2053, "EL2GO_BLOB_TEST_EXTERNAL_2053",
     "External BRAINPOOLP192R1 KEYEXCH ECDH"},
    {&el2go_blob_test_external_2060, "EL2GO_BLOB_TEST_EXTERNAL_2060",
     "External BRAINPOOLP224R1 SIGMSG ECDSASHA256"},
    {&el2go_blob_test_external_2061, "EL2GO_BLOB_TEST_EXTERNAL_2061",
     "External BRAINPOOLP224R1 SIGHASH ECDSASHA256"},
    {&el2go_blob_test_external_2062, "EL2GO_BLOB_TEST_EXTERNAL_2062",
     "External BRAINPOOLP224R1 SIGHASH ECDSAANY"},
    {&el2go_blob_test_external_2063, "EL2GO_BLOB_TEST_EXTERNAL_2063",
     "External BRAINPOOLP224R1 KEYEXCH ECDH"},
    {&el2go_blob_test_external_2070, "EL2GO_BLOB_TEST_EXTERNAL_2070",
     "External BRAINPOOLP256R1 SIGMSG ECDSASHA256"},
    {&el2go_blob_test_external_2071, "EL2GO_BLOB_TEST_EXTERNAL_2071",
     "External BRAINPOOLP256R1 SIGHASH ECDSASHA256"},
    {&el2go_blob_test_external_2072, "EL2GO_BLOB_TEST_EXTERNAL_2072",
     "External BRAINPOOLP256R1 SIGHASH ECDSAANY"},
    {&el2go_blob_test_external_2073, "EL2GO_BLOB_TEST_EXTERNAL_2073",
     "External BRAINPOOLP256R1 KEYEXCH ECDH"},
    {&el2go_blob_test_external_2080, "EL2GO_BLOB_TEST_EXTERNAL_2080",
     "External BRAINPOOLP320R1 SIGMSG ECDSASHA256"},
    {&el2go_blob_test_external_2081, "EL2GO_BLOB_TEST_EXTERNAL_2081",
     "External BRAINPOOLP320R1 SIGHASH ECDSASHA256"},
    {&el2go_blob_test_external_2082, "EL2GO_BLOB_TEST_EXTERNAL_2082",
     "External BRAINPOOLP320R1 SIGHASH ECDSAANY"},
    {&el2go_blob_test_external_2083, "EL2GO_BLOB_TEST_EXTERNAL_2083",
     "External BRAINPOOLP320R1 KEYEXCH ECDH"},
    {&el2go_blob_test_external_2090, "EL2GO_BLOB_TEST_EXTERNAL_2090",
     "External BRAINPOOLP384R1 SIGMSG ECDSASHA384"},
    {&el2go_blob_test_external_2091, "EL2GO_BLOB_TEST_EXTERNAL_2091",
     "External BRAINPOOLP384R1 SIGHASH ECDSASHA384"},
    {&el2go_blob_test_external_2092, "EL2GO_BLOB_TEST_EXTERNAL_2092",
     "External BRAINPOOLP384R1 SIGHASH ECDSAANY"},
    {&el2go_blob_test_external_2093, "EL2GO_BLOB_TEST_EXTERNAL_2093",
     "External BRAINPOOLP384R1 KEYEXCH ECDH"},
    {&el2go_blob_test_external_2100, "EL2GO_BLOB_TEST_EXTERNAL_2100",
     "External BRAINPOOLP512R1 SIGMSG ECDSASHA512"},
    {&el2go_blob_test_external_2101, "EL2GO_BLOB_TEST_EXTERNAL_2101",
     "External BRAINPOOLP512R1 SIGHASH ECDSASHA512"},
    {&el2go_blob_test_external_2102, "EL2GO_BLOB_TEST_EXTERNAL_2102",
     "External BRAINPOOLP512R1 SIGHASH ECDSAANY"},
    {&el2go_blob_test_external_2103, "EL2GO_BLOB_TEST_EXTERNAL_2103",
     "External BRAINPOOLP512R1 KEYEXCH ECDH"},

    {&el2go_blob_test_external_2110, "EL2GO_BLOB_TEST_EXTERNAL_2110",
     "External KOBLITZ192 SIGMSG ECDSASHA256"},
    {&el2go_blob_test_external_2111, "EL2GO_BLOB_TEST_EXTERNAL_2111",
     "External KOBLITZ192 SIGHASH ECDSASHA256"},
    {&el2go_blob_test_external_2112, "EL2GO_BLOB_TEST_EXTERNAL_2112",
     "External KOBLITZ192 SIGHASH ECDSAANY"},
    {&el2go_blob_test_external_2113, "EL2GO_BLOB_TEST_EXTERNAL_2113",
     "External KOBLITZ192 KEYEXCH ECDH"},
    {&el2go_blob_test_external_2120, "EL2GO_BLOB_TEST_EXTERNAL_2120",
     "External KOBLITZ224 SIGMSG ECDSASHA256"},
    {&el2go_blob_test_external_2121, "EL2GO_BLOB_TEST_EXTERNAL_2121",
     "External KOBLITZ224 SIGHASH ECDSASHA256"},
    {&el2go_blob_test_external_2122, "EL2GO_BLOB_TEST_EXTERNAL_2122",
     "External KOBLITZ224 SIGHASH ECDSAANY"},
    {&el2go_blob_test_external_2123, "EL2GO_BLOB_TEST_EXTERNAL_2123",
     "External KOBLITZ224 KEYEXCH ECDH"},
    {&el2go_blob_test_external_2130, "EL2GO_BLOB_TEST_EXTERNAL_2130",
     "External KOBLITZ256 SIGMSG ECDSASHA256"},
    {&el2go_blob_test_external_2131, "EL2GO_BLOB_TEST_EXTERNAL_2131",
     "External KOBLITZ256 SIGHASH ECDSASHA256"},
    {&el2go_blob_test_external_2132, "EL2GO_BLOB_TEST_EXTERNAL_2132",
     "External KOBLITZ256 SIGHASH ECDSAANY"},
    {&el2go_blob_test_external_2133, "EL2GO_BLOB_TEST_EXTERNAL_2133",
     "External KOBLITZ256 KEYEXCH ECDH"},

    {&el2go_blob_test_external_2140, "EL2GO_BLOB_TEST_EXTERNAL_2140",
     "External MONTDH25519 KEYEXCH ECDH"},
    {&el2go_blob_test_external_2150, "EL2GO_BLOB_TEST_EXTERNAL_2150",
     "External MONTDH448 KEYEXCH ECDH"}
};

void testsuite_blob_external(struct test_suite_t *test_suite)
{
    test_suite->name = "EXTERNAL (EL2GO_BLOB_TEST_EXTERNAL_2XXX)";
    test_suite->test_list = blob_external_tests;
    test_suite->test_list_size = (sizeof(blob_external_tests) / sizeof(blob_external_tests[0]));
}
