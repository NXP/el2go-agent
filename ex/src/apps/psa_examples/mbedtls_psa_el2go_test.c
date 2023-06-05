/*
 * Copyright 2021,2022 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "board.h"
#include "app.h"

#include "ksdk_mbedtls.h"

#include <psa/crypto.h>

#include <mcuxClCss.h>
#include <mcuxClKey.h>
#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClPsaDriver.h>

#include <nxp_iot_css_keys_derivation.h>



#define ASSERT_STATUS( actual, expected )                                     \
    do                                                                        \
    {                                                                         \
        if( ( actual ) != ( expected ) )                                      \
        {                                                                     \
            PRINTF( "\tassertion failed at %s:%d - "                  \
                    "actual:%d expected:%d\r\n", __FILE__, __LINE__,  \
                            (psa_status_t) actual, (psa_status_t) expected ); \
            goto exit;                                                        \
        }                                                                     \
    } while ( 0 )
      
#define PSA_ERROR(...)                          \
    for (;;)                                           \
    {                                                  \
        PRINTF("ERROR: %s L#%d ", __func__, __LINE__); \
        PRINTF(__VA_ARGS__);                           \
        PRINTF("\r\n");                                \
        break;                                         \
    }

#define PSA_EXIT_STATUS_MSG(STATUS, ...) \
    psa_status = STATUS;                        \
    PSA_ERROR(__VA_ARGS__);              \
    goto exit;

#define PSA_SUCCESS_OR_EXIT_MSG(...) \
    if (PSA_SUCCESS != psa_status)          \
    {                                       \
        PSA_ERROR(__VA_ARGS__);      \
        goto exit;                          \
    }

#define PSA_SUCCESS_OR_EXIT() \
    PSA_SUCCESS_OR_EXIT_MSG("psa_status is not success but [0x%08x]", psa_status)

#define PSA_SET_STATUS_SUCCESS_AND_EXIT() \
    psa_status = PSA_SUCCESS;                    \
    goto exit;

#define PSA_ASSERT_OR_EXIT_STATUS_MSG(CONDITION, STATUS, ...) \
    if (!(CONDITION))                                                \
    {                                                                \
        PSA_EXIT_STATUS_MSG(STATUS, __VA_ARGS__);             \
    }
	  

#define RTOS_STACK_SIZE (1024*4)
      
#define LIFETIME_INTERNAL PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_LOCATION_S50_TEMP_STORAGE)
#define LIFETIME_EXTERNAL PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_LOCATION_LOCAL_STORAGE)
      
      
bool css_enable() 
{
  bool result;
  
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_Enable_Async());
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Enable_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result)) {
    PRINTF("mcuxClCss_Enable_Async failed: 0x%08x", result);
    return false;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR)); 
  if(((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))) {
  PRINTF("mcuxClCss_WaitForOperation failed: 0x%08x", result);
   return false;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
      
  return true;  
}

bool css_disable() 
{
  bool result;
  
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_Disable());
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Disable) != token) || (MCUXCLCSS_STATUS_OK != result)) {
    PRINTF("mcuxClCss_Disable failed: 0x%08x", result);
    return false;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  
  return true;
}

bool css_gen_keyPair(mcuxClCss_KeyIndex_t key_pair_idx, uint8_t *pPublicKey)
{ 
   
  mcuxClCss_EccKeyGenOption_t pk_options = {0};
  pk_options.bits.kgsrc = MCUXCLCSS_ECC_OUTPUTKEY_RANDOM;
  pk_options.bits.kgsign = MCUXCLCSS_ECC_PUBLICKEY_SIGN_DISABLE;
  pk_options.bits.kgsign_rnd = MCUXCLCSS_ECC_NO_RANDOM_DATA;
  //pk_options.bits.skip_pbk = MCUXCLCSS_ECC_SKIP_PUBLIC_KEY;
  
  mcuxClCss_KeyProp_t key_properties = {0};                           
  key_properties.word.value = 0u;
  key_properties.bits.upprot_priv = MCUXCLCSS_KEYPROPERTY_PRIVILEGED_TRUE;
  //key_properties.bits.upprot_sec = MCUXCLCSS_KEYPROPERTY_SECURE_FALSE;
  //key_properties.bits.uecsg       = MCUXCLCSS_KEYPROPERTY_ECC_TRUE;
  //key_properties.bits.ksize       = MCUXCLCSS_KEYPROPERTY_KEY_SIZE_256;
  key_properties.bits.wrpok = MCUXCLCSS_KEYPROPERTY_WRAP_TRUE;
  key_properties.bits.kactv = MCUXCLCSS_KEYPROPERTY_ACTIVE_TRUE;
  key_properties.bits.ukgsrc= MCUXCLCSS_KEYPROPERTY_INPUT_FOR_ECC_TRUE;
  //key_properties.bits.kbase = MCUXCLCSS_KEYPROPERTY_BASE_SLOT;
  //key_properties.bits.upprot_sec = MCUXCLCSS_KEYPROPERTY_SECURE_FALSE;
  //key_properties.bits.uecsg       = MCUXCLCSS_KEYPROPERTY_ECC_TRUE;
  //key_properties.bits.ksize       = MCUXCLCSS_KEYPROPERTY_KEY_SIZE_256;
  
  PRINTF("ecc_key_pair_props: 0x%08x\r\n", key_properties.word.value);
  PRINTF("ecc_key_pair_options: 0x%08x\r\n", pk_options.word.value);
   
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_EccKeyGen_Async( 
                                                                            pk_options,
                                                                            (mcuxClCss_KeyIndex_t) 0U,
                                                                            key_pair_idx,
                                                                            key_properties,
                                                                            NULL,
                                                                            pPublicKey));
  
  if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_EccKeyGen_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result)) {
    PRINTF("mcuxClCss_EccKeyGen_Async failed: 0x%08x", result);
    return false; 
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result)) {
    PRINTF("mcuxClCss_WaitForOperation failed: 0x%08x", result);
    return false;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  return true;  
}

/**
 *Name: css_load_iot_blob_on_slot
 *Description: Test unwrap iothub provisioned blob on CSS slot. 
 *Steps:
 *- Unwrap/Load iothub blob on css slot
 *- Use key to sign/verify dummy data to verify operation
*/
bool test_css_load_iot_rfc3394_blob_on_slot() {
  
  //targetKey:  d230bdb1a759e80927acb2037a69118a187652b11f40e5819a3043b0354eabc5 (NIST-P-256)
  //BLOB:       A764A9D7D89422D05B85D3E83DC2B6FB043EA740D86F5FBA1F84A99217842227665F44EB589E8C7C77F7C90181614531 (RFC3394 wrapped with NXP_DIE_EL2GOIMPORT_KEK_SK , value 2b6c81b3fa1c60d23ee9ba3a9f778388f9704cca190c2932daf1af8b98265213)
  //KeyIN:	84000061 00000000 D230BDB1A759E80927ACB2037A69118A187652B11F40E5819A3043B0354EABC5 // KeyProps | zero bytes | target key
  //Key Props bits 0x84000061 - [KSIZE 0 0x00000001, KACTV 5 0x00000020, KBASE 6 0x00000040, UPPROT 31 0x80000000, UKGSRC 26 0x4000000]  
 
  static const uint8_t IOT_SECP256_S50_BLOB[] = 
  {0x9D, 0x58, 0x61, 0x52, 0xEC, 0x5E, 0x54, 0xE4, 0xDD, 0x6F, 0x16, 0x91, 0xFE, 
  0x44, 0x6C, 0xD9, 0x98, 0x92, 0x52, 0x30, 0x53, 0x42, 0xE8, 0x47, 0x7C, 0xE0, 
  0x5E, 0x48, 0x9C, 0x3C, 0x28, 0xDD, 0x89, 0x0C, 0x6D, 0x61, 0xF6, 0x20, 0x72, 
  0xC8, 0x69, 0x34, 0x8A, 0x25, 0x02, 0x5C, 0x00, 0x5E};
  
  static uint8_t const ecc_digest[MCUXCLCSS_HASH_OUTPUT_SIZE_SHA_256] =
  {0x61, 0x20, 0xED, 0xC2, 0x19, 0x35, 0x05, 0x02, 0xEE, 0x5C, 0x12, 0x33, 0x3A,
  0x0E, 0x7E, 0x06, 0x5B, 0xAF, 0x2A, 0x05, 0x22, 0x94, 0xB0, 0x96, 0x62, 0x90,
  0x5B, 0xA7, 0xEB, 0x19, 0x55, 0x61};

  static mcuxClCss_EccByte_t ecc_signature[MCUXCLCSS_ECC_SIGNATURE_SIZE];
  static mcuxClCss_EccByte_t ecc_signature_r[MCUXCLCSS_ECC_SIGNATURE_R_SIZE];
  static mcuxClCss_EccByte_t ecc_signature_and_public_key[MCUXCLCSS_ECC_SIGNATURE_SIZE + MCUXCLCSS_ECC_PUBLICKEY_SIZE];

  static const uint8_t ecc_public_key[MCUXCLCSS_ECC_PUBLICKEY_SIZE] = 
  {0x0F, 0x3F, 0x97, 0x1D, 0x29, 0xF3, 0xE9, 0x67, 0x9C, 0x08, 0x6D, 0xCD, 0x9A,
  0x2A, 0xD5, 0xDB, 0xF4, 0xB7, 0x85, 0x55, 0x15, 0x72, 0x78, 0x37, 0x48, 0xFA,
  0xE4, 0x3E, 0x71, 0xE0, 0xD6, 0xC8, 0x74, 0x14, 0xD9, 0xF3, 0x55, 0xAA, 0xEF, 
  0x76, 0xCC, 0xF6, 0xDE, 0xED, 0x46, 0x25, 0x05, 0x41, 0x91, 0x65, 0x6F, 0x1C,
  0x3C, 0x1C, 0x84, 0x8B, 0x01, 0x57, 0xD3, 0x79, 0x42, 0xB6, 0xE9, 0xC5};

  
  bool css_result;
  mcuxClCss_KeyIndex_t wrap_key_idx = EL2GOIMPORT_KEK_SK_IDX; // assign wrapping key id
  mcuxClCss_KeyIndex_t target_slot;
  uint8_t output[48] = {0};
  
  css_result = css_enable();
  ASSERT_STATUS(css_result, true);
    
  css_result = execute_el2go_key_derivation_example();
  ASSERT_STATUS(css_result, true);
    
  target_slot = getFreeSlotIndex();
  
  // Key Import
  mcuxClCss_KeyImportOption_t options;
  options.bits.kfmt = MCUXCLCSS_KEYIMPORT_KFMT_RFC3394;
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_KeyImport_Async(options,
                                                                            IOT_SECP256_S50_BLOB,
                                                                            sizeof(IOT_SECP256_S50_BLOB),
                                                                            wrap_key_idx,
                                                                            target_slot));
  if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_KeyImport_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
  {
    PRINTF("mcuxClCss_KeyImport_Async failed: 0x%08x", result);
    return PSA_ERROR_HARDWARE_FAILURE;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
                                   result, token,
                                   mcuxClCss_WaitForOperation(
                                                              MCUXCLCSS_ERROR_FLAGS_CLEAR));
  if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
  {
    PRINTF("mcuxClCss_KeyImport_Async mcuxClCss_WaitForOperation failed: 0x%08x", result);
    return PSA_ERROR_HARDWARE_FAILURE;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();  
  
  // Intermediate step after key import - KEYGEN (DETERMINISTIC keyProp set automaticly)
  mcuxClCss_KeyProp_t key_properties;
  key_properties.word.value       = 0u; // other properties are set automatically by the command
  key_properties.bits.upprot_priv = MCUXCLCSS_KEYPROPERTY_PRIVILEGED_FALSE;
  key_properties.bits.upprot_sec  = MCUXCLCSS_KEYPROPERTY_SECURE_FALSE;
    
    
  mcuxClCss_EccKeyGenOption_t KeyGenOptions;
  KeyGenOptions.word.value    = 0u;
  KeyGenOptions.bits.kgsign   = MCUXCLCSS_ECC_PUBLICKEY_SIGN_DISABLE;
  KeyGenOptions.bits.kgsrc    = MCUXCLCSS_ECC_OUTPUTKEY_DETERMINISTIC;
  KeyGenOptions.bits.skip_pbk    = MCUXCLCSS_ECC_SKIP_PUBLIC_KEY;
  //key_properties.bits.kactv = MCUXCLCSS_KEYPROPERTY_ACTIVE_TRUE;
  //key_properties.bits.ukgsrc= MCUXCLCSS_KEYPROPERTY_INPUT_FOR_ECC_TRUE;
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_EccKeyGen_Async(
                                                                            KeyGenOptions,
                                                                            NULL,
                                                                            target_slot,
                                                                            key_properties,
                                                                            NULL,
                                                                            NULL));
  if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_EccKeyGen_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
  {
    PRINTF("mcuxClCss_EccKeyGen_Async failed: 0x%08x", result);
    return false;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_LimitedWaitForOperation(0x00100000U, MCUXCLCSS_ERROR_FLAGS_CLEAR));
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_LimitedWaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
  {
    PRINTF("mcuxClCss_EccKeyGen_Async mcuxClCss_LimitedWaitForOperation failed: 0x%08x", result);
    return false;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  
  // sign/verify using the loaded key
  mcuxClCss_EccSignOption_t SignOptions = {0}; 
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_EccSign_Async(
                                                                          SignOptions,   
                                                                          target_slot,      
                                                                          ecc_digest, NULL, (size_t) 0U,
                                                                          ecc_signature));
  // mcuxClCss_EccSign_Async is a flow-protected function: Check the protection token and the return value
  if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_EccSign_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
  {
    PRINTF("mcuxClCss_EccSign_Async mcuxClCss_WaitForOperation failed: 0x%08x", result);
    return false; // Expect that no error occurred, meaning that the mcuxClCss_EccSign_Async operation was started.
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_LimitedWaitForOperation(0x00100000U, MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_EccSign_Async operation to complete.
  // mcuxClCss_LimitedWaitForOperation is a flow-protected function: Check the protection token and the return value
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_LimitedWaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
  {
    PRINTF("mcuxClCss_EccSign_Async mcuxClCss_LimitedWaitForOperation failed: 0x%08x", result);
    return false;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Concatenate signature and public key to prepare input for EccVerify_Async */
  for(size_t i = 0u; i < MCUXCLCSS_ECC_SIGNATURE_SIZE; i++) {
    ecc_signature_and_public_key[i] = ecc_signature[i];
  }
  for(size_t i = 0u; i < MCUXCLCSS_ECC_PUBLICKEY_SIZE; i++) {
    ecc_signature_and_public_key[MCUXCLCSS_ECC_SIGNATURE_SIZE + i] = ecc_public_key[i];
  }
  
  PRINTF("\r\n");
  PRINTF("Signature value: ");
  for (int i = 0; i < MCUXCLCSS_ECC_SIGNATURE_SIZE; i++)
  {
    PRINTF("%02X", ecc_signature[i]);
  }
  PRINTF("\r\n");
  
  PRINTF("Ecc_public_key value: ");
  for (int i = 0; i < MCUXCLCSS_ECC_PUBLICKEY_SIZE; i++)
  {
    PRINTF("%02X", ecc_public_key[i]);
  }
  PRINTF("\r\n");
  
  PRINTF("ecc_signature_and_public_key value: ");
  for (int i = 0; i < MCUXCLCSS_ECC_SIGNATURE_SIZE + MCUXCLCSS_ECC_PUBLICKEY_SIZE; i++)
  {
    PRINTF("%02X", ecc_signature_and_public_key[i]);
  }
  PRINTF("\r\n");
  
  
  mcuxClCss_EccVerifyOption_t VerifyOptions = {0}; // Initialize a new configuration for the planned mcuxClCss_EccVerify_Async operation.
  VerifyOptions.bits.echashchl = MCUXCLCSS_ECC_HASHED;
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_EccVerify_Async(// Perform signature verification.
                                                                            VerifyOptions,                                                  // Set the prepared configuration.
                                                                            ecc_digest, NULL, (size_t) 0U,                // Pre-hashed data to verify. Note that inputLength parameter is ignored since pre-hashed data has a fixed length.
                                                                            ecc_signature_and_public_key,                                   // Concatenation of signature of the pre-hashed data and public key used
                                                                            ecc_signature_r                                                 // Output buffer, which the operation will write the signature part r to, to allow external comparison of between given and recalculated r.
                                                                              ));
  // mcuxClCss_EccVerify_Async is a flow-protected function: Check the protection token and the return value
  if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_EccVerify_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
  {
    PRINTF("mcuxClCss_EccVerify_Async failed: 0x%08x", result);
    return false; // Expect that no error occurred, meaning that the mcuxClCss_EccVerify_Async operation was started.
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_LimitedWaitForOperation(0x00100000U, MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_EccVerify_Async operation to complete.
  // mcuxClCss_LimitedWaitForOperation is a flow-protected function: Check the protection token and the return value
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_LimitedWaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
  {
    PRINTF("mcuxClCss_EccVerify_Async mcuxClCss_LimitedWaitForOperation failed: 0x%08x", result);
    return false;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  
  PRINTF("ecc_signature_r value: ");
  for (int i = 0; i < MCUXCLCSS_ECC_SIGNATURE_SIZE/2; i++)
  {
    PRINTF("%02X", ecc_signature_r[i]);
  }
  PRINTF("\r\n");
  
  
  mcuxClCss_HwState_t state;
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_GetHwState(&state));
  // mcuxClCss_GetHwState is a flow-protected function: Check the protection token and the return value
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_GetHwState) != token) || (MCUXCLCSS_STATUS_OK != result))
  {
    PRINTF("mcuxClCss_GetHwState failed: 0x%08x", result);
    return false;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  
  if (MCUXCLCSS_STATUS_ECDSAVFY_OK != state.bits.ecdsavfy)
  {
    PRINTF("ecdsavfy bit not OK %d: ", state.bits.ecdsavfy);
    return false; // Expect that mcuxClCss_EccVerify_Async operation successfully performed the signature verification.
  }
  
  /* Delete key */
  mcuxClCss_Status_t del_result = mcuxClCss_KeyDelete_Async(target_slot);
  if (MCUXCLCSS_STATUS_OK_WAIT != del_result)
  {
    PRINTF("mcuxClCss_KeyDelete_Async failed: 0x%08x", del_result);
    return false;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_LimitedWaitForOperation(0x00100000U, MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_KeyDelete_Async operation to complete.
  // mcuxClCss_LimitedWaitForOperation is a flow-protected function: Check the protection token and the return value
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_LimitedWaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
  {
    PRINTF("mcuxClCss_LimitedWaitForOperation failed: 0x%08x", del_result);
    return false;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  
  // delete derived keys and free slots
  css_result = delete_derived_keys();
  ASSERT_STATUS(css_result, true);
  
  css_result = css_disable();
  ASSERT_STATUS(css_result, true);
  
  return true;
exit:
  return false;
}


/**
 *Name: test_css_wrap_unwrap_rfc3394_key_sign_vry
 *Description: This test does S50 KeyExport and KeyImport command. After import we use sign/verify operation to confirm the flow.
 * Steps: KEYEXPORT
 *        KEYIMPORT
 *        SIGN
 *        VERIFY
 *
*/
bool test_css_wrap_unwrap_rfc3394_key_sign_vry()
{
  
  static uint8_t const ecc_digest[MCUXCLCSS_HASH_OUTPUT_SIZE_SHA_256] =
  {0x61, 0x20, 0xED, 0xC2, 0x19, 0x35, 0x05, 0x02, 0xEE, 0x5C, 0x12, 0x33, 0x3A,
  0x0E, 0x7E, 0x06, 0x5B, 0xAF, 0x2A, 0x05, 0x22, 0x94, 0xB0, 0x96, 0x62, 0x90,
  0x5B, 0xA7, 0xEB, 0x19, 0x55, 0x61};

  static mcuxClCss_EccByte_t ecc_signature[MCUXCLCSS_ECC_SIGNATURE_SIZE];
  static mcuxClCss_EccByte_t ecc_signature_r[MCUXCLCSS_ECC_SIGNATURE_R_SIZE];
  static mcuxClCss_EccByte_t ecc_signature_and_public_key[MCUXCLCSS_ECC_SIGNATURE_SIZE + MCUXCLCSS_ECC_PUBLICKEY_SIZE];
  uint8_t ecc_public_key[64] = {0};
  mcuxClCss_KeyIndex_t wrap_key_idx = 0;
  mcuxClCss_KeyIndex_t wrap_target_key_idx = 4;
  mcuxClCss_KeyIndex_t unwrap_target_key_idx = 6;
  
  
  uint8_t output_blob[MCUXCLCSS_RFC3394_CONTAINER_SIZE_256] = {0}; // size is 48 bytes
  bool css_result;
  
  css_result = css_enable();
  ASSERT_STATUS(css_result, true);
 
  css_result = keyProv_wrap_key_test(wrap_key_idx);
  ASSERT_STATUS(css_result, true);
  
  css_result = css_gen_keyPair(wrap_target_key_idx, ecc_public_key);
  ASSERT_STATUS(css_result, true);
  
  PRINTF("\r\n Public Key: ");
  PRINTF("\r\n");
  for (int i = 0; i < MCUXCLCSS_ECC_PUBLICKEY_SIZE; i++)
  {
    PRINTF("%02X", ecc_public_key[i]);
  }
  PRINTF("\r\n");
  PRINTF("wrap_key_idx: %d\r\n", wrap_key_idx);
  PRINTF("wrap_key_idx: %d\r\n", wrap_target_key_idx);
  PRINTF("wrap_key_idx: %d\r\n", unwrap_target_key_idx);

  /* wrap blob */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_KeyExport_Async(wrap_key_idx,
                                                                            wrap_target_key_idx,
                                                                            output_blob));
  if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_KeyExport_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
  {
    PRINTF("mcuxClCss_KeyExport_Async failed: 0x%08x", result);
    return false;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
                                   result, token,
                                   mcuxClCss_WaitForOperation(
                                                              MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_EccKeyGen_Async operation to complete.
  // mcuxClCss_LimitedWaitForOperation is a flow-protected function: Check the protection token and the return value
  if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
  {
    PRINTF("mcuxClCss_KeyExport_Async mcuxClCss_WaitForOperation failed: 0x%08x", result);
    return false;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  
  PRINTF("\r\n Rfc3394 container: ");
  PRINTF("\r\n");
  for (int i = 0; i < MCUXCLCSS_RFC3394_CONTAINER_SIZE_256; i++)
  {
    PRINTF("%02X", output_blob[i]);
  }
  PRINTF("\r\n");
  
 
  mcuxClCss_KeyImportOption_t import_options;
  import_options.word.value = 0;
  import_options.bits.kfmt = MCUXCLCSS_KEYIMPORT_KFMT_RFC3394;

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_KeyImport_Async(import_options,
                                                                            output_blob,
                                                                            MCUXCLCSS_RFC3394_CONTAINER_SIZE_256,
                                                                            wrap_key_idx,
                                                                            unwrap_target_key_idx)); // unwrap slot
  if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_KeyImport_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
  {
    PRINTF("mcuxClCss_KeyImport_Async failed: 0x%08x", result);
    return false;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
                                   result, token,
                                   mcuxClCss_WaitForOperation(
                                                              MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_EccKeyGen_Async operation to complete.
  // mcuxClCss_LimitedWaitForOperation is a flow-protected function: Check the protection token and the return value
  if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
  {
    PRINTF("mcuxClCss_KeyImport_Async mcuxClCss_WaitForOperation failed: 0x%08x", result);
    return false;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  
 // sign/verify using the loaded key
  mcuxClCss_EccSignOption_t SignOptions = {0}; 
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_EccSign_Async(
                                                                          SignOptions,   
                                                                          unwrap_target_key_idx,      
                                                                          ecc_digest, NULL, (size_t) 0U,
                                                                          ecc_signature));
  // mcuxClCss_EccSign_Async is a flow-protected function: Check the protection token and the return value
  if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_EccSign_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
  {
    PRINTF("mcuxClCss_EccSign_Async mcuxClCss_WaitForOperation failed: 0x%08x", result);
    return false; // Expect that no error occurred, meaning that the mcuxClCss_EccSign_Async operation was started.
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_LimitedWaitForOperation(0x00100000U, MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_EccSign_Async operation to complete.
  // mcuxClCss_LimitedWaitForOperation is a flow-protected function: Check the protection token and the return value
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_LimitedWaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
  {
    PRINTF("mcuxClCss_EccSign_Async mcuxClCss_LimitedWaitForOperation failed: 0x%08x", result);
    return false;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Concatenate signature and public key to prepare input for EccVerify_Async */
  for(size_t i = 0u; i < MCUXCLCSS_ECC_SIGNATURE_SIZE; i++) {
    ecc_signature_and_public_key[i] = ecc_signature[i];
  }
  for(size_t i = 0u; i < MCUXCLCSS_ECC_PUBLICKEY_SIZE; i++) {
    ecc_signature_and_public_key[MCUXCLCSS_ECC_SIGNATURE_SIZE + i] = ecc_public_key[i];
  }
  
  PRINTF("\r\n");
  PRINTF("Signature value: ");
  for (int i = 0; i < MCUXCLCSS_ECC_SIGNATURE_SIZE; i++)
  {
    PRINTF("%02X", ecc_signature[i]);
  }
  PRINTF("\r\n");
  
  PRINTF("Ecc_public_key value: ");
  for (int i = 0; i < MCUXCLCSS_ECC_PUBLICKEY_SIZE; i++)
  {
    PRINTF("%02X", ecc_public_key[i]);
  }
  PRINTF("\r\n");
  
  PRINTF("ecc_signature_and_public_key value: ");
  for (int i = 0; i < MCUXCLCSS_ECC_SIGNATURE_SIZE + MCUXCLCSS_ECC_PUBLICKEY_SIZE; i++)
  {
    PRINTF("%02X", ecc_signature_and_public_key[i]);
  }
  PRINTF("\r\n");
  
  
  mcuxClCss_EccVerifyOption_t VerifyOptions = {0}; // Initialize a new configuration for the planned mcuxClCss_EccVerify_Async operation.
  VerifyOptions.bits.echashchl = MCUXCLCSS_ECC_HASHED;
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_EccVerify_Async(// Perform signature verification.
                                                                            VerifyOptions,                                                  // Set the prepared configuration.
                                                                            ecc_digest, NULL, (size_t) 0U,                // Pre-hashed data to verify. Note that inputLength parameter is ignored since pre-hashed data has a fixed length.
                                                                            ecc_signature_and_public_key,                                   // Concatenation of signature of the pre-hashed data and public key used
                                                                            ecc_signature_r                                                 // Output buffer, which the operation will write the signature part r to, to allow external comparison of between given and recalculated r.
                                                                              ));
  // mcuxClCss_EccVerify_Async is a flow-protected function: Check the protection token and the return value
  if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_EccVerify_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
  {
    PRINTF("mcuxClCss_EccVerify_Async failed: 0x%08x", result);
    return false; // Expect that no error occurred, meaning that the mcuxClCss_EccVerify_Async operation was started.
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_LimitedWaitForOperation(0x00100000U, MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_EccVerify_Async operation to complete.
  // mcuxClCss_LimitedWaitForOperation is a flow-protected function: Check the protection token and the return value
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_LimitedWaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
  {
    PRINTF("mcuxClCss_EccVerify_Async mcuxClCss_LimitedWaitForOperation failed: 0x%08x", result);
    return false;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  
  PRINTF("ecc_signature_r value: ");
  for (int i = 0; i < MCUXCLCSS_ECC_SIGNATURE_SIZE/2; i++)
  {
    PRINTF("%02X", ecc_signature_r[i]);
  }
  PRINTF("\r\n");
  
  
  mcuxClCss_HwState_t state;
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_GetHwState(&state));
  // mcuxClCss_GetHwState is a flow-protected function: Check the protection token and the return value
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_GetHwState) != token) || (MCUXCLCSS_STATUS_OK != result))
  {
    PRINTF("mcuxClCss_GetHwState failed: 0x%08x", result);
    return false;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  
  if (MCUXCLCSS_STATUS_ECDSAVFY_OK != state.bits.ecdsavfy)
  {
    PRINTF("ecdsavfy bit not OK %d: ", state.bits.ecdsavfy);
    return false; // Expect that mcuxClCss_EccVerify_Async operation successfully performed the signature verification.
  }
  
  css_result = css_disable();
  ASSERT_STATUS(css_result, true);
  return true;
exit:
  return false;
}

typedef struct
{
    const char *name;
    bool ( *function )( void );
} mbedtls_psa_el2go_test_t;

bool css_load_iot_rfc3394_blob_on_slot (void) {
  return test_css_load_iot_rfc3394_blob_on_slot();
}

bool css_wrap_unwrap_rfc3394_key_sign_vry (void) {
  return test_css_wrap_unwrap_rfc3394_key_sign_vry();
}

/**
 *Name: test_derived_key_for_tls_connection
 *Description: This test simulates iot agent tls flow. The goal of the test
 * is to use CSS key from slot with mbedtls sign/verify functions with
 * help of mbedtls_pk_setup_opaque. In real scenario we will reference signature
 * key from slot using mbedtls_pk_setup_opaque before executing TLS connection 
 * with the server.
 *Steps:
 *- Build a blob with receipt on how to derive the key in S50
 *- Call psa_import_key and provide the created blob blob (will be stored in TFM),
 *  Oracle will validate PSA attributes and store the key in TFM
 *- Use psa public PSA sign function, which will first derive the key
 *  into CSS slot (Oracle) and execute the crypto operations.
 *- Execute the signature verification using the corresponding public key with PSA APIs

*/
bool test_derived_key_for_tls_connection()
{
    psa_status_t psa_status;
    // in case CSS is used the key used for TLS connection will be imported as a blob
    // with instruction on how can be used
    static const uint8_t derive_key_buffer[] =
    {
    // 1st API: KEYPROV to derive NXP_DIE_EXT_MK_SK (temporary, only for A0)
    0x20, 0x7A, 
      // type: KEY_PROV, storage option: TEMP_KEY
      0x21, 0x02, 0x02, 0x00,
      // parameter 1: options = 0x00000000
      0x34, 0x04, 0x00, 0x00, 0x00, 0x00,
      // parameter 2: shared 1
      0x35, 0x20,
      0x4e, 0x53, 0x27, 0x90, 0x94, 0xbe, 0x56, 0xa8, 0x27, 0x67, 0x53, 0x40, 0xac, 0x51, 0xa4, 0xbc,
      0x39, 0xb5, 0x41, 0xa5, 0x22, 0x6e, 0xe3, 0x83, 0x43, 0xbd, 0x99, 0xa4, 0x4a, 0x7e, 0x61, 0xdf,
      // parameter 3: shared 2
      0x36, 0x40,
      0xcb, 0x30, 0xfa, 0x0c, 0x17, 0x35, 0x5d, 0x8a, 0x3a, 0xcc, 0x82, 0x4f, 0xd1, 0x3b, 0xe4, 0xe9,
      0x99, 0xb7, 0xc8, 0x48, 0x3f, 0x44, 0x86, 0x73, 0x6e, 0xfa, 0xad, 0x26, 0xfd, 0xcd, 0x72, 0x7d,
      0xf3, 0x91, 0x6b, 0xa7, 0x93, 0xb4, 0xe5, 0x22, 0x91, 0xa3, 0xdd, 0x7f, 0x65, 0xd8, 0x6a, 0xcc,
      0xec, 0xfc, 0x92, 0x56, 0x7c, 0x5d, 0xc0, 0x05, 0xd4, 0x69, 0x4d, 0x82, 0x78, 0xf8, 0x85, 0x07,
      // parameter 1: target key ID = NXP_DIE_EXT_MK_SK (0x00000000)
      0x31, 0x04, 0x00, 0x00, 0x00, 0x00,
      // parameter 2: key properties = 0xA0010000
      0x32, 0x04, 0xA0, 0x01, 0x00, 0x00,
    // 2nd API: CKDF to derive NXP_DIE_EL2GOPUBLIC_MK_SK
    0x20, 0x24, 
      // type: CKDF, storage option: TEMP_KEY
      0x21, 0x02, 0x00, 0x00,
      // parameter 1: derivation key ID = NXP_DIE_EXT_MK_SK (0x00000000)
      0x30, 0x04, 0x00, 0x00, 0x00, 0x00,
      // parameter 2: target key ID = EL2GOPUBLIC_MK_SK_IDX (0x00000004)
      0x31, 0x04, 0x00, 0x00, 0x00, 0x04,
      // parameter 3: key properties = 0x80010021
      0x32, 0x04, 0x80, 0x01, 0x00, 0x21,
      // parameter 4: derivation data = 0x00, 'e', '2', 'g', 'p', 'u', 'b', '_', 'm', 'k', 0x00, 0x00
      0x33, 0x0C, 0x00, 0x65, 0x32, 0x67, 0x70, 0x75, 0x62, 0x5f, 0x6d, 0x6b,  0x00,  0x00,
    // 3rd API: CKDF to derive NXP_DIE_EL2GOCONN_AUTH_PRK_SEED 
    0x20, 0x24, 
      // type: CKDF, storage option: TEMP_KEY
      0x21, 0x02, 0x00, 0x00,
      // parameter 1: derivation key ID = EL2GOPUBLIC_MK_SK_IDX (0x00000004)
      0x30, 0x04, 0x00, 0x00, 0x00, 0x04,
      // parameter 2: target key ID = EL2GOCONN_SEED_IDX (0x00000006)
      0x31, 0x04, 0x00, 0x00, 0x00, 0x06,
      // parameter 3: key properties = 0x84000021
      0x32, 0x04, 0x84, 0x00, 0x00, 0x21,
      // parameter 4: derivation data = 0x00, 'e', '2', 'g', 'c', 'o', 'n', '_', 's', 'e', 0x00, 0x00
      0x33, 0x0C, 0x00, 0x65, 0x32, 0x67, 0x63, 0x6f, 0x6e, 0x5f, 0x73, 0x65, 0x00, 0x00,
    // 4th API: KEYGEN to derive NXP_DIE_EL2GOCONN_AUTH_PRK
    0x20, 0x16, 
      // type: KEY_GEN, storage option: FINAL_KEY (will be associated with the mbedtls_svc_key_id_t)
      0x21, 0x02, 0x01, 0x01,
      // parameter 1: options = 0x00000000
      0x34, 0x04, 0x00, 0x00, 0x00, 0x00,
      // parameter 2: target key ID = EL2GOCONN_SEED_IDX (0x00000006)
      0x31, 0x04, 0x00, 0x00, 0x00, 0x06,
      // parameter 3: key properties = 0x80040001
      0x32, 0x04, 0x80, 0x04, 0x00, 0x01
    };
	uint8_t public_key [] =
	{
	  	0x04, 0xDD, 0x63, 0xA2, 0x5E, 0xE9, 0x9D, 0x87, 0xA2, 0xCD, 0x9C, 0x6E, 0x16, 0x20, 0x01, 0xBB,
		0x1A, 0xE7, 0x31, 0x9B, 0x31, 0x71, 0xC9, 0xF7, 0xB1, 0x6A, 0x4E, 0xB9, 0xBF, 0xB8, 0xCD, 0x9E,
		0xE1, 0x9D, 0x3C, 0x7F, 0x54, 0xB3, 0x4F, 0x8B, 0x83, 0xF0, 0x79, 0x8B, 0x12, 0x01, 0x52, 0x83,
		0x2E, 0x54, 0xE4, 0x3A, 0x3C, 0xFF, 0x3F, 0x5D, 0x70, 0xB9, 0x96, 0xF9, 0xA9, 0x90, 0x55, 0xA6,
		0x25
	};
	uint8_t input[PSA_SIGNATURE_MAX_SIZE];
	uint8_t signature[PSA_SIGNATURE_MAX_SIZE];
	size_t signature_length;
	
	psa_status = psa_crypto_init();
	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_crypto_init");

	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_attributes_t public_key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t id = 0U;
	psa_key_id_t public_key_id = 0U;
	
	/* Set key attributes */
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH));
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_PERSISTENT, PSA_KEY_LOCATION_VENDOR_FLAG | 0x03U));
    psa_set_key_id(&attributes, 0x3fff0201);
	  
	/* Import the key */
	psa_status = psa_import_key(&attributes, derive_key_buffer, sizeof(derive_key_buffer), &id);
	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_import_key");

	psa_status = psa_generate_random(input, sizeof(input));
	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_generate_random");

	/* Compute signature */
	psa_status = psa_sign_hash(id,
		PSA_ALG_ECDSA(PSA_ALG_SHA_256),
		input,
		256,
		signature,
		PSA_SIGNATURE_MAX_SIZE,
		&signature_length);
	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_sign_hash");
	  
	
	/* Set key attributes */
	psa_set_key_usage_flags(&public_key_attributes, PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE);
	psa_set_key_algorithm(&public_key_attributes, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH));
	psa_set_key_type(&public_key_attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&public_key_attributes, 256);
	psa_set_key_lifetime(&public_key_attributes, PSA_KEY_LIFETIME_VOLATILE);

	/* Import the corresponding public key */
	psa_status = psa_import_key(&public_key_attributes, public_key, sizeof(public_key), &public_key_id);
	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_import_key of public key");

	psa_status = psa_verify_hash(public_key_id,
		PSA_ALG_ECDSA(PSA_ALG_SHA_256),
		input,
		256,
		signature,
		signature_length);
	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_verify_hash");
	
	return true;
exit:
	/* Free the attributes */
	psa_reset_key_attributes(&attributes);

	/* Destroy the key */
	psa_status = psa_destroy_key(id);
	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_destroy_key");
	return false;
}


/**
 *Name: test_psa_import_key_aes (internal key)
 *Description: This test simulates iot agent import/load key functionality.
 * The goal of the test is to load a key on CSS slot over Oracle functionality
 * and use it with public PSA encrypt/decrypt functions.
 *Steps:
 *- Derive unwrapping key using CSS low level driver on CSS slot
 *- Call psa_import_key and provide el2go blob (will be stored in TFM)
 *- Oracle will validate PSA attributes and store the key in TFM
 *- Use psa public PSA encrypt/decrypt functions, which will first load a key
 *- into CSS slot (Oracle) and execute the crypto operations.
*/

/**
 *Name: test_psa_import_key_hmac (internal key)
 *Description: This test simulates iot agent import/load key functionality.
 * The goal of the test is to load a key on CSS slot over Oracle functionality
 * and use it with public PSA hmac functions.
 *Steps:
 *- Derive unwrapping key using CSS low level driver on CSS slot
 *- Call psa_import_key and provide el2go blob (will be stored in TFM)
 *- Oracle will validate PSA attributes and store the key in TFM
 *- Use psa public PSA hmac functions, which will first load a key
 *- into CSS slot (Oracle) and execute the crypto operations.
*/

/**
 *Name: test_psa_import_key_blob_internal
 *Description: This test simulates iot agent import/load key functionality.
 * The goal of the test is to load a key on CSS slot over Oracle functionality
 * and use it with public PSA sign/verify functions.
 *Steps:
 *- Build a private key blob
 *- Call psa_import_key and provide el2go blob (will be stored in TFM),
 *  Oracle will validate PSA attributes and store the key in TFM
 *- Use psa public PSA sign function, which will first load a key
 *  into CSS slot (Oracle) and execute the crypto operations.
 *- Execute the signature verification using the corresponding public key with PSA APIs
*/
bool test_psa_import_key_blob_internal()
{
    psa_status_t psa_status;
	uint8_t private_key_blob [] =
	{
	  	// MAGIC
		0x40, 0x0B, 0x65, 0x64, 0x67, 0x65, 0x6C, 0x6F, 0x63, 0x6B, 0x32, 0x67, 0x6F,
		// KEY ID
		0x41, 0x04, 0x00, 0x00, 0x40, 0x00,
		// PERMITTED ALGORITHM
		0x42, 0x04, 0x06, 0x00, 0x06, 0xFF,
		// KEY USAGE FLAGS
		0x43, 0x04, 0x00, 0x00, 0x14, 0x00,
		// KEY TYPE
		0x44, 0x02, 0x71, 0x12,
		// KEY BITS
		0x45, 0x04, 0x00, 0x00, 0x01, 0x00,
		// KEY LIFETIME
		0x46, 0x04, 0x80, 0x00, 0x01, 0x01,
		// WRAPPING KEY ID
		0x50, 0x04, 0x3F, 0xFF, 0x02, 0x10,
		// WRAPPING ALGORITHM
		0x51, 0x04, 0x00, 0x00, 0x00, 0x01,
		// SIGNATURE KEY ID
		0x53, 0x04, 0x3F, 0xFF, 0x02, 0x12,
		// SIGNATURE ALGORITHM
		0x54, 0x04, 0x00, 0x00, 0x00, 0x01,
		// KEY IN BLOB
		0x55, 0x30, 0xB8, 0x40, 0xCE, 0x5A, 0x73, 0x07, 0xE5, 0xC5, 0x91, 0x63, 0x1D, 0xD5, 0xD6, 0xE2,
			0x23, 0x65, 0xB5, 0xCE, 0x8F, 0x9B, 0x28, 0xBB, 0x5D, 0x95, 0xF0, 0x77, 0x4F, 0xEF, 0x10, 0xC7,
			0xBF, 0x4D, 0x7F, 0x0C, 0x42, 0x50, 0x7A, 0xB6, 0x7F, 0xC5, 0xA0, 0x59, 0x66, 0x94, 0x7C, 0x29,
			0xB6, 0x02,
		// SINGATURE
		0x5E, 0x10, 0x47, 0x2F, 0x87, 0x40, 0x68, 0x8F, 0x35, 0xF8, 0xE9, 0x2A, 0x72, 0x07, 0x7C, 0x78, 0xF1, 0x2B
	};
	uint8_t public_key [] =
	{
	  	0x04, 0x7A, 0xFC, 0xE4, 0xD2, 0x2D, 0xE7, 0x86, 0xB5, 0x74, 0xFB, 0xB2, 0x15, 0x07, 0x31, 0x0B,
		0x10, 0x2C, 0x4C, 0x62, 0x34, 0x93, 0x69, 0x56, 0x11, 0xC7, 0x10, 0x65, 0x8B, 0xD5, 0x5B, 0x7F,
		0xEC, 0xED, 0x75, 0xE7, 0x04, 0x76, 0x5B, 0x32, 0x7F, 0xF5, 0x5A, 0x37, 0x21, 0xA7, 0x8F, 0x26,
		0x4D, 0xA2, 0x42, 0x6C, 0x94, 0x10, 0x8B, 0xFD, 0x93, 0xB6, 0x0C, 0xBD, 0x4B, 0x0F, 0xEF, 0x6B,
		0x93
	};
	uint8_t input[PSA_SIGNATURE_MAX_SIZE];
	uint8_t signature[PSA_SIGNATURE_MAX_SIZE];
	size_t signature_length;
	
	psa_status = psa_crypto_init();
	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_crypto_init");

	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_attributes_t public_key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t id = 0U;
	psa_key_id_t public_key_id = 0U;
	
	/* Set key attributes */
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH));
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_PERSISTENT, PSA_KEY_LOCATION_VENDOR_FLAG | 0x01U));
	psa_set_key_bits(&attributes, 256);
    psa_set_key_id(&attributes, 0x00004000);
	  
	/* Import the key */
	psa_status = psa_import_key(&attributes, private_key_blob, sizeof(private_key_blob), &id);
	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_import_key");

	psa_status = psa_generate_random(input, sizeof(input));
	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_generate_random");

	/* Compute signature */
	psa_status = psa_sign_hash(id,
		PSA_ALG_ECDSA(PSA_ALG_SHA_256),
		input,
		256,
		signature,
		PSA_SIGNATURE_MAX_SIZE,
		&signature_length);
	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_sign_hash");
	  
	
	/* Set key attributes */
	psa_set_key_usage_flags(&public_key_attributes, PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE);
	psa_set_key_algorithm(&public_key_attributes, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH));
	psa_set_key_type(&public_key_attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&public_key_attributes, 256);
	psa_set_key_lifetime(&public_key_attributes, PSA_KEY_LIFETIME_VOLATILE);

	/* Import the corresponding public key */
	psa_status = psa_import_key(&public_key_attributes, public_key, sizeof(public_key), &public_key_id);
	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_import_key of public key");

	psa_status = psa_verify_hash(public_key_id,
		PSA_ALG_ECDSA(PSA_ALG_SHA_256),
		input,
		256,
		signature,
		signature_length);
	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_verify_hash");
	
	return true;
exit:
	/* Free the attributes */
	psa_reset_key_attributes(&attributes);

	/* Destroy the key */
	psa_status = psa_destroy_key(id);
	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_destroy_key");
	return false;
}

/**
 *Name: test_psa_import_key_plain
 *Description: This test executes a PSA import key function for importing
 * a plain ECC NIST-P256 private key. The goal is to check if PSA library
 * successfully working before to start with more complex tests
*/
bool test_psa_import_key_plain()
{  

	psa_status_t psa_status;
	uint8_t EC_SECP_R1_256_KEY[] =
	{
		0x8B, 0xDE, 0xE3, 0x32, 0xFC, 0xB0, 0x95, 0xBF, 0x63, 0xF2, 0xE5, 0x9E, 0xD5, 0xE3, 0x48, 0x9D,
		0x7B, 0xEF, 0xAE, 0xEE, 0x22, 0x6D, 0x31, 0x0E, 0x84, 0xE0, 0x52, 0xDF, 0x22, 0x1A, 0x1A, 0x25
	};
	uint8_t EC_SECP_R1_256_PUBLIC_KEY[] =
	{
	  	0x04, 0x7A, 0xFC, 0xE4, 0xD2, 0x2D, 0xE7, 0x86, 0xB5, 0x74, 0xFB, 0xB2, 0x15, 0x07, 0x31, 0x0B,
		0x10, 0x2C, 0x4C, 0x62, 0x34, 0x93, 0x69, 0x56, 0x11, 0xC7, 0x10, 0x65, 0x8B, 0xD5, 0x5B, 0x7F,
		0xEC, 0xED, 0x75, 0xE7, 0x04, 0x76, 0x5B, 0x32, 0x7F, 0xF5, 0x5A, 0x37, 0x21, 0xA7, 0x8F, 0x26,
		0x4D, 0xA2, 0x42, 0x6C, 0x94, 0x10, 0x8B, 0xFD, 0x93, 0xB6, 0x0C, 0xBD, 0x4B, 0x0F, 0xEF, 0x6B,
		0x93
	};
	uint8_t input[PSA_SIGNATURE_MAX_SIZE];
	uint8_t signature[PSA_SIGNATURE_MAX_SIZE];
	size_t signature_length;

	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t id = 0U;
	psa_key_attributes_t public_key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t public_key_id = 0U;

	psa_status = psa_crypto_init();
	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_crypto_init");

	/* Set key attributes */
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH));
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);

	/* Import the key */
	psa_status = psa_import_key(&attributes, EC_SECP_R1_256_KEY, sizeof(EC_SECP_R1_256_KEY), &id);
	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_import_key");
	
	// Comment since there is issue in the driver wrapper with sign hash and LOCAL sotrage
//	psa_status = psa_generate_random(input, sizeof(input));
//	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_generate_random");
//
//	psa_status = psa_sign_hash(id,
//		PSA_ALG_ECDSA(PSA_ALG_SHA_256),
//		input,
//		256,
//		signature,
//		PSA_SIGNATURE_MAX_SIZE,
//		&signature_length);
//	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_sign_hash");
//	
//	/* Set key attributes */
//	psa_set_key_usage_flags(&public_key_attributes, PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE);
//	psa_set_key_algorithm(&public_key_attributes, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH));
//	psa_set_key_type(&public_key_attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
//	psa_set_key_lifetime(&public_key_attributes, PSA_KEY_LIFETIME_VOLATILE);
//
//	/* Import the corresponding public key */
//	psa_status = psa_import_key(&public_key_attributes, EC_SECP_R1_256_PUBLIC_KEY, sizeof(EC_SECP_R1_256_PUBLIC_KEY), &public_key_id);
//	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_import_key of public key");
//
//	psa_status = psa_verify_hash(public_key_id,
//		PSA_ALG_ECDSA(PSA_ALG_SHA_256),
//		input,
//		256,
//		signature,
//		signature_length);
//	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_verify_hash");	
	return true;
exit:

	/* Free the attributes */
	psa_reset_key_attributes(&attributes);

	/* Destroy the key */
	psa_status = psa_destroy_key(id);
	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_destroy_key");

	return false;
}

/**
 *Name: test_psa_import_certificate_blob_external (external data)
 *Description: This test simulates iot agent import functionality.
 * The goal of the test is to import a binary data into device over Oracle
 * functionality and read out the data in playin.
 *Steps:
 *- Derive decryption key using CSS low level driver on CSS slot
 *- Call psa_import_key and provide el2go blob (will be stored in TFM)
 *- Oracle will validate PSA attributes and store the key in TFM
 *- Import a target data into TFM module (mocked) using Oracle functionality
 *- Read out data as plain
*/
bool test_psa_import_certificate_blob_external()
{
    psa_status_t psa_status;
	
	uint8_t cert_blob [] =
	{
	  	// MAGIC
		0x40, 0x0B, 0x65, 0x64, 0x67, 0x65, 0x6C, 0x6F, 0x63, 0x6B, 0x32, 0x67, 0x6F,
		// KEY ID
		0x41, 0x04, 0x00, 0x00, 0x41, 0x01,
		// PERMITTED ALGORITHM
		0x42, 0x04, 0x00, 0x00, 0x00, 0x00,
		// KEY USAGE FLAGS
		0x43, 0x04, 0x00, 0x00, 0x00, 0x01,
		// KEY TYPE
		0x44, 0x02, 0x10, 0x01,
		// KEY BITS
		0x45, 0x04, 0x00, 0x00, 0x0A, 0xB8,
		// KEY LIFETIME
		0x46, 0x04, 0x80, 0x00, 0x00, 0x01,
		// WRAPPING KEY ID
		0x50, 0x04, 0x3F, 0xFF, 0x02, 0x11,
		// WRAPPING ALGORITHM
		0x51, 0x04, 0x00, 0x00, 0x00, 0x02,
		// IV
		0x52, 0x10, 0x01, 0x50, 0xBD, 0xA6, 0xF1, 0x29, 0x22, 0xC3, 0x70, 0x7F, 0x88, 0xE6, 0xAB, 0x92, 0x3F, 0x4F,
		// SIGNATURE KEY ID
		0x53, 0x04, 0x3F, 0xFF, 0x02, 0x12,
		// SIGNATURE ALGORITHM
		0x54, 0x04, 0x00, 0x00, 0x00, 0x01,
		// KEY IN BLOB
		0x55, 0x82, 0x01, 0x60, 0x5A, 0xC2, 0x01, 0xE0, 0x78, 0xE2, 0x94, 0xDA, 0x1F, 0x57, 0xBC, 0xBD,
			0xEF, 0xAE, 0x10, 0x21, 0x9A, 0xE4, 0xF9, 0x5A, 0x4F, 0x12, 0xEB, 0xDE, 0x8C, 0x6C, 0xF4, 0x79,
			0xBD, 0x5E, 0x1F, 0x1A, 0xD2, 0xE4, 0x36, 0x6A, 0x9D, 0xCE, 0x39, 0xFD, 0x3A, 0x9D, 0x05, 0x4C,
			0x28, 0xD9, 0x69, 0xCD, 0x4B, 0xB1, 0x8A, 0xD1, 0xE8, 0xD6, 0xFC, 0xBB, 0x60, 0xA5, 0xD8, 0x68,
			0xE7, 0x98, 0xFA, 0x64, 0x35, 0xC9, 0x0E, 0xB1, 0x0E, 0x22, 0xA5, 0x0C, 0xDF, 0xFC, 0x99, 0x55,
			0x8D, 0x61, 0xB6, 0xC0, 0x9A, 0x3F, 0x0F, 0xE2, 0x05, 0x6D, 0x60, 0xE9, 0x28, 0x8F, 0x8D, 0xD2,
			0x0E, 0xF8, 0x60, 0xC6, 0x68, 0xB3, 0xA7, 0x03, 0x9A, 0x24, 0xCE, 0xF6, 0xB3, 0xF9, 0x30, 0x0E,
			0x7B, 0xEF, 0x19, 0xC6, 0x34, 0xE3, 0x7B, 0x67, 0x94, 0xFA, 0x68, 0x1D, 0xEB, 0x9E, 0xF7, 0xD0,
			0x6E, 0xBD, 0x78, 0x82, 0x0A, 0x8A, 0x6E, 0x29, 0x71, 0x47, 0x54, 0x39, 0xC6, 0x90, 0xF7, 0xA8,
			0x09, 0x39, 0xFC, 0xE0, 0x48, 0xE7, 0xBC, 0x3E, 0x2A, 0xE6, 0x13, 0xC2, 0x96, 0x10, 0x5A, 0x0A,
			0x80, 0x2F, 0x7A, 0x49, 0x91, 0xE6, 0x71, 0x17, 0x3C, 0xB2, 0xFC, 0x7C, 0x57, 0x35, 0x99, 0x5F,
			0x0C, 0x96, 0x44, 0x8E, 0xB8, 0xCA, 0xAD, 0x74, 0xB6, 0xA4, 0x6A, 0x4E, 0x71, 0x75, 0x04, 0x2C,
			0x98, 0x34, 0xC0, 0xF9, 0x7F, 0x92, 0x8E, 0x69, 0x17, 0x76, 0xF5, 0x25, 0x98, 0x51, 0xAC, 0x58,
			0x0D, 0x14, 0x2A, 0x48, 0x6D, 0x72, 0x35, 0x00, 0x2E, 0x16, 0x38, 0xB2, 0x97, 0x85, 0xED, 0x8A,
			0xFD, 0x89, 0xC3, 0x0E, 0x2E, 0xEE, 0x79, 0x3E, 0x32, 0xB0, 0x3F, 0x25, 0x04, 0x06, 0xBD, 0x00,
			0x99, 0x73, 0xB6, 0x34, 0xDC, 0x0F, 0x51, 0x4B, 0x2A, 0x46, 0x3A, 0x5D, 0x18, 0x09, 0xD2, 0x9A,
			0xF0, 0xD2, 0x44, 0x11, 0x22, 0x64, 0xAD, 0xD3, 0x79, 0x49, 0xCF, 0xCB, 0xAD, 0x54, 0x9E, 0x27,
			0x79, 0x41, 0x35, 0xF5, 0x8B, 0x77, 0x84, 0x8A, 0x9E, 0xDB, 0xFE, 0x5C, 0x85, 0x6C, 0xA1, 0x49,
			0xA1, 0x0D, 0x3C, 0xFA, 0xA0, 0xE3, 0xA1, 0xB0, 0xDA, 0x00, 0x79, 0xC0, 0xED, 0x64, 0x7F, 0xCA,
			0xF9, 0x45, 0x35, 0x25, 0xB2, 0xA5, 0x31, 0x12, 0x91, 0x8C, 0x47, 0xA2, 0x71, 0x6F, 0xE2, 0x7F,
			0x2E, 0x93, 0x0F, 0x57, 0x6A, 0xCB, 0xE0, 0xE4, 0x9A, 0xBD, 0x4F, 0xBC, 0xD5, 0x35, 0x7B, 0x79,
			0xBA, 0xD1, 0x92, 0x10, 0xC3, 0x82, 0xA7, 0x0C, 0x69, 0x76, 0x73, 0xB6, 0x36, 0x3A, 0x49, 0x43,
			0xCC, 0x22, 0x6D, 0xB5,
		// SINGATURE
		0x5E, 0x10, 0x80, 0x8C, 0xDB, 0x87, 0xEC, 0x15, 0xCA, 0x90, 0x34, 0xBA, 0x2B, 0x54, 0x13, 0x51, 0xB9, 0xAF
	};
	
	uint8_t exported_cert[1024] = {0U};
	size_t exported_cert_length = sizeof(exported_cert);
	
	psa_status = psa_crypto_init();
	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_crypto_init");

	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_attributes_t public_key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t id = 0U;
	psa_key_id_t public_key_id = 0U;
	
	/* Set key attributes */
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&attributes, PSA_ALG_NONE);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_RAW_DATA);
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_PERSISTENT, PSA_KEY_LOCATION_VENDOR_FLAG | 0x00U));
	psa_set_key_bits(&attributes, 2744);
    psa_set_key_id(&attributes, 0x00004101);
	  
	/* Import the key */
	psa_status = psa_import_key(&attributes, cert_blob, sizeof(cert_blob), &id);
	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_import_key");

	/* Import the key */
	psa_status = psa_export_key(id, exported_cert, sizeof(exported_cert), &exported_cert_length);
	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_export_key");

	PSA_ASSERT_OR_EXIT_STATUS_MSG(exported_cert_length != 0x160,
								  PSA_ERROR_GENERIC_ERROR,
								  "Error in exported object length");
	PSA_ASSERT_OR_EXIT_STATUS_MSG(memcmp(exported_cert, (cert_blob + 186), exported_cert_length) != 0,
								  PSA_ERROR_GENERIC_ERROR,
								  "Error in exported object comparison");

	return true;
exit:
	/* Free the attributes */
	psa_reset_key_attributes(&attributes);

	/* Destroy the key */
	psa_status = psa_destroy_key(id);
	PSA_SUCCESS_OR_EXIT_MSG("Error in psa_destroy_key");
	return false;
}


/**
 *Name: test_psa_import_key_nist_p384 (external key)
 *Description: This test simulates iot agent import/load key functionality.
 * The goal of the test is to import/load a key in CSS memory (PKC) over Oracle functionality
 * and use it with public PSA sign/verify functions.
 *Steps:
 *- Derive decryption key using CSS low level driver on CSS slot
 *- Call psa_import_key and provide el2go blob (will be stored in TFM)
 *- Oracle will validate PSA attributes and store the key in TFM
 *- Use psa public sign/verify functions, which will first decrypt a key (oracle)
 *- and use with CL functions.
*/

/**
 *Name: test_psa_import_key_rsa_2048 (external key)
 *Description: This test simulates iot agent import/load key functionality.
 * The goal of the test is to import a key in CLNS memory over Oracle functionality
 * and use it with public PSA sign/verify functions.
 *Steps:
 *- Derive decryption key using CSS low level driver on CSS slot
 *- Call psa_import_key and provide el2go blob (will be stored in TFM)
 *- Oracle will validate PSA attributes and store the key in TFM
 *- Use psa public sign/verify functions, which will first decrypt a key (oracle)
 *- and use with CL functions.
*/

/**
 *Name: test_create_claim_code_blob
 *Description: This test simulates iot agent creation of the claim code blob functionality.
 * The goal of the test is to create claim code blob and encrypt/sign the code payload.
 * Spec. https://confluence.sw.nxp.com/display/IOTHUB/Claiming
 *Steps TBD.:
 *
*/

const mbedtls_psa_el2go_test_t mbedtls_psa_el2go_test[] =
{
 	//{"test_css_load_iot_blob_on_slot", css_load_iot_rfc3394_blob_on_slot},
    //{"test_css_wrap_unwrap_rfc3394_key_sign_vry", css_wrap_unwrap_rfc3394_key_sign_vry},
  	//{"test_psa_import_key_plain", test_psa_import_key_plain},
  	{"test_psa_import_key_blob_internal", test_psa_import_key_blob_internal},
  	{"test_psa_import_certificate_blob_external", test_psa_import_certificate_blob_external},
	{"test_derived_key_for_tls_connection", test_derived_key_for_tls_connection},
    {NULL, NULL}
};


int main()
{
    const mbedtls_psa_el2go_test_t *test;
    psa_status_t status;
	bool css_result = false;
  
    BOARD_InitHardware();
    status = CRYPTO_InitHardware();
    ASSERT_STATUS(status, PSA_SUCCESS);

	css_result = css_enable();
	ASSERT_STATUS(css_result, true);

    PRINTF("\r\nStart of for PSA tests for EL2GO use case.\r\n\r\n");

	size_t fail_num = 0U;
    for (test = mbedtls_psa_el2go_test; test->name != NULL; test++)
    {
        PRINTF("%s", test->name);
        if (test->function() == true)
        {
			PRINTF("=>PASS\r\n", test->name);
        }
		else
        {
			fail_num ++;
			PRINTF("FAIL\r\n", test->name);
        }
    }

	if (fail_num != 0)
	{
	  PRINTF("\r\n[%d test FAIL]\r\n");
	}
	else
	{
	  PRINTF("\r\n[All test PASS]\r\n");
	}

exit:
  	return 1;
	
}

