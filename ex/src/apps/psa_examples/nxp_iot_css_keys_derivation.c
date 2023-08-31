/*
 * Copyright 2021-2022 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/**
 * @file  nxpClKey_example.c
 * @brief Example for the nxpClKey component
 *
 * @example nxpClKey_example.c
 * @brief   Example for the nxpClKey component
 */

#include <mcuxClKey.h>
#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h> // Code flow protection
#include <stdbool.h>               // bool type for the example's return code
#include "fsl_debug_console.h"
#include <RW610.h>

#include <nxp_iot_css_keys_derivation.h>

#define CSS_SLOT_NUMBER 20u


typedef struct
{
    __O uint32_t HARDENRING_FSM0_CTRL; /**< Hardenring FSM0 Ctrl, offset: 0x0 */
    __O uint32_t HARDENRING_FSM1_CTRL; /**< Hardenring FSM1 Ctrl, offset: 0x4 */
    __O uint32_t HARDENRING_FSM2_CTRL; /**< Hardenring FSM2 Ctrl, offset: 0x8 */
    __O uint32_t HARDENRING_FSM3_CTRL; /**< Hardenring FSM3 Ctrl, offset: 0xC */
    uint8_t RESERVED_0[24];
    __O uint32_t HARDENRING_FSM10_CTRL; /**< Hardenring FSM10 Ctrl, offset: 0x28 */
    __O uint32_t HARDENRING_FSM11_CTRL; /**< Hardenring FSM11 Ctrl, offset: 0x2C */
    __O uint32_t HARDENRING_FSM12_CTRL; /**< Hardenring FSM12 Ctrl, offset: 0x30 */
    __O uint32_t HARDENRING_FSM13_CTRL; /**< Hardenring FSM13 Ctrl, offset: 0x34 */
    uint8_t RESERVED_1[456];
    __IO uint32_t I_CUSTOM_31_0;       /**< CSS sideband ctrl - i_custom[31:0], offset: 0x200 */
    __IO uint32_t I_CUSTOM_63_32;      /**< CSS sideband ctrl - i_custom[63:32], offset: 0x204 */
    __IO uint32_t I_CUSTOM_95_64;      /**< CSS sideband ctrl - i_custom[95:64], offset: 0x208 */
    __IO uint32_t I_CUSTOM_127_96;     /**< CSS sideband ctrl - i_custom[127:96], offset: 0x20C */
    __IO uint32_t I_HW_DRV_DATA_31_0;  /**< CSS sideband ctrl - i_hw_drv_data[31:0], offset: 0x210 */
    __IO uint32_t I_HW_DRV_DATA_63_32; /**< CSS sideband ctrl - i_hw_drv_data[63:32], offset: 0x214 */
    uint8_t RESERVED_2[104];
    __IO uint32_t I_CSS_FEATURE0_31_0;     /**< CSS sideband ctrl - i_css_feature0[31:0], offset: 0x280 */
    __O uint32_t I_CSS_HW_EEM_EN_31_0;     /**< CSS sideband ctrl - i_css_hw_eem_en[31:0], offset: 0x284 */
    __IO uint32_t PUF_CONFIG;              /**< PUF sideband ctrl, offset: 0x288 */
    __IO uint32_t I_CSS_FEATURE0_DP_31_0;  /**< CSS sideband ctrl - i_css_feature0_dp[31:0] (Default Enable
                                              i_css_cmd_ena[31:0]), offset: 0x28C */
    __IO uint32_t I_CSS_FEATURE0_63_32;    /**< CSS sideband ctrl - i_css_feature0[63:32], offset: 0x290 */
    __IO uint32_t I_CSS_FEATURE0_DP_63_32; /**< CSS sideband ctrl - i_css_feature0_dp[63:32], offset: 0x294 */
    uint8_t RESERVED_3[360];
    __IO uint32_t WO_SCRATCH_REG0; /**< Write once scratch register 0, offset: 0x400 */
    __IO uint32_t WO_SCRATCH_REG1; /**< Write once scratch register 1, offset: 0x404 */
    __IO uint32_t WO_SCRATCH_REG2; /**< Write once scratch register 2, offset: 0x408 */
    __IO uint32_t WO_SCRATCH_REG3; /**< Write once scratch register 3, offset: 0x40C */
    __IO uint32_t WO_SCRATCH_REG4; /**< Write once scratch register 4, offset: 0x410 */
    __IO uint32_t WO_SCRATCH_REG5; /**< Write once scratch register 5, offset: 0x414 */
    __IO uint32_t WO_SCRATCH_REG6; /**< Write once scratch register 6, offset: 0x418 */
    __IO uint32_t WO_SCRATCH_REG7; /**< Write once scratch register 7, offset: 0x41C */
    uint8_t RESERVED_4[96];
    __IO uint32_t RW_SCRATCH_REG0; /**< Scratch register 0, offset: 0x480 */
    __IO uint32_t RW_SCRATCH_REG1; /**< Scratch register 1, offset: 0x484 */
    __IO uint32_t RW_SCRATCH_REG2; /**< Scratch register 2, offset: 0x488 */
    __IO uint32_t RW_SCRATCH_REG3; /**< Scratch register 3, offset: 0x48C */
    __IO uint32_t RW_SCRATCH_REG4; /**< Scratch register 4, offset: 0x490 */
    __IO uint32_t RW_SCRATCH_REG5; /**< Scratch register 5, offset: 0x494 */
    __IO uint32_t RW_SCRATCH_REG6; /**< Scratch register 6, offset: 0x498 */
    __IO uint32_t RW_SCRATCH_REG7; /**< Scratch register 7, offset: 0x49C */
    uint8_t RESERVED_5[32];
    __IO uint32_t PKC_RAM_SUBSYSTEM_CTRL; /**< PKC ram subsystem ctrl, offset: 0x4C0 */
    __I uint32_t CSS_STATUS;              /**< CSS status, offset: 0x4C4 */
    __IO uint32_t VTOR_CTRL;              /**< VTOR CTRL, offset: 0x4C8 */
    __IO uint32_t TESTBUS_CTRL;           /**< TESTBUS CTRL, offset: 0x4CC */
} RF_SYSCON_Type;

/* RF_SYSCON - Peripheral instance base addresses */
#if (defined(__ARM_FEATURE_CMSE) && (__ARM_FEATURE_CMSE & 0x2))
/** Peripheral RF_SYSCON base address */
#define RF_SYSCON_BASE (0x5003B000u)
/** Peripheral RF_SYSCON base address */
#define RF_SYSCON_BASE_NS (0x4003B000u)
/** Peripheral RF_SYSCON base pointer */
#define RF_SYSCON ((RF_SYSCON_Type *)RF_SYSCON_BASE)
/** Peripheral RF_SYSCON base pointer */
#define RF_SYSCON_NS ((RF_SYSCON_Type *)RF_SYSCON_BASE_NS)
/** Array initializer of RF_SYSCON peripheral base addresses */
#define RF_SYSCON_BASE_ADDRS \
    {                        \
        RF_SYSCON_BASE       \
    }
/** Array initializer of RF_SYSCON peripheral base pointers */
#define RF_SYSCON_BASE_PTRS \
    {                       \
        RF_SYSCON           \
    }
/** Array initializer of RF_SYSCON peripheral base addresses */
#define RF_SYSCON_BASE_ADDRS_NS \
    {                           \
        RF_SYSCON_BASE_NS       \
    }
/** Array initializer of RF_SYSCON peripheral base pointers */
#define RF_SYSCON_BASE_PTRS_NS \
    {                          \
        RF_SYSCON_NS           \
    }
#else
/** Peripheral RF_SYSCON base address */
#define RF_SYSCON_BASE (0x4003B000u)
/** Peripheral RF_SYSCON base pointer */
#define RF_SYSCON      ((RF_SYSCON_Type *)RF_SYSCON_BASE)
/** Array initializer of RF_SYSCON peripheral base addresses */
#define RF_SYSCON_BASE_ADDRS \
    {                        \
        RF_SYSCON_BASE       \
    }
/** Array initializer of RF_SYSCON peripheral base pointers */
#define RF_SYSCON_BASE_PTRS \
    {                       \
        RF_SYSCON           \
    }
#endif

/** Finds a free slot. */
void printSlotsInfo() {
  
  mcuxClCss_KeyIndex_t             keyIdx = 0u;
  mcuxClCss_KeyProp_t              key_properties;
  
     /* Get free CSS key slot */
    for(keyIdx = 0; keyIdx < CSS_SLOT_NUMBER; keyIdx++){
        /* Get CSS keystore slot properties */
    mcuxClCss_GetKeyProperties(keyIdx, &key_properties);

        if(key_properties.bits.kactv == 0
            && keyIdx != 2 && keyIdx != 3) { // slot 2 can not be taken (FHWO props bit set), removing slot 3 also
              PRINTF("\r\nAvaiable slot found, slot: %d", keyIdx);
            } else {
              PRINTF("\r\nSlot in use, slot: %d", keyIdx);
            }
    };
}

/** Finds a free slot.
 * @retval keyIdx  keySlotIndex */
mcuxClCss_KeyIndex_t getFreeSlotIndex() {
  
  mcuxClCss_KeyIndex_t keyIdx;
  mcuxClCss_KeyProp_t              key_properties;
  
     /* Get free CSS key slot */
    for(keyIdx = 0; keyIdx < CSS_SLOT_NUMBER; keyIdx++){
        /* Get CSS keystore slot properties */
    mcuxClCss_GetKeyProperties(keyIdx, &key_properties);

        if(key_properties.bits.kactv == 0 
           && keyIdx != 2 && keyIdx != 3) { // slot 2/3 can not be taken (FHWO props bit set)
           //PRINTF("Found free key slot %d\r\n", keyIdx);
           break;
        }
    };
    return keyIdx;
}

bool delete_derived_keys()
{
    bool result;
  
    mcuxClCss_KeyIndex_t die_ext_idx = DIE_EXT_IDX;
    mcuxClCss_KeyIndex_t el2gopublic_mk_sk_idx = EL2GOPUBLIC_MK_SK_IDX; 
    mcuxClCss_KeyIndex_t el2goconn_seed_idx = EL2GOCONN_SEED_IDX; 
    mcuxClCss_KeyIndex_t el2goconn_pk_idx = EL2GOCONN_PK_IDX; 
    mcuxClCss_KeyIndex_t el2gosym_mk_sk_idx = EL2GOSYM_MK_SK_IDX;
    mcuxClCss_KeyIndex_t el2gooem_mk_sk_idx = EL2GOOEM_MK_SK_IDX;
    mcuxClCss_KeyIndex_t el2goimport_kek_sk_idx = EL2GOIMPORT_KEK_SK_IDX;
    mcuxClCss_KeyIndex_t el2goimport_auth_sk_idx = EL2GOIMPORT_AUTH_SK_IDX;
    mcuxClCss_KeyIndex_t el2goimporttfm_kek_sk_idx = EL2GOIMPORTTFM_KEK_SK_IDX;

    mcuxClCss_KeyIndex_t key_indices[] = {
        die_ext_idx,
        el2gopublic_mk_sk_idx,
        el2goconn_seed_idx,
        el2goconn_pk_idx,
        el2gosym_mk_sk_idx,
        el2gooem_mk_sk_idx,
        el2goimport_kek_sk_idx,
        el2goimport_auth_sk_idx,
        el2goimporttfm_kek_sk_idx
    };
    
    for (int i=0; i < ARRAY_SIZE(key_indices); i++) {
      mcuxClCss_KeyIndex_t idx = key_indices[i];
      
      /* Delete keys */
      mcuxClCss_Status_t del_result = mcuxClCss_KeyDelete_Async(idx);
      if (MCUXCLCSS_STATUS_OK_WAIT != del_result)
      {
        PRINTF("mcuxClCss_KeyDelete_Async failed: 0x%08x", del_result);
        return false;
      }
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_LimitedWaitForOperation(0x00100000U, MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_KeyDelete_Async operation to complete.
      // mcuxClCss_LimitedWaitForOperation is a flow-protected function: Check the protection token and the return value
      if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_LimitedWaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
      {
        PRINTF("mcuxClCss_KeyDelete_Async mcuxClCss_LimitedWaitForOperation failed: 0x%08x", result);
        return false;
      }
      MCUX_CSSL_FP_FUNCTION_CALL_END();
    }
    
    return true;
}

static void nboot_set_icustom(const uint8_t *data)
{
    const uint32_t* tmp = (uint32_t*) data;
    // Do not set temporal state, skip first 32-bits
    tmp++;
    RF_SYSCON->I_CUSTOM_63_32 = *tmp++;
    RF_SYSCON->I_CUSTOM_95_64 = *tmp++;
    RF_SYSCON->I_CUSTOM_127_96 = *tmp++;
}

/** Performs of KeyProv for loading test wrap key
* @retval true  The example code completed successfully
* @retval false The example code failed */
bool keyProv_wrap_key_test(mcuxClCss_KeyIndex_t key_idx) {
  
  // this is CSS input 1 (fixed length of 256 bits)
  uint8_t share_1[256/8] = { 0x4e, 0x53, 0x27, 0x90, 0x94, 0xbe, 0x56, 0xa8, 0x27, 0x67, 0x53, 0x40, 0xac, 0x51, 0xa4, 0xbc, 0x39, 0xb5, 0x41, 0xa5, 0x22, 0x6e, 0xe3, 0x83, 0x43, 0xbd, 0x99, 0xa4, 0x4a, 0x7e, 0x61, 0xdf, };
  // this is CSS input 0 (variable length)
  uint8_t share_2[2 * 256/8] = { 0xcb, 0x30, 0xfa, 0x0c, 0x17, 0x35, 0x5d, 0x8a, 0x3a, 0xcc, 0x82, 0x4f, 0xd1, 0x3b, 0xe4, 0xe9, 0x99, 0xb7, 0xc8, 0x48, 0x3f, 0x44, 0x86, 0x73, 0x6e, 0xfa, 0xad, 0x26, 0xfd, 0xcd, 0x72, 0x7d, 
  0xf3, 0x91, 0x6b, 0xa7, 0x93, 0xb4, 0xe5, 0x22, 0x91, 0xa3, 0xdd, 0x7f, 0x65, 0xd8, 0x6a, 0xcc, 0xec, 0xfc, 0x92, 0x56, 0x7c, 0x5d, 0xc0, 0x05, 0xd4, 0x69, 0x4d, 0x82, 0x78, 0xf8, 0x85, 0x07, };
  uint8_t i_custom[] = { 0x00, 0x00, 0x00, 0x00, 0x67, 0xd3, 0x7d, 0xdf, 0x8e, 0xd0, 0x5d, 0x66, 0x68, 0x40, 0x99, 0x23, };
  
  // Set icustom
  nboot_set_icustom(i_custom);
  
  mcuxClCss_KeyProp_t key_properties = {0};
  key_properties.word.value = 0u;
  key_properties.bits.upprot_priv = MCUXCLCSS_KEYPROPERTY_PRIVILEGED_TRUE;
  //key_properties.bits.upprot_sec = MCUXCLCSS_KEYPROPERTY_SECURE_FALSE;
  key_properties.bits.ukwk        = MCUXCLCSS_KEYPROPERTY_KWK_TRUE;
  key_properties.bits.ksize = MCUXCLCSS_KEYPROPERTY_KEY_SIZE_256;
    key_properties.bits.kactv = MCUXCLCSS_KEYPROPERTY_ACTIVE_TRUE;
  //key_properties.bits.ksize = MCUXCLCSS_KEYPROPERTY_KEY_SIZE_256;
  //key_properties.bits.kactv = MCUXCLCSS_KEYPROPERTY_ACTIVE_TRUE;
  //die_ext_prop.bits.upprot_sec  = MCUXCLCSS_KEYPROPERTY_SECURE_FALSE;
  //die_ext_prop.bits.uckdf       = MCUXCLCSS_KEYPROPERTY_CKDF_TRUE;
  //die_ext_prop.bits.duk         = MCUXCLCSS_KEYPROPERTY_DEVICE_UNIQUE_TRUE;
  
  mcuxClCss_KeyProvisionOption_t options = {0};
  //options.bits.noic = 0;
  
  PRINTF("wrap_prop: 0x%08x\r\n", key_properties.word.value);
  PRINTF("wrap_options: 0x%08x\r\n", options.word.value);
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_KeyProvision_Async(
                                                                             options,
                                                                             share_1,
                                                                             share_2,
                                                                             sizeof(share_2),
                                                                             key_idx,
                                                                             key_properties));
  if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_KeyProvision_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result)) {
    PRINTF("Css_KeyProvision_Async failed: 0x%08x", result);
    return false; 
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result)) {
    PRINTF("Css_WaitForOperation failed: 0x%08x", result);
    return false;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  return true;
}

/** Performs of KeyProv.
* @retval true  The example code completed successfully
* @retval false The example code failed */
bool keyProv(mcuxClCss_KeyIndex_t key_idx) {
  
  // this is CSS input 1 (fixed length of 256 bits)
  uint8_t share_1[256/8] = { 0x4e, 0x53, 0x27, 0x90, 0x94, 0xbe, 0x56, 0xa8, 0x27, 0x67, 0x53, 0x40, 0xac, 0x51, 0xa4, 0xbc, 0x39, 0xb5, 0x41, 0xa5, 0x22, 0x6e, 0xe3, 0x83, 0x43, 0xbd, 0x99, 0xa4, 0x4a, 0x7e, 0x61, 0xdf, };
  // this is CSS input 0 (variable length)
  uint8_t share_2[2 * 256/8] = { 0xcb, 0x30, 0xfa, 0x0c, 0x17, 0x35, 0x5d, 0x8a, 0x3a, 0xcc, 0x82, 0x4f, 0xd1, 0x3b, 0xe4, 0xe9, 0x99, 0xb7, 0xc8, 0x48, 0x3f, 0x44, 0x86, 0x73, 0x6e, 0xfa, 0xad, 0x26, 0xfd, 0xcd, 0x72, 0x7d, 
  0xf3, 0x91, 0x6b, 0xa7, 0x93, 0xb4, 0xe5, 0x22, 0x91, 0xa3, 0xdd, 0x7f, 0x65, 0xd8, 0x6a, 0xcc, 0xec, 0xfc, 0x92, 0x56, 0x7c, 0x5d, 0xc0, 0x05, 0xd4, 0x69, 0x4d, 0x82, 0x78, 0xf8, 0x85, 0x07, };
  uint8_t i_custom[] = { 0x00, 0x00, 0x00, 0x00, 0x67, 0xd3, 0x7d, 0xdf, 0x8e, 0xd0, 0x5d, 0x66, 0x68, 0x40, 0x99, 0x23, };
  
  // Set icustom
  nboot_set_icustom(i_custom);
  
  mcuxClCss_KeyProp_t die_ext_prop = {0};                           
  
  die_ext_prop.bits.upprot_priv = MCUXCLCSS_KEYPROPERTY_PRIVILEGED_FALSE; 
  die_ext_prop.bits.upprot_sec  = MCUXCLCSS_KEYPROPERTY_SECURE_FALSE;
  die_ext_prop.bits.uckdf       = MCUXCLCSS_KEYPROPERTY_CKDF_TRUE;
  die_ext_prop.bits.duk         = MCUXCLCSS_KEYPROPERTY_DEVICE_UNIQUE_TRUE;
  
  mcuxClCss_KeyProvisionOption_t die_ext_options = {0};
  die_ext_options.bits.noic = 0;
  
  PRINTF("die_ext_prop: 0x%08x\r\n", die_ext_prop.word.value);
  PRINTF("die_ext_options: 0x%08x\r\n", die_ext_options.word.value);
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_KeyProvision_Async(
                                                                             die_ext_options,
                                                                             share_1,
                                                                             share_2,
                                                                             sizeof(share_2),
                                                                             key_idx,
                                                                             die_ext_prop));
  if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_KeyProvision_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result)) {
    PRINTF("Css_KeyProvision_Async failed: 0x%08x", result);
    return false; 
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result)) {
    PRINTF("Css_WaitForOperation failed: 0x%08x", result);
    return false;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  return true;
}

/** Performs a CKDF.
* @retval true  The example code completed successfully
* @retval false The example code failed */
bool cKDF(mcuxClCss_KeyIndex_t dd_key_idx, mcuxClCss_KeyIndex_t target_key_idx, mcuxClCss_KeyProp_t targetKeyProperties, uint8_t const *pDerivationData) {
 
  
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_Ckdf_Sp800108_Async(
                                                                              dd_key_idx,
                                                                              target_key_idx,
                                                                              targetKeyProperties,
                                                                              pDerivationData));
  
  if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Ckdf_Sp800108_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result)) {
    PRINTF("Css_Ckdf_Sp800108_Async failed: 0x%08x", result);
    return false; 
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result)) {
    PRINTF("Css_WaitForOperation failed: 0x%08x", result);
    return false;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  return true;
}

/** Performs a deterministic KeyGen.
* @retval true  The example code completed successfully
* @retval false The example code failed */
bool keyGen_deterministic(mcuxClCss_EccKeyGenOption_t options, mcuxClCss_KeyIndex_t seedKeyIdx, mcuxClCss_KeyProp_t generatedKeyProperties, uint8_t *pPublicKey) {
  
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_EccKeyGen_Async( 
                                                                          options,
                                                                          0,
                                                                          seedKeyIdx, // Seed
                                                                          generatedKeyProperties,
                                                                          NULL,
                                                                          pPublicKey));
  
  if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_EccKeyGen_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result)) {
    PRINTF("Css_EccKeyGen_Async failed: 0x%08x", result);
    return false; 
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result)) {
    PRINTF("Css_WaitForOperation failed: 0x%08x", result);
    return false;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
  return true;
}

bool execute_el2go_key_derivation_example()
{
  bool result;
  
   mcuxClCss_KeyIndex_t die_ext_idx = DIE_EXT_IDX;
    mcuxClCss_KeyIndex_t el2gopublic_mk_sk_idx = EL2GOPUBLIC_MK_SK_IDX; 
    mcuxClCss_KeyIndex_t el2goconn_seed_idx = EL2GOCONN_SEED_IDX; 
    mcuxClCss_KeyIndex_t el2goconn_pk_idx = EL2GOCONN_PK_IDX; 
    mcuxClCss_KeyIndex_t el2gosym_mk_sk_idx = EL2GOSYM_MK_SK_IDX;
    mcuxClCss_KeyIndex_t el2gooem_mk_sk_idx = EL2GOOEM_MK_SK_IDX;
    mcuxClCss_KeyIndex_t el2goimport_kek_sk_idx = EL2GOIMPORT_KEK_SK_IDX;
    mcuxClCss_KeyIndex_t el2goimport_auth_sk_idx = EL2GOIMPORT_AUTH_SK_IDX;
    mcuxClCss_KeyIndex_t el2goimporttfm_kek_sk_idx = EL2GOIMPORTTFM_KEK_SK_IDX;

    mcuxClCss_KeyIndex_t key_indices[] = {
        die_ext_idx,
        el2gopublic_mk_sk_idx,
        el2goconn_seed_idx,
        el2goconn_pk_idx,
        el2gosym_mk_sk_idx,
        el2gooem_mk_sk_idx,
        el2goimport_kek_sk_idx,
        el2goimport_auth_sk_idx,
        el2goimporttfm_kek_sk_idx
    };
  
  /*
  KeyProv (DUK = 1)
  */
  result = keyProv(die_ext_idx);
  if (result != true) {
    return false;
  }
  
  /*
  CKDF -> NXP_DIE_EL2GOPUBLIC_MK_SK 
  */
  mcuxClCss_KeyProp_t el2gopublic_mk_sk_prop = {0};                           
  
  uint8_t el2gopublic_mk_sk_dd[12] = { 
    0x00, 'e', '2', 'g', 'p', 'u', 'b', '_', 'm', 'k', 0x00, 0x00,
  };
  
  el2gopublic_mk_sk_prop.bits.upprot_priv = MCUXCLCSS_KEYPROPERTY_PRIVILEGED_FALSE; 
  el2gopublic_mk_sk_prop.bits.upprot_sec  = MCUXCLCSS_KEYPROPERTY_SECURE_FALSE;
  el2gopublic_mk_sk_prop.bits.uckdf       = MCUXCLCSS_KEYPROPERTY_CKDF_TRUE;
  el2gopublic_mk_sk_prop.bits.kactv       = MCUXCLCSS_KEYPROPERTY_ACTIVE_TRUE;
  el2gopublic_mk_sk_prop.bits.ksize       = MCUXCLCSS_KEYPROPERTY_KEY_SIZE_256;
  PRINTF("el2gopublic_mk_sk_prop: 0x%08x\r\n", el2gopublic_mk_sk_prop.word.value);
  PRINTF("el2gopublic_mk_sk_dd: %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x\r\n", 
         el2gopublic_mk_sk_dd[0],
         el2gopublic_mk_sk_dd[1],
         el2gopublic_mk_sk_dd[2],
         el2gopublic_mk_sk_dd[3],
         el2gopublic_mk_sk_dd[4],
         el2gopublic_mk_sk_dd[5],
         el2gopublic_mk_sk_dd[6],
         el2gopublic_mk_sk_dd[7],
         el2gopublic_mk_sk_dd[8],
         el2gopublic_mk_sk_dd[9],
         el2gopublic_mk_sk_dd[10],
         el2gopublic_mk_sk_dd[11]);
  result = cKDF(die_ext_idx,  el2gopublic_mk_sk_idx, el2gopublic_mk_sk_prop, el2gopublic_mk_sk_dd);
  if (result != true) {
    return false;
  }
  
  /*
  CKDF -> NXP_DIE_EL2GOCONN_AUTH_PRK_SEED 
  */
  mcuxClCss_KeyProp_t el2goconn_seed_prop = {0};                           
  
  uint8_t el2goconn_seed_dd[12] = { 
    0x00, 'e', '2', 'g', 'c', 'o', 'n', '_', 's', 'e', 0x00, 0x00,
  };
  
  el2goconn_seed_prop.bits.upprot_priv = MCUXCLCSS_KEYPROPERTY_PRIVILEGED_FALSE; 
  el2goconn_seed_prop.bits.upprot_sec  = MCUXCLCSS_KEYPROPERTY_SECURE_FALSE;
  el2goconn_seed_prop.bits.ukgsrc      = MCUXCLCSS_KEYPROPERTY_INPUT_FOR_ECC_TRUE;
  el2goconn_seed_prop.bits.kactv       = MCUXCLCSS_KEYPROPERTY_ACTIVE_TRUE;
  el2goconn_seed_prop.bits.ksize       = MCUXCLCSS_KEYPROPERTY_KEY_SIZE_256;
  PRINTF("el2goconn_seed_prop: 0x%08x\r\n", el2goconn_seed_prop.word.value);
  PRINTF("el2goconn_seed_dd: %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x\r\n", 
         el2goconn_seed_dd[0],
         el2goconn_seed_dd[1],
         el2goconn_seed_dd[2],
         el2goconn_seed_dd[3],
         el2goconn_seed_dd[4],
         el2goconn_seed_dd[5],
         el2goconn_seed_dd[6],
         el2goconn_seed_dd[7],
         el2goconn_seed_dd[8],
         el2goconn_seed_dd[9],
         el2goconn_seed_dd[10],
         el2goconn_seed_dd[11]);
  
  result = cKDF(el2gopublic_mk_sk_idx,  el2goconn_seed_idx, el2goconn_seed_prop, el2goconn_seed_dd);
  if (result != true) {
    return false;
  }
  
  /*
  KEYGEN -> NXP_DIE_EL2GOCONN_AUTH_PRK 
  */
  mcuxClCss_EccKeyGenOption_t el2goconn_pk_options = {0};
  el2goconn_pk_options.bits.kgsrc = MCUXCLCSS_ECC_OUTPUTKEY_DETERMINISTIC;
  el2goconn_pk_options.bits.kgtypedh = MCUXCLCSS_ECC_OUTPUTKEY_SIGN;
  el2goconn_pk_options.bits.skip_pbk = MCUXCLCSS_ECC_GEN_PUBLIC_KEY;
  
  mcuxClCss_KeyProp_t el2goconn_pk_prop = {0};                           
  
  el2goconn_pk_prop.bits.upprot_priv = MCUXCLCSS_KEYPROPERTY_PRIVILEGED_FALSE; 
  el2goconn_pk_prop.bits.upprot_sec  = MCUXCLCSS_KEYPROPERTY_SECURE_FALSE;
  el2goconn_pk_prop.bits.uecsg       = MCUXCLCSS_KEYPROPERTY_ECC_TRUE;
  el2goconn_pk_prop.bits.ksize       = MCUXCLCSS_KEYPROPERTY_KEY_SIZE_256;
  PRINTF("el2goconn_pk_options: 0x%08x\r\n", el2goconn_pk_options.word.value);
  PRINTF("el2goconn_pk_prop: 0x%08x\r\n", el2goconn_pk_prop.word.value);
  uint8_t el2go_conn_pk_pub[64] = {0};
  
  result = keyGen_deterministic(el2goconn_pk_options, el2goconn_seed_idx, el2goconn_pk_prop, el2go_conn_pk_pub);
  if (result != true) {
    return false;
  }
  
  PRINTF("\r\nel2go_conn_pk_pub key value: \r\n");
  // Print Public Key
  for (int i = 0; i < 64; i++)
  {
    PRINTF("%02X", el2go_conn_pk_pub[i]);
  }
  
  /*
  CKDF -> NXP_DIE_EL2GOSYM_MK_SK 
  */
  mcuxClCss_KeyProp_t el2gosym_mk_sk_prop = {0};                           
  
  uint8_t el2gosym_mk_sk_dd[12] = { 
    0x00, 'e', '2', 'g', 's', 'y', 'm', '_', 'm', 'k', 0x00, 0x00,
  };
  
  el2gosym_mk_sk_prop.bits.upprot_priv = MCUXCLCSS_KEYPROPERTY_PRIVILEGED_FALSE; 
  el2gosym_mk_sk_prop.bits.upprot_sec  = MCUXCLCSS_KEYPROPERTY_SECURE_FALSE;
  el2gosym_mk_sk_prop.bits.uckdf       = MCUXCLCSS_KEYPROPERTY_CKDF_TRUE;
  el2gosym_mk_sk_prop.bits.kactv       = MCUXCLCSS_KEYPROPERTY_ACTIVE_TRUE;
  el2gosym_mk_sk_prop.bits.ksize       = MCUXCLCSS_KEYPROPERTY_KEY_SIZE_256;
  PRINTF("\r\nel2gosym_mk_sk_prop: 0x%08x\r\n", el2gosym_mk_sk_prop.word.value);
  PRINTF("el2gosym_mk_sk_dd: %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x\r\n", 
         el2gosym_mk_sk_dd[0],
         el2gosym_mk_sk_dd[1],
         el2gosym_mk_sk_dd[2],
         el2gosym_mk_sk_dd[3],
         el2gosym_mk_sk_dd[4],
         el2gosym_mk_sk_dd[5],
         el2gosym_mk_sk_dd[6],
         el2gosym_mk_sk_dd[7],
         el2gosym_mk_sk_dd[8],
         el2gosym_mk_sk_dd[9],
         el2gosym_mk_sk_dd[10],
         el2gosym_mk_sk_dd[11]);
  result = cKDF(die_ext_idx,  el2gosym_mk_sk_idx, el2gosym_mk_sk_prop, el2gosym_mk_sk_dd);
  if (result != true) {
    return false;
  }
  
  /*
  CKDF -> NXP_DIE_EL2GOOEM_MK_SK 
  */
  mcuxClCss_KeyProp_t el2gooem_mk_sk_prop = {0};                           
  
  uint8_t el2gooem_mk_sk_dd[12] = { 
    0x00, 'e', '2', 'g', 'o', 'e', 'm', '_', 'm', 'k', 0x00, 0x00,
  };
  
  el2gooem_mk_sk_prop.bits.upprot_priv = MCUXCLCSS_KEYPROPERTY_PRIVILEGED_FALSE; 
  el2gooem_mk_sk_prop.bits.upprot_sec  = MCUXCLCSS_KEYPROPERTY_SECURE_FALSE;
  el2gooem_mk_sk_prop.bits.uckdf       = MCUXCLCSS_KEYPROPERTY_CKDF_TRUE;
  el2gooem_mk_sk_prop.bits.kactv       = MCUXCLCSS_KEYPROPERTY_ACTIVE_TRUE;
  el2gooem_mk_sk_prop.bits.ksize       = MCUXCLCSS_KEYPROPERTY_KEY_SIZE_256;
  PRINTF("\r\nel2gooem_mk_sk_prop: 0x%08x\r\n", el2gooem_mk_sk_prop.word.value);
  PRINTF("el2gooem_mk_sk_dd: %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x\r\n", 
         el2gooem_mk_sk_dd[0],
         el2gooem_mk_sk_dd[1],
         el2gooem_mk_sk_dd[2],
         el2gooem_mk_sk_dd[3],
         el2gooem_mk_sk_dd[4],
         el2gooem_mk_sk_dd[5],
         el2gooem_mk_sk_dd[6],
         el2gooem_mk_sk_dd[7],
         el2gooem_mk_sk_dd[8],
         el2gooem_mk_sk_dd[9],
         el2gooem_mk_sk_dd[10],
         el2gooem_mk_sk_dd[11]);
  result = cKDF(el2gosym_mk_sk_idx,  el2gooem_mk_sk_idx, el2gooem_mk_sk_prop, el2gooem_mk_sk_dd);
  if (result != true) {
    return false;
  }
  
  /*
  CKDF -> NXP_DIE_EL2GOIMPORT_KEK_SK 
  */
  mcuxClCss_KeyProp_t el2goimport_kek_sk_prop = {0};                           
  
  uint8_t el2goimport_kek_sk_dd[12] = { 
    0x00, 'e', '2', 'g', 'i', 'k', 'e', 'k', '_', 's', 'k', 0x00,
  };
  
  el2goimport_kek_sk_prop.bits.upprot_priv = MCUXCLCSS_KEYPROPERTY_PRIVILEGED_FALSE; 
  el2goimport_kek_sk_prop.bits.upprot_sec  = MCUXCLCSS_KEYPROPERTY_SECURE_FALSE;
  el2goimport_kek_sk_prop.bits.kactv       = MCUXCLCSS_KEYPROPERTY_ACTIVE_TRUE;
  el2goimport_kek_sk_prop.bits.ksize       = MCUXCLCSS_KEYPROPERTY_KEY_SIZE_256;
  el2goimport_kek_sk_prop.bits.ukuok       = MCUXCLCSS_KEYPROPERTY_KUOK_TRUE;
  PRINTF("\r\nel2goimport_kek_sk_prop: 0x%08x\r\n", el2goimport_kek_sk_prop.word.value);
  PRINTF("el2goimport_kek_sk_dd: %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x\r\n", 
         el2goimport_kek_sk_dd[0],
         el2goimport_kek_sk_dd[1],
         el2goimport_kek_sk_dd[2],
         el2goimport_kek_sk_dd[3],
         el2goimport_kek_sk_dd[4],
         el2goimport_kek_sk_dd[5],
         el2goimport_kek_sk_dd[6],
         el2goimport_kek_sk_dd[7],
         el2goimport_kek_sk_dd[8],
         el2goimport_kek_sk_dd[9],
         el2goimport_kek_sk_dd[10],
         el2goimport_kek_sk_dd[11]);
  result = cKDF(el2gooem_mk_sk_idx, el2goimport_kek_sk_idx, el2goimport_kek_sk_prop, el2goimport_kek_sk_dd);
  if (result != true) {
    return false;
  }
  
  /*
  CKDF -> NXP_DIE_EL2GOIMPORT_AUTH_SK 
  */
  mcuxClCss_KeyProp_t el2goimport_auth_sk_prop = {0};                           
  
  uint8_t el2goimport_auth_sk_dd[12] = { 
    0x00, 'e', '2', 'g', 'i', 'a', 'u', 't', '_', 's', 'k', 0x00,
  };
  
  el2goimport_auth_sk_prop.bits.upprot_priv = MCUXCLCSS_KEYPROPERTY_PRIVILEGED_FALSE; 
  el2goimport_auth_sk_prop.bits.upprot_sec  = MCUXCLCSS_KEYPROPERTY_SECURE_FALSE;
  el2goimport_auth_sk_prop.bits.kactv       = MCUXCLCSS_KEYPROPERTY_ACTIVE_TRUE;
  el2goimport_auth_sk_prop.bits.ksize       = MCUXCLCSS_KEYPROPERTY_KEY_SIZE_256;
  el2goimport_auth_sk_prop.bits.ucmac       = MCUXCLCSS_KEYPROPERTY_CMAC_TRUE;
  PRINTF("\r\nel2goimport_auth_sk_prop: 0x%08x\r\n", el2goimport_auth_sk_prop.word.value);
  PRINTF("el2goimport_auth_sk_dd: %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x\r\n", 
         el2goimport_auth_sk_dd[0],
         el2goimport_auth_sk_dd[1],
         el2goimport_auth_sk_dd[2],
         el2goimport_auth_sk_dd[3],
         el2goimport_auth_sk_dd[4],
         el2goimport_auth_sk_dd[5],
         el2goimport_auth_sk_dd[6],
         el2goimport_auth_sk_dd[7],
         el2goimport_auth_sk_dd[8],
         el2goimport_auth_sk_dd[9],
         el2goimport_auth_sk_dd[10],
         el2goimport_auth_sk_dd[11]);
  result = cKDF(el2gooem_mk_sk_idx, el2goimport_auth_sk_idx, el2goimport_auth_sk_prop, el2goimport_auth_sk_dd);
  if (result != true) {
    return false;
  }
  
  /*
  CKDF -> NXP_DIE_EL2GOIMPORTTFM_KEK_SK 
  */
  mcuxClCss_KeyProp_t el2goimporttfm_kek_sk_prop = {0};                           
  
  uint8_t el2goimporttfm_kek_sk_dd[12] = { 
    0x00, 'e', '2', 'g', 'i', 't', 'f', 'm', '_', 's', 'k', 0x00,
  };
  
  el2goimporttfm_kek_sk_prop.bits.upprot_priv = MCUXCLCSS_KEYPROPERTY_PRIVILEGED_FALSE; 
  el2goimporttfm_kek_sk_prop.bits.upprot_sec  = MCUXCLCSS_KEYPROPERTY_SECURE_FALSE;
  el2goimporttfm_kek_sk_prop.bits.kactv       = MCUXCLCSS_KEYPROPERTY_ACTIVE_TRUE;
  el2goimporttfm_kek_sk_prop.bits.ksize       = MCUXCLCSS_KEYPROPERTY_KEY_SIZE_256;
  el2goimporttfm_kek_sk_prop.bits.uaes        = MCUXCLCSS_KEYPROPERTY_AES_TRUE;
  PRINTF("\r\nel2goimporttfm_kek_sk_prop: 0x%08x\r\n", el2goimporttfm_kek_sk_prop.word.value);
  PRINTF("el2goimporttfm_kek_sk_dd: %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x\r\n", 
         el2goimporttfm_kek_sk_dd[0],
         el2goimporttfm_kek_sk_dd[1],
         el2goimporttfm_kek_sk_dd[2],
         el2goimporttfm_kek_sk_dd[3],
         el2goimporttfm_kek_sk_dd[4],
         el2goimporttfm_kek_sk_dd[5],
         el2goimporttfm_kek_sk_dd[6],
         el2goimporttfm_kek_sk_dd[7],
         el2goimporttfm_kek_sk_dd[8],
         el2goimporttfm_kek_sk_dd[9],
         el2goimporttfm_kek_sk_dd[10],
         el2goimporttfm_kek_sk_dd[11]);
  result = cKDF(el2gooem_mk_sk_idx, el2goimporttfm_kek_sk_idx, el2goimporttfm_kek_sk_prop, el2goimporttfm_kek_sk_dd);
  if (result != true) {
    return false;
  }
  
  return true;
}