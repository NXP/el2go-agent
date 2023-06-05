/*
 * Copyright 2021 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#define DIE_EXT_IDX 0U // slot 2 can not be used
#define EL2GOPUBLIC_MK_SK_IDX 4U 
#define EL2GOCONN_SEED_IDX 6U 
#define EL2GOCONN_PK_IDX 8U
#define EL2GOSYM_MK_SK_IDX 10U
#define EL2GOOEM_MK_SK_IDX 12U
#define EL2GOIMPORT_KEK_SK_IDX 14U
#define EL2GOIMPORT_AUTH_SK_IDX 16U
#define EL2GOIMPORTTFM_KEK_SK_IDX 18U

bool execute_el2go_key_derivation_example();
mcuxClCss_KeyIndex_t getFreeSlotIndex();
void printSlotsInfo();
bool keyProv_wrap_key_test(mcuxClCss_KeyIndex_t key_idx);
bool delete_derived_keys();