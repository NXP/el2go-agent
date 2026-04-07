/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "el2go_csr.h"

extern uint8_t el2go_csr_conf_data[];

/*! @brief Verify received x.509 certificate from CLI.
 * 
 * This function is  used to verify an x.509 certificate received from SPSDK/CLI with the 
 * PSA key id parsed from the configuration block. The x.509 is read from the ctx (=context)
 * provided memory address.
 * 
 * @param[in] ctx: Structure with filled x.509 cert storage configuration data.
 * @retval PSA_SUCCESS Upon success.
 */
static psa_status_t verify_recv_x509_cert(cert_storage_context_t* ctx)
{
    psa_status_t psa_status = PSA_SUCCESS;
    psa_key_id_t key_id =  (psa_key_id_t)ctx->key_id;
    uint8_t* cert_input_buf_imm = NULL;
    uint32_t cert_size = ctx->cert_source_addr_size;

    if (cert_size > MAX_X509_CERT_SIZE)
    {
        LOG(LOG_ERROR, "x.509 certificate size exceeds maximum allowed size!\r\n");
        psa_status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    cert_input_buf_imm = (uint8_t*)malloc(cert_size);
    if (!cert_input_buf_imm)
    {
        LOG(LOG_ERROR, "Memory allocation for x.509 certificate verification failed!\r\n");
        psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto exit;
    }

    if (mem_read(ctx->cert_source_addr, cert_input_buf_imm, cert_size) != kStatus_CSR_MEM_SUCCESS)
    {
        LOG(LOG_ERROR, "Reading x.509 certificate from memory failed!\r\n");
        psa_status = PSA_ERROR_STORAGE_FAILURE;
        goto exit;
    }
    LOG(LOG_DEBUG, "x.509 certificate has been read successfully from memory! Verifying keypair...\r\n");

    psa_status = verify_certificate(key_id, cert_input_buf_imm, cert_size);
    if (psa_status != PSA_SUCCESS)
    {
        LOG(LOG_ERROR, "Certificate verification failed!\r\n");
        psa_status = PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }

    exit:
        LOG(LOG_TRACE, "Returning to main function from verify_recv_x509_cert subroutine.\r\n");
        memset(cert_input_buf_imm, 0, sizeof(cert_size));
        free(cert_input_buf_imm);
        return psa_status;
}

/*! @brief Generate a certificate signing request (CSR).
 * 
 * This function is  used to generate a CSR using a PSA key id parsed from the configuration block,
 * and store the generated CSR to a specified memory location. The key id is extracted from the
 * configuration block and used to generate the CSR which is then written to the designated output address.
 * 
 * @param[in] ctx: Structure with filled x.509 cert storage configuration data.
 * @retval PSA_SUCCESS Upon success.
 */
static psa_status_t generate_cert_sign_req(csr_gen_context_t* ctx)
{
    psa_status_t psa_status = PSA_SUCCESS;
    psa_key_id_t key_id = (psa_key_id_t)ctx->key_id;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t csr_output_buf_imm[MAX_CSR_SIZE] = {0};
    size_t csr_output_len = 0U; 

    psa_status = fill_key_attributes(&key_attr, &key_id);
    if (psa_status != PSA_SUCCESS)
    {
        LOG(LOG_ERROR, "PSA Key Attribute initialization failed!\r\n");
        goto exit;
    }

    psa_status = generate_csr(key_id, csr_output_buf_imm, sizeof(csr_output_buf_imm), &csr_output_len);
    if (psa_status != PSA_SUCCESS)
    {
        LOG(LOG_ERROR, "CSR generation failed!\r\n");
        goto exit;
    }
    LOG(LOG_DEBUG, "CSR has been generated! Writing to memory now...\r\n");

    if (mem_write(ctx->destination_addr, csr_output_buf_imm, csr_output_len) != kStatus_CSR_MEM_SUCCESS)
    {
        LOG(LOG_ERROR, "Writing generated CSR to memory failed!\r\n");
        psa_status = PSA_ERROR_STORAGE_FAILURE;
        goto exit;
    }
    
    exit:
        LOG(LOG_TRACE, "Returning to main function from generate_cert_sign_req subroutine.\r\n");
        return psa_status;
}

int main(void)
{
    uint32_t spsdk_status = SPSDK_STATUS_CODE_SUCCESS;    
    csr_gen_context_t csr_gen_ctx = CSR_GEN_CONTEXT_INIT;
    cert_storage_context_t cert_storage_ctx = CERT_STORAGE_CONTEXT_INIT;
    bool is_csr_gen_enabled = false;

    platform_init();
    LOG(LOG_INFO, "########### EdgeLock2GO Certificate Signing Request Application ###########\r\n");

    psa_status_t psa_status = psa_crypto_init();
    if(psa_status != PSA_SUCCESS)
    {
        LOG(LOG_ERROR, "Initialization of crypto HW failed!\r\n");
        spsdk_status = (uint32_t)psa_status;
        goto exit; 
    }

    csr_parser_status_t tlv_status = parse_buf_and_fill_context(&csr_gen_ctx, &cert_storage_ctx, el2go_csr_conf_data);
    if (tlv_status != kStatus_CSR_SUCCESS) 
    {
        LOG(LOG_ERROR, "Failed to parse configuration block data!\r\n");
        spsdk_status = (uint32_t)tlv_status;
        goto exit;
    }

    is_csr_gen_enabled = csr_gen_ctx.magic ? true : false;
    size_t data_verify_size = is_csr_gen_enabled ? CSR_GEN_TOTAL_FIXED_FIELDS_LEN : CERT_STORAGE_TOTAL_FIXED_FIELDS_LEN;
    const uint8_t* expected_crc =  is_csr_gen_enabled ? csr_gen_ctx.integrity_value : cert_storage_ctx.integrity_value;

    csr_integrity_verifier_t integrity_status = crc32_verify(el2go_csr_conf_data, data_verify_size, expected_crc);
    if (integrity_status != kStatus_CSR_INT_VERIFY_SUCCESS)
    {
        LOG(LOG_ERROR, "Configuration data integrity verification failed!\r\n");
        spsdk_status = (uint32_t)integrity_status;
        goto exit;
    }  

    if (is_csr_gen_enabled)
    {
        psa_status = generate_cert_sign_req(&csr_gen_ctx);
        if (psa_status != PSA_SUCCESS)
        {
            spsdk_status = (uint32_t)psa_status;
            goto exit;
        }
        LOG(LOG_INFO, "CSR generation completed successfully!\r\n");
    }
    else 
    {
        psa_status = verify_recv_x509_cert(&cert_storage_ctx);
        if (psa_status != PSA_SUCCESS)
        {
            spsdk_status = (uint32_t)psa_status;
            goto exit;
        }
        LOG(LOG_INFO, "Certificate verification and storage completed successfully!\r\n");
    }
    
exit:
    // mbedtls_psa_crypto_free(); // <-- need this?
    // psa_destroy_key(key_id);
 
    // Using the first 4 bytes of the config block address, as a 
    // status information for SPSDK. 
    LOG(LOG_DEBUG, "Returning status code of operation\r\n");
    if (mem_write((uint32_t)&el2go_csr_conf_data, (const uint8_t *)&spsdk_status, sizeof(spsdk_status))  != kStatus_CSR_MEM_SUCCESS)
    {
        LOG(LOG_ERROR, "Writing status code to memory failed!\r\n");
    }
    LOG(LOG_INFO, "########### EdgeLock2GO Certificate Signing Request App. EXIT ###########\r\n");
    return (int)spsdk_status;
}
