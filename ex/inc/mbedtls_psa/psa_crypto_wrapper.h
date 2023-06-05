/*
 * Copyright 2021 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#ifndef _PSA_CRYPTO_WRAPPER_H_
#define _PSA_CRYPTO_WRAPPER_H_

#include <psa/crypto.h>

 /** @brief This function is the PSA import key wrapping to be used with simulators.
  *
  * The function extends the PSA import key provided by MBED TLS supporting the command
  * structure as will be used in non-MCU devices
  *
  * \p attributes user to provided an pointer to an initialized psa_key_attributes_t structure
  * \p data is the command used for PSA import key on non-MCU devices
  * \p data_length the size of the command
  * \p the handle to the key returned by PSA and which needs to be used in futher calls of MBED TLS
  *
  */
psa_status_t psa_import_key_wrap(const psa_key_attributes_t *attributes,
	const uint8_t *data,
	size_t data_length,
	mbedtls_svc_key_id_t *key);

#endif //_PSA_CRYPTO_WRAPPER_H_