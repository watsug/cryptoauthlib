/**
 * \brief mbedTLS Interface Functions that enable mbedtls objects to use
 * cryptoauthlib functions
 *
 * \copyright (c) 2017 Microchip Technology Inc.
 *
 * \page License
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

#ifndef _ATCA_MBEDTLS_WRAP_H_
#define _ATCA_MBEDTLS_WRAP_H_

/** \defgroup atca_mbedtls_ mbedTLS Wrapper methods (atca_mbedtls_)
 *
 * \brief
 * These methods are for interfacing cryptoauthlib to mbedtls
 *
   @{ */

#ifdef __cplusplus
extern "C" {
#endif

/* Wrapper Functions */
int atca_mbedtls_pk_init(struct mbedtls_pk_context * pkey, uint16_t slotid);
int atca_mbedtls_cert_add(struct mbedtls_x509_crt * cert, struct atcacert_def_s * cert_def);

/* Application Callback definitions */

/** \brief ECDH Callback to obtain the "slot" used in ECDH operations from the
 * application
 * \return Slot Number
 */
int atca_mbedtls_ecdh_slot_cb(void);

/** \brief ECDH Callback to obtain the IO Protection secret from the application
 * \param[out] secret 32 byte array used to store the secret
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
int atca_mbedtls_ecdh_ioprot_cb(uint8_t secret[32]);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* _ATCA_MBEDTLS_WRAP_H_ */
