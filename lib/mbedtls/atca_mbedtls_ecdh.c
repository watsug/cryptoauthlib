/**
 * \brief Replace mbedTLS ECDH Functions with hardware acceleration &
 * hardware key security.
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

/* mbedTLS boilerplate includes */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ECDH_C)

#include "mbedtls/ecdh.h"
/* Cryptoauthlib Includes */
#include "cryptoauthlib.h"
#include "basic/atca_basic.h"
#include <string.h>

#ifdef MBEDTLS_ECDH_GEN_PUBLIC_ALT
/** Generate keypair */
int mbedtls_ecdh_gen_public(mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *Q,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
    int ret = 0;
    uint8_t public_key[ATCA_PUB_KEY_SIZE];
    uint8_t temp = 1;

    if (grp->id != MBEDTLS_ECP_DP_SECP256R1)
    {
        ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    if (!ret)
    {
        ret = atcab_genkey(d->s, public_key);
    }

    if (!ret)
    {
        ret = mbedtls_mpi_read_binary(&(Q->X), public_key, ATCA_PUB_KEY_SIZE / 2);
    }

    if (!ret)
    {
        ret = mbedtls_mpi_read_binary(&(Q->Y), &public_key[ATCA_PUB_KEY_SIZE / 2], ATCA_PUB_KEY_SIZE / 2);
    }

    if (!ret)
    {
        ret = mbedtls_mpi_read_binary(&(Q->Z), &temp, 1);
    }

    return ret;
}
#endif /* MBEDTLS_ECDH_GEN_PUBLIC_ALT */

#ifdef MBEDTLS_ECDH_COMPUTE_SHARED_ALT

extern uint8_t atca_io_protection_key[32];

/*
 * Compute shared secret (SEC1 3.3.1)
 */
int mbedtls_ecdh_compute_shared(mbedtls_ecp_group *grp, mbedtls_mpi *z,
                                const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng)
{

    int ret = 0;
    uint8_t public_key[ATCA_PUB_KEY_SIZE];
    uint8_t shared_key[ATCA_KEY_SIZE];

    if (grp == NULL)
    {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    if (grp->id != MBEDTLS_ECP_DP_SECP256R1)
    {
        ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    if (!ret)
    {
        ret = mbedtls_mpi_write_binary(&(Q->X), public_key, ATCA_PUB_KEY_SIZE / 2);
    }

    if (!ret)
    {
        ret = mbedtls_mpi_write_binary(&(Q->Y), &public_key[ATCA_PUB_KEY_SIZE / 2], ATCA_PUB_KEY_SIZE / 2);
    }

    if (!ret)
    {
        if (d->s > 15)
        {
            ret = atcab_ecdh_tempkey_ioenc(public_key, shared_key, atca_io_protection_key);
        }
        else
        {
            ret = atcab_ecdh_ioenc(d->s, public_key, shared_key, atca_io_protection_key);
        }
    }

    if (!ret)
    {
        ret = mbedtls_mpi_read_binary(z, shared_key, ATCA_KEY_SIZE);
    }

    return ret;
}
#endif /* MBEDTLS_ECDH_COMPUTE_SHARED_ALT */

#endif /* MBEDTLS_ECDH_C */
