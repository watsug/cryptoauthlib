

#ifndef _ATCA_MBEDTLS_WRAP_H_
#define _ATCA_MBEDTLS_WRAP_H_

extern uint8_t atca_io_protection_key[32];

int atca_mbedtls_pk_init(mbedtls_pk_context * pkey, uint16_t slotid);
int atca_mbedtls_cert_init(mbedtls_x509_crt * cert, atcacert_def_t * cert_def);

#endif /* _ATCA_MBEDTLS_WRAP_H_ */
