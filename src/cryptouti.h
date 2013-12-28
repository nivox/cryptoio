#ifndef CRYPTOUTI_H
#define CRYPTOUTI_H

#include <openssl/evp.h>

#include "cryptoio.h"

typedef struct {
  unsigned char *key;
  unsigned char *iv;
  const EVP_CIPHER*  algo;
} crypto_ctx;


void cryptoInit();

void cryptoFree();

crypto_ctx* newCryptoCtx(algorithm_t algo, unsigned char *key);

void freeCryptoCtx(crypto_ctx *ctx);

size_t keySizeFor(algorithm_t algo);

/**
 * Encrypts the plaintext pointed by *p* of length *plen* into the buffer pointed
 * by *c*.
 *
 * @return Len of the generated chipertext or -1 in case of error.
 */
int encrypt(crypto_ctx *ctx, unsigned char *p, unsigned char *c, int plen);

/**
 * Decrypts the cyphertext pointed by *c* of length *clen* into the buffer pointed
 * by *p*.
 *
 * @return Len of the generated plaintext or -1 in case of error.
 */
int decrypt(crypto_ctx *ctx, unsigned char *c, unsigned char *p, int clen);
#endif
