#include "cryptouti.h"

#include <string.h>
#include <stdio.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>


void cryptoInit() {
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);
}

void cryptoFree() {
  EVP_cleanup();
  ERR_free_strings();
}

size_t keySizeFor(algorithm_t algo) {
  const EVP_CIPHER *c;
  switch(algo) {
  case AES_128_CBC:
    c = EVP_aes_128_cbc();
    break;
  case AES_256_CBC:
    c = EVP_aes_256_cbc();
    break;
  default:
    return -1;
  }

  return EVP_CIPHER_key_length(c);
}

crypto_ctx* newCryptoCtx(algorithm_t algo, unsigned char *key) {
  crypto_ctx *ctx;

  ctx = malloc(sizeof(crypto_ctx));
  if (ctx == NULL) {
    fprintf(stderr, "CryptoIO: Error allocating memory for crypto context!\n");
    return NULL;
  }

  ctx->key = ctx->iv = NULL;

  switch(algo) {
  case AES_128_CBC:
    ctx->algo = EVP_aes_128_cbc();
    break;
  case AES_256_CBC:
    ctx->algo = EVP_aes_256_cbc();
    break;
  default:
    goto err;
  }

  ctx->key=malloc(sizeof(unsigned char) * EVP_CIPHER_key_length(ctx->algo));
  if (!ctx->key) goto err;
  memcpy(ctx->key, key, EVP_CIPHER_key_length(ctx->algo));

  ctx->iv=malloc(sizeof(unsigned char) * EVP_CIPHER_iv_length(ctx->algo));
  if (!ctx->iv) goto err;
  memset(ctx->iv, 0, EVP_CIPHER_iv_length(ctx->algo));

  return ctx;

 err:
  if(ctx->key) free(ctx->key);
  if(ctx->iv) free(ctx->iv);
  free(ctx);
  return NULL;
}

void freeCryptoCtx(crypto_ctx *ctx) {
  if (ctx) {
    free(ctx->key);
    free(ctx->iv);
    free(ctx);
  }
}

void dumpBuffer(unsigned char *ptr, int len) {
  int i;
  for (i=0; i<len; i++) {
    if (i > 0 && i%2 == 0) fprintf(stderr, " ");
    fprintf(stderr, "%02x", ptr[i]);
  }
  fprintf(stderr, "\n");
}

int encrypt(crypto_ctx *ctx, unsigned char *ptr, unsigned char *dst, int len) {
  EVP_CIPHER_CTX *ectx;

  ectx = EVP_CIPHER_CTX_new();
  if (ectx == NULL) {
    fprintf(stderr, "CtryptoIO: Error creating encryption EVP context!\n");
    return -1;
  }

  if (!EVP_EncryptInit_ex(ectx, ctx->algo, NULL, ctx->key, ctx->iv)) {
    fprintf(stderr, "CryptoIO: Error initializing encryption EVP context!\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  int plen=-1;
  int clen=0;
  if(!EVP_EncryptUpdate(ectx, dst, &plen, ptr, len)) {
    fprintf(stderr, "CryptoIO: Error EVP_EncryptUpdate\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }
  clen = plen;

  // Pad and flush
  if(!EVP_EncryptFinal_ex(ectx, dst+plen, &plen)){
    fprintf(stderr, "CryptoIO: Error EVP_EncryptFinal_ex\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }
  clen += plen;


  /* fprintf(stderr, "Encryption\n"); */
  /* fprintf(stderr, "IN=%d\n", len); */
  /* dumpBuffer(ptr, len); */
  /* fprintf(stderr, "-----------\n"); */
  /* fprintf(stderr, "OUT=%d\n", clen); */
  /* dumpBuffer(dst, clen); */
  /* fprintf(stderr, "===========\n"); */

  EVP_CIPHER_CTX_free(ectx);

  return clen;
}

int decrypt(crypto_ctx *ctx, unsigned char *ptr, unsigned char *dst, int len) {
  EVP_CIPHER_CTX *dctx;

  dctx = EVP_CIPHER_CTX_new();
  if (dctx == NULL) {
    fprintf(stderr, "CryptoIO: Error creating decription EVP context!\n");
    return -1;
  }

  /* fprintf(stderr, "Decryption\n"); */
  /* fprintf(stderr, "IN=%d\n", len); */
  /* dumpBuffer(ptr, len); */
  /* fprintf(stderr, "-----------\n"); */

  if(!EVP_DecryptInit_ex(dctx, ctx->algo, NULL, ctx->key, ctx->iv)) {
    fprintf(stderr, "CryptoIO: Error initializing decryption EVP context!\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  int tlen=-1;
  int clen=0;
  if(!EVP_DecryptUpdate(dctx, dst, &tlen, ptr, len)) {
    fprintf(stderr, "CryptoIO: Error EVP_DecryptUpdate\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  clen = tlen;

  if(!EVP_DecryptFinal_ex(dctx, dst+tlen, &tlen)) {
    fprintf(stderr, "CryptoIO: Error EVP_DecryptFinal_ex\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }
  clen += tlen;

  /* fprintf(stderr, "OUT=%d\n", clen); */
  /* dumpBuffer(dst, clen); */
  /* fprintf(stderr, "===========\n"); */


  EVP_CIPHER_CTX_free(dctx);

  return clen;
}
