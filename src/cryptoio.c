#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cryptoio.h"
#include "cryptouti.h"
#include "buffer.h"

#define BUFFER_SIZE 8192
#define PLAIN_BLOCK_SIZE 512
#define CYPHER_BLOCK_SIZE ((PLAIN_BLOCK_SIZE/16)+1)*16

#define BUFF_MODE_READ 1
#define BUFF_MODE_WRITE 2

typedef struct {
  int len;
  unsigned char c[CYPHER_BLOCK_SIZE];
} crypto_block;

typedef struct {
  cbuff_t *cipherBuff;
  buff_t *plainBuff;

  buff_t *currBlockBuff;
  uint8_t currBlockMode;

  long currBlockPos;
} io_ctx;

struct CIO_FILE {
  FILE *fp;
  crypto_ctx *ctx;
  io_ctx itx;

};

/*************************************************************
 * Utility functions
 *************************************************************/

static long plainPosToCipherPos(long pos, int *offset) {
  long blocks = pos / PLAIN_BLOCK_SIZE;
  *offset = pos % PLAIN_BLOCK_SIZE;

  return blocks * sizeof(crypto_block);
}

static size_t cio_writeBuff(CIO_FILE *cfp) {
  crypto_block block;
  long pos;
  block.len = buffLen(cfp->itx.currBlockBuff);

  if (block.len > 0) {
    buffReset(cfp->itx.currBlockBuff);
    int w = encrypt(cfp->ctx,
                    buffPos(cfp->itx.currBlockBuff),
                    (unsigned char *) &block.c,
                    PLAIN_BLOCK_SIZE);
    if (w < 0) {
      fprintf(stderr, "CryptoIO: Error encrypting block!\n");
      return -1;
    }

    pos = ftell(cfp->fp);
    if (pos != cfp->itx.currBlockPos) {
      fseek(cfp->fp, cfp->itx.currBlockPos, SEEK_SET);
      /* fprintf(stderr,"Seek %d -> %d\n", pos, cfp->itx.currBlockPos); */
    }

    /* fprintf(stderr, "Writing at %d[%d] plaintxt bytes: %d\n", cfp->itx.currBlockPos, ftell(cfp->fp), block.len); */
    if (fwrite(&block, sizeof(crypto_block), 1, cfp->fp) <= 0) {
      fprintf(stderr, "CryptoIO: Error writing to file!\n");
      return -1;
    }
    fflush(cfp->fp);

    cfp->itx.currBlockPos += sizeof(crypto_block);
    buffClear(cfp->itx.currBlockBuff);
    buffClear(cfp->itx.plainBuff);
    cbuffClear(cfp->itx.cipherBuff);
    cfp->itx.currBlockMode = 0;

    /* fprintf(stderr, "WRITE pos=%d  block=%d fpos=%d\n", */
    /*         cfp->itx.currBlockPos, */
    /*         cfp->itx.currBlockPos/sizeof(crypto_block), ftell(cfp->fp)); */
  }

  return block.len;
}

static int fillCipherBuffer(CIO_FILE *cfp) {
  uint8_t *buff;
  int len = cbuffFree(cfp->itx.cipherBuff);
  if (len == 0) return 0;

  buff = malloc(len);
  if (!buff) return -1;

  /* fprintf(stderr, "Reading cipher at %d\n", ftell(cfp->fp)); */

  int r = fread(buff, sizeof(uint8_t), len, cfp->fp);
  /* fprintf(stderr, "Read %d bytes of ciphertxt\n", r); */
  cbuffPush(cfp->itx.cipherBuff, buff, r);
  free(buff);
  return r;
}

static int fillPlainBuffer(CIO_FILE *cfp) {
  int availBytes = buffRemaining(cfp->itx.plainBuff);

  if (availBytes == 0) {
    uint8_t plaintxt[CYPHER_BLOCK_SIZE];
    crypto_block block;
    int r;

    block.len=0;
    if (cbuffAvail(cfp->itx.cipherBuff) < sizeof(crypto_block)) {
      do {
        r = fillCipherBuffer(cfp);
        if (r < 0 || (r == 0 && cbuffAvail(cfp->itx.cipherBuff) > 0)) {
          fprintf(stderr,
                  "CryptoIO: Error filling buffer for decryption! Len=%d Block=%d\n",
                  cbuffAvail(cfp->itx.cipherBuff),
                  sizeof(crypto_block));
          return -1;
        } else if (r == 0 && cbuffAvail(cfp->itx.cipherBuff) == 0) return 0;
      } while (cbuffAvail(cfp->itx.cipherBuff) < sizeof(crypto_block));
    }

    /* fprintf(stderr, "FillPlainBuffer in: len=%d offset=%d \n", */
    /*         buffLen(cfp->itx.plainBuff), buffOffset(cfp->itx.plainBuff)); */

    cbuffFetch(cfp->itx.cipherBuff, (uint8_t *)&block, sizeof(crypto_block));
    r = decrypt(cfp->ctx, block.c, plaintxt, CYPHER_BLOCK_SIZE);

    buffClear(cfp->itx.plainBuff);
    buffExtend(cfp->itx.plainBuff, plaintxt, block.len);

    /* fprintf(stderr, "FillPlainBuffer out: len=%d offset=%d \n", */
    /*         buffLen(cfp->itx.plainBuff), buffOffset(cfp->itx.plainBuff)); */
    return block.len;
  }
}

static int fillCurrBlockBuffer(CIO_FILE *cfp) {
  if (buffRemaining(cfp->itx.currBlockBuff) == 0 &&
      buffExtendableFor(cfp->itx.currBlockBuff) == 0) {
    if (cfp->itx.currBlockMode & BUFF_MODE_WRITE) {
      cio_writeBuff(cfp);
    } else {
      buffClear(cfp->itx.currBlockBuff);
      cfp->itx.currBlockMode = 0;
      cfp->itx.currBlockPos += sizeof(crypto_block);
    }
  }

  if (buffExtendableFor(cfp->itx.currBlockBuff) > 0) {
    int w;
    do {
      int n = buffExtendableFor(cfp->itx.currBlockBuff);
      fillPlainBuffer(cfp);
      buffAdjustPos(cfp->itx.plainBuff, buffOffset(cfp->itx.currBlockBuff));

      w = buffRead(cfp->itx.plainBuff, buffEndPos(cfp->itx.currBlockBuff), n);
      buffAdjustLen(cfp->itx.currBlockBuff, w);
    } while(buffExtendableFor(cfp->itx.currBlockBuff) > 0 && w > 0);

    /* fprintf(stderr, "FillCurrBlockBuffer out: len=%d offset=%d plen=%d poff=%d\n", */
    /*         buffLen(cfp->itx.currBlockBuff), buffOffset(cfp->itx.currBlockBuff), */
    /*         buffLen(cfp->itx.plainBuff), buffOffset(cfp->itx.plainBuff)); */
  }

  return 1;
}

static int cio_seekImpl(CIO_FILE *cfp, long pos, int backward) {
  int coff;

  /* fprintf(stderr, "Seeking to %d (back=%d)\n", pos, backward); */

  if (cfp->itx.currBlockMode & BUFF_MODE_WRITE) cio_writeBuff(cfp);
  cbuffClear(cfp->itx.cipherBuff);
  buffClear(cfp->itx.plainBuff);
  buffClear(cfp->itx.currBlockBuff);

  cfp->itx.currBlockPos = plainPosToCipherPos(pos, &coff);
  /* fprintf(stderr, "Seek cipherpos=%d offset=%d\n", cfp->itx.currBlockPos, coff); */
  fseek(cfp->fp, cfp->itx.currBlockPos, SEEK_SET);
  fillCurrBlockBuffer(cfp);
  buffAdjustPos(cfp->itx.currBlockBuff, coff);
  /* fprintf(stderr, "Buff offset=%d end=%d\n", */
  /*         buffOffset(cfp->itx.currBlockBuff), */
  /*         buffLen(cfp->itx.currBlockBuff)); */
}

static char* convertOpenMode(const char *mode) {
  if (strcmp(mode, "r")==0 || strcmp(mode, "rb")==0) return "rb";
  else if(strcmp(mode, "r+")==0 || strcmp(mode, "rb+")==0) return "r+b";
  else if(strcmp(mode, "w")==0 || strcmp(mode, "wb")==0
          || strcmp(mode, "w+")==0 ||strcmp(mode, "w+b")==0) return "w+b";
  else {
    fprintf(stderr, "CryptoIO: open mode not supported (%s)!\n", mode);
    return NULL;
  }
}

/*************************************************************
 * API functions
 *************************************************************/

static int cio_crypto_initialized=0;
CIO_FILE *cio_open(const char *path, const char *mode,
                   algorithm_t algo, unsigned char *key)
{
  CIO_FILE *cfp;
  int pos;
  char *cmode;

  if (!cio_crypto_initialized) {
    cio_crypto_initialized = 1;
    cryptoInit();
  }

  cfp = malloc(sizeof(CIO_FILE));
  if (cfp == NULL) goto err;

  cfp->fp = NULL;
  cfp->ctx = NULL;
  cfp->itx.cipherBuff = NULL;
  cfp->itx.plainBuff = NULL;
  cfp->itx.currBlockBuff = NULL;


  cmode = convertOpenMode(mode);
  if (cmode == NULL) goto err;

  cfp->fp = fopen(path, cmode);
  if (cfp->fp == NULL) goto err;

  cfp->itx.cipherBuff = newCBuff(BUFFER_SIZE);
  if (cfp->itx.cipherBuff == NULL) goto err;

  cfp->itx.plainBuff = newBuff(PLAIN_BLOCK_SIZE);
  if (cfp->itx.plainBuff == NULL) goto err;

  cfp->itx.currBlockBuff = newBuff(PLAIN_BLOCK_SIZE);
  if (cfp->itx.currBlockBuff == NULL) goto err;

  cfp->itx.currBlockMode = 0;

  cfp->ctx = newCryptoCtx(algo, key);
  if (cfp->ctx == NULL) {
    fprintf(stderr, "Error creating Crypto Context\n");
    goto err;
  }

  pos = ftell(cfp->fp);
  if (pos > 0) cio_seekImpl(cfp, pos, 0);
  else cfp->itx.currBlockPos = 0;

  return cfp;

 err:
  if (cfp) {
    if(cfp->itx.cipherBuff) freeCBuff(cfp->itx.cipherBuff);
    if(cfp->itx.plainBuff) freeBuff(cfp->itx.plainBuff);
    if(cfp->itx.currBlockBuff) freeBuff(cfp->itx.currBlockBuff);
    free(cfp);
  }
  return NULL;
}

long cio_tell(CIO_FILE *cfp) {
  int blocks = cfp->itx.currBlockPos / sizeof(crypto_block);
  long plainPos = blocks * PLAIN_BLOCK_SIZE;

  return plainPos + buffOffset(cfp->itx.currBlockBuff);
}

int cio_seek(CIO_FILE *cfp, long offset, int whence) {
  switch (whence) {
  case SEEK_SET: return cio_seekImpl(cfp, offset, 0);
  case SEEK_CUR: return cio_seekImpl(cfp, cio_tell(cfp)+offset, 0);
  case SEEK_END: return cio_seekImpl(cfp, offset, 1);
  default: return EINVAL;
  }
}

int cio_flush(CIO_FILE *cfp) {
  return fflush(cfp->fp);
}

size_t cio_read(void *ptr, size_t size, size_t nmemb, CIO_FILE *cfp) {
  int availBytes;
  int askedBytes = size * nmemb;
  int len;

  /* fprintf(stderr, "Read in. Len=%d/%d off=%d pos=%d[%d]\n", */
  /*         buffLen(cfp->itx.currBlockBuff), buffMaxLen(cfp->itx.currBlockBuff), */
  /*         buffOffset(cfp->itx.currBlockBuff), */
  /*         cfp->itx.currBlockPos, ftell(cfp->fp)); */

  fillCurrBlockBuffer(cfp);

  availBytes = buffRemaining(cfp->itx.currBlockBuff);
  len = availBytes > askedBytes ? askedBytes : availBytes;

  /* fprintf(stderr, "Reading %d len bytes\n", len); */
  buffRead(cfp->itx.currBlockBuff, ptr, len);
  /* fprintf(stderr, "Read out. Len=%d/%d off=%d pos=%d[%d]\n", */
  /*         buffLen(cfp->itx.currBlockBuff), buffMaxLen(cfp->itx.currBlockBuff), */
  /*         buffOffset(cfp->itx.currBlockBuff), */
  /*         cfp->itx.currBlockPos, ftell(cfp->fp)); */
  return len;
}

size_t cio_write(void *ptr, size_t size, size_t nmemb, CIO_FILE *cfp) {
  int rem = size * nmemb;
  int len;
  crypto_block block;
  uint8_t *data=(uint8_t *)ptr;

  block.len = PLAIN_BLOCK_SIZE;

  do {
    int bufLen;

    len = buffWrite(cfp->itx.currBlockBuff, data, rem);
    cfp->itx.currBlockMode |= BUFF_MODE_WRITE;
    /* fprintf(stderr, "Write in. Len=%d/%d Off=%d pos=%d[%d]\n", */
    /*         buffLen(cfp->itx.currBlockBuff), buffMaxLen(cfp->itx.currBlockBuff), */
    /*         buffOffset(cfp->itx.currBlockBuff), */
    /*         cfp->itx.currBlockPos, ftell(cfp->fp)); */

    rem -= len;
    data += len;

    bufLen = buffLen(cfp->itx.currBlockBuff);
    if (bufLen == PLAIN_BLOCK_SIZE &&
        buffRemaining(cfp->itx.currBlockBuff) == 0) {
      cio_writeBuff(cfp);
    } else if ((cfp->itx.currBlockMode & BUFF_MODE_READ) == 0){
      fillCurrBlockBuffer(cfp);
      cfp->itx.currBlockMode |= BUFF_MODE_WRITE;
    }
    /* fprintf(stderr, "Write out. Len=%d/%d Off=%d pos=%d[%d]\n", */
    /*         buffLen(cfp->itx.currBlockBuff), buffMaxLen(cfp->itx.currBlockBuff), */
    /*         buffOffset(cfp->itx.currBlockBuff), */
    /*         cfp->itx.currBlockPos, ftell(cfp->fp)); */
  } while (rem > 0);
  return nmemb;
}

int cio_close(CIO_FILE *cfp) {
  if (cfp->itx.currBlockMode & BUFF_MODE_WRITE) cio_writeBuff(cfp);

  int ret = fclose(cfp->fp);
  if (ret != 0) return ret;

  freeCBuff(cfp->itx.cipherBuff);
  freeBuff(cfp->itx.currBlockBuff);

  freeCryptoCtx(cfp->ctx);
  free(cfp);

  return 0;
}

int cio_eof(CIO_FILE *cfp) {
  int iseof = (buffRemaining(cfp->itx.currBlockBuff) == 0) &&
    (cbuffAvail(cfp->itx.cipherBuff) == 0) &&
    feof(cfp->fp);

  return iseof;
}

size_t cio_keysize(algorithm_t algo) {
  return keySizeFor(algo);
}
