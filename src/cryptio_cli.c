#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cryptoio.h"

// initialization vector
unsigned char IV[128] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

int main(int argc, char *argv[]) {
  if (argc < 4) {
    fprintf(stderr, "Usage: %s <mode> <key> <in> <out>\n", argv[0]);
    return 2;
  }

  char mode='\0';
  char *key;
  void *in_f;
  void *out_f;

  int klen = strlen(argv[2]);
  int tlen = cio_keysize(AES_256_CBC);
  if (klen == tlen) {
    key = argv[2];
  } else {
    key = malloc(tlen + 1);
    memset(key, 0, tlen);

    int i;
    for (i=0; i<klen && i<tlen; i++) key[i] = argv[2][i];
    if (i < tlen) fprintf(stderr, "WARN: key too short. Padded with \\0\n");
    else fprintf(stderr, "WARN: key too long. Truncated at %d\n", tlen);
    key[tlen-1] = 0;
    fprintf(stderr, "WARN: actual key: '%s'\n", key);
  }

  mode=argv[1][0];
  if (mode != 'd' && mode != 'e') {
    fprintf(stderr, "Mode must be one of: e (encryption), d (decryption)\n");
    return 2;
  }

  if (mode == 'e') in_f = fopen(argv[3], "rb");
  else in_f = cio_open(argv[3], "rb", AES_256_CBC, key);
  if (in_f == NULL) {
    fprintf(stderr, "Error opening input file: %s\n", argv[2]);
    return 2;
  }

  if (mode == 'd') out_f = fopen(argv[4], "wb");
  else out_f = cio_open(argv[4], "wb", AES_256_CBC, key);
  if (out_f == NULL) {
    fprintf(stderr, "Error opening output file: %s\n", argv[3]);
    return 2;
  }

  unsigned char *buff[8192];
  int r;
  int w;
  while( (mode=='e' && !feof((FILE*)in_f)) || (mode=='d' && !cio_eof((CIO_FILE*)in_f)) ) {
    if (mode == 'e') {
      r = fread(buff, sizeof(unsigned char), sizeof(buff), (FILE*)in_f);
    } else {
      r = cio_read(buff, sizeof(unsigned char), sizeof(buff), (CIO_FILE*)in_f);
    }

    if (mode=='e') {
      w = cio_write(buff, sizeof(unsigned char), r, (CIO_FILE*)out_f);
    } else {
      w = fwrite(buff, sizeof(unsigned char), r, (FILE*)out_f);
    }
  }

  if (mode == 'e') {
    fclose((FILE*)in_f);
    cio_close((CIO_FILE*)out_f);
  } else {
    cio_close((CIO_FILE*)in_f);
    fclose((FILE*)out_f);
  }

  return 0;
}
