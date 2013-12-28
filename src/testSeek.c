#include <stdlib.h>
#include <stdio.h>
#include "cryptoio.h"
#include "cryptouti.h"

#ifndef CRYPTOIO
#define IFILE FILE
#define i_fopen(p, m) fopen(p, m)
#define i_fwrite(ptr, s, n, f) fwrite(ptr, s, n, f)
#define i_fread(ptr, s, n, f) fread(ptr, s, n, f)
#define i_ftell(f) ftell(f)
#define i_fseek(f, p, m) fseek(f, p, m)
#define i_fclose(f) fclose(f)
#else
unsigned char *KEY="questa è la mia chiave di prova";
#define IFILE CIO_FILE
#define i_fopen(p, m) cio_open(p, m, AES_256_CBC, KEY)
#define i_fwrite(ptr, s, n, f) cio_write(ptr, s, n, f)
#define i_fread(ptr, s, n, f) cio_read(ptr, s, n, f)
#define i_ftell(f) cio_tell(f)
#define i_fseek(f, p, m) cio_seek(f, p, m)
#define i_fclose(f) cio_close(f)
#endif


int main(int argc, char *argv[]) {
  int seed = 0;

  if (argc >= 3) {
    seed = atoi(argv[1]);
  } else {
    fprintf(stderr, "Usage: %s <num-seed> <path>\n", argv[0]);
    return 1;
  }

  IFILE *f = i_fopen(argv[2], "w+");

  srand(seed);
  int n = rand() % 1000;

  int i;
  long maxpos = 0;
  for (i=0; i<n; i++) {

    int b = rand() % 10000;
    int j;

    char *buff = malloc(b);
    char rr;
    if (!buff) {
      fprintf(stderr, "Error allocating buff of: %d\n", b);
      return 1;
    }

    fprintf(stderr, "TS: writing %d bytes\n", b);
    fprintf(stderr, "TS: pre pos=%d\n", i_ftell(f));
    int rcount;
    for(j=0; j<b-1; j++){
      if (rand() % 2 == 0) buff[j] = (char) 97 + (rand() % 25);
      else {
        char rr=0;
        int r = i_fread(&rr, sizeof(char), 1, f);
        if (r > 0) {
          buff[j] = rr - 97 + 65;
          rcount++;
        }else buff[j]= '_';
      }
      fprintf(stderr, "%c", buff[j]);
    }
    buff[b-1]='\n';
    fprintf(stderr,"\n");
    fprintf(stderr,"rcount=%d\n", rcount);

    i_fwrite(buff, sizeof(char), b, f);
    fprintf(stderr, "TS: Written %d bytes\n", b);
    long pos = i_ftell(f);
    fprintf(stderr,"TS: post pos=%d\n", pos);

    if (pos > maxpos) maxpos = pos;
    if (rand() % 100 < 25){
      long newpos=rand() % maxpos;
      fprintf(stderr, "TS: seeking to %d\n", newpos);
      i_fseek(f, newpos, SEEK_SET);
    }
  }

  i_fclose(f);
}
