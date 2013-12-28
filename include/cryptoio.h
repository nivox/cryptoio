#ifndef CRYPTOIO_H
#define CRYPTOIO_H

/* Supported crypto algorithms */
typedef enum { AES_128_CBC, AES_256_CBC } algorithm_t;

/* CryptoIO file handler */
typedef struct CIO_FILE CIO_FILE;

/*
 * Opens the file pointed by the string *path* with the speicified mode.
 * Valid modes are the ones supported by fopen except for a+.
 *
 * The *algo* and *key* parameters specify respectively the crypto algorithm
 * to use and the associated key.
 *
 * Return a pointer to the file handler or NULL in case of errors;
 */
CIO_FILE *cio_open(const char *path, const char *mode,
                   algorithm_t algo, unsigned char *key);

int cio_close(CIO_FILE *fp);
int cio_eof(CIO_FILE *fp);

size_t cio_read(void *ptr, size_t size, size_t nmemb, CIO_FILE *stream);
size_t cio_write(void *ptr, size_t size, size_t nmemb, CIO_FILE *stream);

int cio_seek(CIO_FILE *cfp, long offset, int whence);
long cio_tell(CIO_FILE *cfp);

size_t cio_keysize(algorithm_t algo);
#endif
