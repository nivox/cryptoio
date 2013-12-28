#ifndef BUFFER_H
#define BUFFER_H

#include <stdint.h>
#include <stdlib.h>

/* Circular buffer data structure */
typedef struct {
  uint8_t *buff;
  size_t len;
  int start;
  int end;
} cbuff_t;

/* Buffer data structure */
typedef struct {
  uint8_t *buff;
  size_t len;
  int offset;
  int end;
} buff_t;


/* Circular buffer functions */
cbuff_t* newCBuff(size_t size);
void freeCBuff(cbuff_t *buff);

size_t cbuffLen(cbuff_t *buff);
size_t cbuffAvail(cbuff_t *buff);
size_t cbuffFree(cbuff_t *buff);

int cbuffFetch(cbuff_t *buff, uint8_t *ptr, size_t len);
int cbuffPush(cbuff_t *buff, uint8_t *ptr, size_t len);

void cbuffClear(cbuff_t *buff);

/* Buffer functions */
buff_t* newBuff(size_t size);
void freeBuff(buff_t *buff);

size_t buffLen(buff_t *buff);
size_t buffMaxLen(buff_t *buff);
size_t buffOffset(buff_t *buff);
size_t buffRemaining(buff_t *buff);
size_t buffExtendableFor(buff_t *buff);

uint8_t* buffPos(buff_t *buff);
uint8_t* buffEndPos(buff_t *buff);
int buffAdjustPos(buff_t *buff, int adjust);
int buffAdjustLen(buff_t *buff, int adjust);
void buffReset(buff_t *buff);
void buffClear(buff_t *buff);

int buffRead(buff_t *buff, uint8_t *ptr, size_t len);
int buffWrite(buff_t *buff, uint8_t *ptr, size_t len);
int buffExtend(buff_t *buff, uint8_t *ptr, size_t len);
#endif
