#include <assert.h>
#include <string.h>

#include "buffer.h"

/************************************************************
 * Circular bffe implementation
 ************************************************************/

cbuff_t* newCBuff(size_t size) {
  cbuff_t *buff = malloc(sizeof(cbuff_t));
  if (!buff) return NULL;

  buff->buff = malloc(size);
  if (!buff) {
    free(buff);
    return NULL;
  }

  buff->len=size;
  buff->start=0;
  buff->end=-1;
}

void freeCBuff(cbuff_t *buff) {
  if (buff) {
    free(buff->buff);
    free(buff);
  }
}

size_t cbuffLen(cbuff_t *buff) {
  return buff->len;
}

size_t cbuffAvail(cbuff_t *buff) {
  if (buff->end < 0) return 0;
  else if (buff->start == buff->end) return buff->len;
  else if (buff->start < buff->end) return buff->end - buff->start;
  else return (buff->len - buff->start) + buff->end;
}

size_t cbuffFree(cbuff_t *buff) {
  return buff->len - cbuffAvail(buff);
}

int cbuffFetch(cbuff_t *buff, uint8_t *ptr, size_t len) {
  size_t avail = cbuffAvail(buff);
  int i,k;

  if (len > avail) len = avail;

  k=0;
  for (i=buff->start; i<buff->len && k<len; i++, k++) ptr[k] = buff->buff[i];
  for (i=0; i<buff->end && k<len; i++, k++) ptr[k] = buff->buff[i];

  buff->start = (buff->start + k) % buff->len;

  if (buff->start == buff->end) {
    buff->start=0;
    buff->end=-1;
  }
  assert(cbuffAvail(buff) == avail-k);
  return k;
}

int cbuffPush(cbuff_t *buff, uint8_t *ptr, size_t len) {
  size_t free = cbuffFree(buff);
  int i,k;

  if (len > free) len = free;
  if (len == 0) return;

  if (buff->end < 0) buff->end = buff->start;

  k=0;
  for (i=buff->end; i<buff->len && k<len; i++, k++) buff->buff[i] = ptr[k];
  for (i=0; i<buff->start && k<len; i++, k++) buff->buff[i] = ptr[k];

  buff->end = (buff->end + k) % buff->len;

  assert(cbuffFree(buff) == free-k);
  return k;
}

void cbuffClear(cbuff_t *buff) {
  buff->start=0;
  buff->end=-1;
}

/************************************************************
 * Buffer implementation
 ************************************************************/
buff_t* newBuff(size_t size) {
  buff_t *buff = malloc(sizeof(buff_t));
  if (!buff) return NULL;

  buff->buff = malloc(size);
  if (!buff) {
    free(buff);
    return NULL;
  }

  buff->len=size;
  buff->offset=0;
  buff->end=0;
}

void freeBuff(buff_t *buff) {
  if (buff) {
    free(buff->buff);
    free(buff);
  }
}

size_t buffLen(buff_t *buff) {
  return buff->end;
}

size_t buffMaxLen(buff_t *buff) {
  return buff->len;
}

size_t buffOffset(buff_t *buff) {
  return buff->offset;
}

size_t buffExtendableFor(buff_t *buff) {
  return buff->len - buff->end;
}

size_t buffRemaining(buff_t *buff) {
  return buff->end - buff->offset;
}

uint8_t* buffPos(buff_t *buff) {
  return buff->buff + buff->offset;
}

uint8_t* buffEndPos(buff_t *buff) {
  return buff->buff + buff->offset;
}

void buffReset(buff_t *buff) {
  buff->offset=0;
}

void buffClear(buff_t *buff) {
  buff->end = buff->offset = 0;
}

int buffAdjustPos(buff_t *buff, int adjust) {
  int newoffset = buff->offset + adjust;
  if (newoffset < 0) return -1;
  else if (newoffset > buff->end) newoffset = buff->end;

  adjust = newoffset - buff->offset;
  buff->offset = newoffset;
  return adjust;
}

int buffAdjustLen(buff_t *buff, int adjust) {
  int newend = buff->end + adjust;
  if (newend < 0) return -1;
  else if (newend > buff->len) newend = buff->len;

  adjust = newend - buff->offset;
  buff->end = newend;
  return adjust;
}

int buffRead(buff_t *buff, uint8_t *ptr, size_t len) {
  int rem = buffRemaining(buff);
  if (len > rem) len = rem;

  memcpy(ptr, buff->buff + buff->offset, len);
  buff->offset += len;

  return len;
}

int buffWrite(buff_t *buff, uint8_t *ptr, size_t len) {
  int rem = buff->len - buff->offset;
  if (len > rem) len = rem;

  memcpy(buff->buff + buff->offset, ptr, len);
  buff->offset += len;
  if (buff->offset > buff->end) buff->end = buff->offset;

  return len;
}

int buffExtend(buff_t *buff, uint8_t *ptr, size_t len) {
  int rem = buff->len - buff->end;
  if (len > rem) len = rem;

  memcpy(buff->buff + buff->end, ptr, len);
  buff->end += len;

  return len;
}
