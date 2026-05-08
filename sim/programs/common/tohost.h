#ifndef RVMT_TOHOST_H
#define RVMT_TOHOST_H

#define RVMT_TOHOST_ADDR 0x10000000UL

static inline void rvmt_finish(unsigned long code) {
  volatile unsigned long *tohost = (volatile unsigned long *)RVMT_TOHOST_ADDR;
  *tohost = code;
  while (1) {
  }
}

#endif
