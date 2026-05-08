#include <svdpi.h>

unsigned char read_symbol(const char *symbol_name, unsigned long long *address) {
  (void)symbol_name;
  if (address) {
    *address = 0;
  }
  return 0;
}

void read_elf(const char *filename) {
  (void)filename;
}

unsigned char get_section(long long *address, long long *len) {
  if (address) {
    *address = 0;
  }
  if (len) {
    *len = 0;
  }
  return 0;
}

void read_section_sv(long long address, const svOpenArrayHandle buffer) {
  (void)address;
  (void)buffer;
}

int debug_tick(
    svBit *debug_req_valid,
    svBit debug_req_ready,
    int *debug_req_bits_addr,
    int *debug_req_bits_op,
    int *debug_req_bits_data,
    svBit debug_resp_valid,
    svBit *debug_resp_ready,
    int debug_resp_bits_resp,
    int debug_resp_bits_data) {
  (void)debug_req_ready;
  (void)debug_resp_valid;
  (void)debug_resp_bits_resp;
  (void)debug_resp_bits_data;

  if (debug_req_valid) {
    *debug_req_valid = 0;
  }
  if (debug_req_bits_addr) {
    *debug_req_bits_addr = 0;
  }
  if (debug_req_bits_op) {
    *debug_req_bits_op = 0;
  }
  if (debug_req_bits_data) {
    *debug_req_bits_data = 0;
  }
  if (debug_resp_ready) {
    *debug_resp_ready = 0;
  }
  return 0;
}

int jtag_tick(
    svBit *jtag_TCK,
    svBit *jtag_TMS,
    svBit *jtag_TDI,
    svBit *jtag_TRSTn,
    svBit jtag_TDO) {
  (void)jtag_TDO;

  if (jtag_TCK) {
    *jtag_TCK = 0;
  }
  if (jtag_TMS) {
    *jtag_TMS = 0;
  }
  if (jtag_TDI) {
    *jtag_TDI = 0;
  }
  if (jtag_TRSTn) {
    *jtag_TRSTn = 0;
  }
  return 0;
}
