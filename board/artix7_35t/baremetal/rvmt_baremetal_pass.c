#include <stdint.h>

#define LITEX_UART_RXTX   ((volatile uint32_t *)0xf0004000u)
#define LITEX_UART_TXFULL ((volatile uint32_t *)0xf0004004u)

static void uart_putc(char c) {
    while (*LITEX_UART_TXFULL) {
    }
    *LITEX_UART_RXTX = (uint32_t)c;
}

static void uart_puts(const char *s) {
    while (*s) {
        if (*s == '\n') {
            uart_putc('\r');
        }
        uart_putc(*s++);
    }
}

void main(void) {
    volatile uint32_t *ram = (volatile uint32_t *)0x40001000u;
    ram[0] = 0x52564d54u;
    ram[1] = ram[0] ^ 0x13579bdfu;

    uart_puts("\nRVMT_BAREMETAL_PASS\n");
    uart_puts("RVMT_BAREMETAL_MEM=");
    uart_puts(ram[1] == 0x4101d68bu ? "OK\n" : "FAIL\n");

    for (;;) {
        __asm__ volatile("" ::: "memory");
    }
}
