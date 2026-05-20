#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#define RVMT_TRACE_WORDS 16u
#define RVMT_TRACE_STATUS_WORD 1u
#define RVMT_TRACE_COUNT_WORD 4u
#define RVMT_TRACE_DROP_WORD 5u
#define RVMT_TRACE_READ_INDEX_WORD 6u
#define RVMT_TRACE_READ_WORD_WORD 7u

static unsigned long parse_ulong(const char *s, const char *name) {
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(s, &end, 0);
    if (errno || end == s || *end != '\0') {
        fprintf(stderr, "invalid %s: %s\n", name, s);
        exit(2);
    }
    return value;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <trace-csr-base> <records>\n", argv[0]);
        return 2;
    }

    unsigned long base = parse_ulong(argv[1], "trace-csr-base");
    unsigned long records = parse_ulong(argv[2], "records");
    unsigned long page_size = (unsigned long)sysconf(_SC_PAGESIZE);
    unsigned long page_base = base & ~(page_size - 1u);
    unsigned long page_off = base - page_base;
    unsigned long map_len = page_off + 0x1000u;

    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) {
        perror("open /dev/mem");
        return 1;
    }

    volatile uint32_t *csr = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)page_base);
    if (csr == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }
    csr = (volatile uint32_t *)((volatile uint8_t *)csr + page_off);

    uint32_t available = csr[RVMT_TRACE_COUNT_WORD];
    if (records > available) {
        records = available;
    }

    printf("RVMT_TRACE_STATUS %08" PRIx32 "\n", csr[RVMT_TRACE_STATUS_WORD]);
    printf("RVMT_TRACE_COUNT %08" PRIx32 "\n", available);
    printf("RVMT_TRACE_DROP %08" PRIx32 "\n", csr[RVMT_TRACE_DROP_WORD]);
    printf("RVMT_TRACE_RECORDS_READ %lu\n", records);
    puts("RVMT_TRACE_DUMP_BEGIN");
    for (unsigned long i = 0; i < records; ++i) {
        printf("RVMT_TRACE_RECORD %lu", i);
        for (unsigned word = 0; word < RVMT_TRACE_WORDS; ++word) {
            csr[RVMT_TRACE_READ_INDEX_WORD] = (uint32_t)(i * RVMT_TRACE_WORDS + word);
            printf(" %08" PRIx32, csr[RVMT_TRACE_READ_WORD_WORD]);
        }
        putchar('\n');
    }
    puts("RVMT_TRACE_DUMP_END");

    munmap((void *)((uintptr_t)csr - page_off), map_len);
    close(fd);
    return 0;
}
