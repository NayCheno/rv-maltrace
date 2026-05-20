#include <stdio.h>
#include <unistd.h>

int main(void) {
    puts("RVMT_LINUX_USER_PASS");
    fsync(STDOUT_FILENO);
    return 0;
}
