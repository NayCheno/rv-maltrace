#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static const char *fixture_path(void) {
    const char *root = getenv("RVMT_FIXTURE_ROOT");
    if (root == NULL || root[0] == '\0') {
        return "experiments/linux_behavior/benign/fixtures/input.txt";
    }

    static char path[512];
    snprintf(path, sizeof(path), "%s/input.txt", root);
    return path;
}

static int copy_fd(int in_fd, int out_fd, int also_stdout) {
    char buffer[256];
    for (;;) {
        ssize_t count = read(in_fd, buffer, sizeof(buffer));
        if (count < 0) {
            perror("read");
            return 1;
        }
        if (count == 0) {
            return 0;
        }
        if (also_stdout && write(STDOUT_FILENO, buffer, (size_t)count) != count) {
            perror("write stdout");
            return 1;
        }
        if (out_fd >= 0 && write(out_fd, buffer, (size_t)count) != count) {
            perror("write output");
            return 1;
        }
    }
}

static int run_hello(void) {
    static const char message[] = "rv-maltrace benign hello\n";
    return write(STDOUT_FILENO, message, sizeof(message) - 1) == (ssize_t)(sizeof(message) - 1) ? 0 : 1;
}

static int run_ls(void) {
    char buffer[1024];
    int fd = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        perror("open /tmp");
        return 1;
    }

    for (;;) {
        int count = (int)syscall(SYS_getdents64, fd, buffer, sizeof(buffer));
        if (count < 0) {
            perror("getdents64");
            close(fd);
            return 1;
        }
        if (count == 0) {
            break;
        }
        int offset = 0;
        while (offset < count) {
            struct linux_dirent64 {
                uint64_t d_ino;
                int64_t d_off;
                unsigned short d_reclen;
                unsigned char d_type;
                char d_name[];
            };
            struct linux_dirent64 *entry = (struct linux_dirent64 *)(buffer + offset);
            dprintf(STDOUT_FILENO, "%s\n", entry->d_name);
            offset += entry->d_reclen;
        }
    }

    close(fd);
    return 0;
}

static int run_cat(void) {
    int fd = open(fixture_path(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        perror("open input");
        return 1;
    }
    int rc = copy_fd(fd, -1, 1);
    close(fd);
    return rc;
}

static int run_cp(void) {
    int in_fd = open(fixture_path(), O_RDONLY | O_CLOEXEC);
    if (in_fd < 0) {
        perror("open input");
        return 1;
    }
    int out_fd = open("/tmp/rvmt_benign_copy.txt", O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
    if (out_fd < 0) {
        perror("open copy output");
        close(in_fd);
        return 1;
    }
    int rc = copy_fd(in_fd, out_fd, 0);
    close(out_fd);
    close(in_fd);
    return rc;
}

static int run_file_hash(void) {
    int fd = open(fixture_path(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        perror("open input");
        return 1;
    }

    uint64_t hash = 1469598103934665603ull;
    char buffer[256];
    for (;;) {
        ssize_t count = read(fd, buffer, sizeof(buffer));
        if (count < 0) {
            perror("read input");
            close(fd);
            return 1;
        }
        if (count == 0) {
            break;
        }
        for (ssize_t i = 0; i < count; ++i) {
            hash ^= (unsigned char)buffer[i];
            hash *= 1099511628211ull;
        }
    }
    close(fd);
    printf("%016llx  %s\n", (unsigned long long)hash, fixture_path());
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <hello|ls|cat|cp|sha256sum>\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "hello") == 0) {
        return run_hello();
    }
    if (strcmp(argv[1], "ls") == 0) {
        return run_ls();
    }
    if (strcmp(argv[1], "cat") == 0) {
        return run_cat();
    }
    if (strcmp(argv[1], "cp") == 0) {
        return run_cp();
    }
    if (strcmp(argv[1], "sha256sum") == 0) {
        return run_file_hash();
    }
    fprintf(stderr, "unknown benign workload: %s\n", argv[1]);
    return 2;
}
