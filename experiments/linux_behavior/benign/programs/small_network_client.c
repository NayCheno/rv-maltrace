#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static uint16_t parse_port(const char *text) {
  char *end = NULL;
  long value = strtol(text, &end, 10);
  if (end == text || *end != '\0' || value <= 0 || value > 65535) {
    return 0;
  }
  return (uint16_t)value;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    return 2;
  }

  uint16_t port = parse_port(argv[2]);
  if (port == 0) {
    return 3;
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (inet_pton(AF_INET, argv[1], &addr.sin_addr) != 1) {
    return 4;
  }

  long fd = syscall(SYS_socket, AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return 5;
  }
  if (syscall(SYS_connect, (int)fd, &addr, sizeof(addr)) < 0) {
    syscall(SYS_close, (int)fd);
    return 6;
  }

  static const char message[] = "rv-maltrace benign network client\n";
  syscall(SYS_write, (int)fd, message, sizeof(message) - 1);

  char buffer[64];
  syscall(SYS_read, (int)fd, buffer, sizeof(buffer));
  syscall(SYS_close, (int)fd);
  return 0;
}
