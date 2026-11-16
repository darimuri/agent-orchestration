#define _GNU_SOURCE 1
/* Test-only fixed, bounded syscall denial profile. Not Node, not a validator.
 * Future owner launcher places this binary in a separately hashed fixture slot.
 * No command/path/environment input and no resource exhaustion outside a fixture.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
static int denied_socket(int domain, int type) {
  int fd = socket(domain, type, 0);
  if (fd >= 0) { (void)close(fd); return 0; }
  return errno == EPERM || errno == EACCES;
}
int main(int argc, char **argv) {
  struct stat s; int kind = 0; socklen_t length = sizeof(kind);
  (void)argv;
  /* Refuse ambient standalone execution; do not use caller env as an enable flag.
   * These checks are necessary fixture shape, NEVER proof of qualified admission. */
  if (argc != 1 || getuid() != 10002 || geteuid() != 10002 ||
      fstat(3, &s) != 0 || !S_ISSOCK(s.st_mode) ||
      getsockopt(3, SOL_SOCKET, SO_TYPE, &kind, &length) != 0 || kind != SOCK_SEQPACKET ||
      fstat(4, &s) != 0 || !S_ISREG(s.st_mode) || s.st_size != 496 ||
      fcntl(4, F_GET_SEALS) != (F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE)) return 70;
  if (!denied_socket(AF_INET, SOCK_STREAM) || !denied_socket(AF_INET6, SOCK_DGRAM) ||
      !denied_socket(AF_UNIX, SOCK_SEQPACKET)) return 71;
  /* Send a dummy held capsule FD only on the already private fixture socket.
   * A broken policy may transfer it, so the future owner must treat any success
   * as REQUEST_CHANGES and retain the failed case. */
  char data = 'X'; struct iovec iov = { .iov_base = &data, .iov_len = 1 };
  union { struct cmsghdr alignment; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control;
  memset(&control, 0, sizeof(control));
  struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes) };
  struct cmsghdr *header = CMSG_FIRSTHDR(&msg); if (header == NULL) return 70;
  header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS; header->cmsg_len = CMSG_LEN(sizeof(int));
  int capsule_fd = 4; memcpy(CMSG_DATA(header), &capsule_fd, sizeof(capsule_fd));
  if (sendmsg(3, &msg, MSG_DONTWAIT|MSG_NOSIGNAL) >= 0 || (errno != EPERM && errno != EACCES)) return 71;
  /* A denial record from this binary alone is not host PASS. SCM_RIGHTS,
   * canaries, descendants, exhaustion and crash cases remain separate gates. */
  static const char record[] = "AGE30 driver socket/rights-denial observation only\n";
  if (write(1, record, sizeof(record)-1U) != (ssize_t)(sizeof(record)-1U)) return 70;
  return 0;
}
