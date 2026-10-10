/* SPDX-License-Identifier: Apache-2.0
 * Native FRR control transport integration test. Run in bgpd's network
 * namespace with VPP's control client disabled. No production intermediary.
 * After ADDED, inspect the two local Type-2 routes, then press Enter.
 * After DELETED, verify withdrawal, then press Enter. Finally an incompatible
 * frame must cause EOF. Tests partial frames and coalesced add/delete frames.
 * cc -Wall -Wextra -Werror -o /tmp/srv6-control test/srv6_control.c
 * ip netns exec dataplane /tmp/srv6-control 10100
 */
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "../evpn_srv6_wire.h"

static void send_all(int fd, const void *data, size_t size)
{
  const char *bytes = data;
  while (size) {
    ssize_t n = send(fd, bytes, size, MSG_NOSIGNAL);
    if (n < 0 && errno == EINTR)
      continue;
    assert(n > 0);
    bytes += n;
    size -= n;
  }
}

static int read_frame(int fd, struct evpn_srv6_msg *message)
{
  size_t used = 0;
  while (used < sizeof(*message)) {
    ssize_t n = read(fd, (char *)message + used, sizeof(*message) - used);
    if (n < 0 && errno == EINTR)
      continue;
    assert(n >= 0);
    if (!n) {
      assert(!used);
      return 0;
    }
    used += n;
  }
  assert(ntohl(message->magic) == EVPN_SRV6_MAGIC);
  assert(message->version == EVPN_SRV6_VERSION);
  return 1;
}

int main(int argc, char **argv)
{
  assert(argc == 2);
  struct sockaddr_un address = { .sun_family = AF_UNIX };
  memcpy(address.sun_path + 1, EVPN_SRV6_SOCKET, strlen(EVPN_SRV6_SOCKET));
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  assert(fd >= 0);
  struct timeval timeout = { .tv_sec = 5 };
  assert(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
  assert(!connect(fd, (struct sockaddr *)&address,
                  offsetof(struct sockaddr_un, sun_path) + 1 +
                    strlen(EVPN_SRV6_SOCKET)));
  struct evpn_srv6_msg frame;
  assert(read_frame(fd, &frame) && frame.op == EVPN_SRV6_BEGIN);
  do {
    assert(read_frame(fd, &frame));
    assert(frame.op == EVPN_SRV6_ROUTE || frame.op == EVPN_SRV6_END);
  } while (frame.op != EVPN_SRV6_END);
  struct evpn_srv6_msg updates[2] = {{
    .magic = htonl(EVPN_SRV6_MAGIC),
    .version = EVPN_SRV6_VERSION,
    .op = EVPN_SRV6_LOCAL,
    .type = 2,
    .add = 1,
    .vni = htonl((uint32_t)strtoul(argv[1], NULL, 10)),
    .key = {2, 0, 0, 255, 0, 1},
  }};
  updates[1] = updates[0];
  updates[1].key[5] = 2;
  send_all(fd, updates, 5);
  send_all(fd, (char *)updates + 5, sizeof(updates) - 5);
  puts("ADDED 02:00:00:ff:00:01 and 02:00:00:ff:00:02; Enter to delete");
  fflush(stdout);
  assert(getchar() != EOF);
  updates[0].add = updates[1].add = 0;
  send_all(fd, updates, sizeof(updates));
  puts("DELETED; Enter to test incompatible version disconnect");
  fflush(stdout);
  assert(getchar() != EOF);
  updates[0].version++;
  send_all(fd, updates, sizeof(updates[0]));
  while (read_frame(fd, &frame))
    assert(frame.op == EVPN_SRV6_ROUTE);
  close(fd);
  puts("PASS: snapshot, split/coalesced frames, incompatible version rejected");
  return 0;
}
