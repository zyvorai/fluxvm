// SPDX-License-Identifier: Apache-2.0
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define FLUXVM_IOC_MAGIC 0xF5
struct fluxvm_bulk_test { uint32_t length; uint8_t value; uint8_t op; uint8_t reserved[2]; uint32_t crc32; };
#define FLUXVM_IOC_BULK_TEST _IOWR(FLUXVM_IOC_MAGIC, 1, struct fluxvm_bulk_test)

static int call_json(const char *dev, const char *json) {
    int fd = open(dev, O_RDWR | O_CLOEXEC); char buf[1<<20]; ssize_t n;
    if (fd < 0) { perror(dev); return 1; }
    if (write(fd, json, strlen(json)) < 0) { perror("write"); close(fd); return 1; }
    n = read(fd, buf, sizeof(buf)-1); if (n < 0) { perror("read"); close(fd); return 1; }
    buf[n] = 0; puts(buf); close(fd); return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s ping|capabilities|stats|echo TEXT|bulk-test|bulk-zero-test|bulk-copy-test|bulk-crc-test [bytes] [value]\n", argv[0]);
        return 2;
    }
    if (!strcmp(argv[1], "ping"))
        return call_json("/dev/fluxvm", "{\"version\":1,\"request_id\":\"cli\",\"operation\":\"ping\"}");
    if (!strcmp(argv[1], "capabilities"))
        return call_json("/dev/fluxvm", "{\"version\":1,\"request_id\":\"cli\",\"operation\":\"capabilities\"}");
    if (!strcmp(argv[1], "stats"))
        return call_json("/dev/fluxvm", "{\"version\":1,\"request_id\":\"cli\",\"operation\":\"stats\"}");
    if (!strcmp(argv[1], "echo") && argc == 3) {
        char *json = malloc(strlen(argv[2]) + 160);
        if (!json) return 1;
        /* Test helper only: reject characters that would need JSON escaping. */
        if (strpbrk(argv[2], "\\\"") != NULL) { fprintf(stderr, "echo text may not contain quote/backslash\n"); free(json); return 2; }
        sprintf(json, "{\"version\":1,\"request_id\":\"cli\",\"operation\":\"echo\",\"payload\":{\"text\":\"%s\"}}", argv[2]);
        int r = call_json("/dev/fluxvm", json); free(json); return r;
    }
    static const struct { const char *name; uint8_t op; const char *what; } bulk[] = {
        { "bulk-test", 0, "fill" }, { "bulk-zero-test", 1, "zero" },
        { "bulk-copy-test", 2, "copy" }, { "bulk-crc-test", 3, "crc32" },
    };
    for (unsigned i = 0; i < sizeof(bulk) / sizeof(bulk[0]); i++) {
        if (strcmp(argv[1], bulk[i].name)) continue;
        struct fluxvm_bulk_test t = { .length = argc > 2 ? strtoul(argv[2],0,0) : 65536,
                                      .value = argc > 3 ? strtoul(argv[3],0,0) : 0x5a,
                                      .op = bulk[i].op };
        int fd = open("/dev/fluxvm-bulk", O_RDWR | O_CLOEXEC);
        if (fd < 0) { perror("/dev/fluxvm-bulk"); return 1; }
        if (ioctl(fd, FLUXVM_IOC_BULK_TEST, &t) < 0) { perror("FLUXVM_IOC_BULK_TEST"); close(fd); return 1; }
        printf("bulk %s verified: bytes=%u value=%u crc32=%08x\n", bulk[i].what, t.length, t.value, t.crc32);
        close(fd); return 0;
    }
    fprintf(stderr, "unknown command\n"); return 2;
}
