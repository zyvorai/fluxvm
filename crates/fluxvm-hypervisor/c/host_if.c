#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

int flux_ioctl(int fd, unsigned long req, void *arg) {
    return ioctl(fd, req, arg);
}

/* multi_queue != 0 opens one queue of a multi-queue TAP (IFF_MULTI_QUEUE);
 * call it once per queue pair with the same name. The TAP device must have
 * been created multi_queue (or be created by the first call). */
int flux_tap_open_mq(const char *name, int multi_queue) {
    int fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd < 0)
        return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (multi_queue)
        ifr.ifr_flags |= IFF_MULTI_QUEUE;
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int flux_tap_open(const char *name) {
    return flux_tap_open_mq(name, 0);
}

int flux_if_up(const char *name) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
        close(s);
        return -1;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    int r = ioctl(s, SIOCSIFFLAGS, &ifr);
    close(s);
    return r;
}

int flux_if_addr(const char *name, uint32_t addr_be, uint32_t mask_be) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);

    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = addr_be;
    if (ioctl(s, SIOCSIFADDR, &ifr) < 0) {
        close(s);
        return -1;
    }
    sin->sin_addr.s_addr = mask_be;
    int r = ioctl(s, SIOCSIFNETMASK, &ifr);
    close(s);
    return r;
}

int flux_errno(void) { return errno; }
