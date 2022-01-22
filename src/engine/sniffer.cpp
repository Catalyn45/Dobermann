#include "sniffer.h"

#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../utils/logging.h"
#include "../utils/utils.h"

static Logger* logger = Logger::get_logger();

using namespace util;

uint32_t Sniffer::id{0};
std::vector<Sniffer*> Sniffer::sniffers{};

static void set_nonblocking(int sock) {
    int flags;

    flags = fcntl(sock, F_GETFL, NULL);
    if (!(flags & O_NONBLOCK)) {
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    }
}

Sniffer::Sniffer(const char* name)
    : name(name) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1) {
        logger->error("Error creating the socket: %s", get_system_error());
        return;
    }

    descriptor_ptr p_sock(&sock);

    set_nonblocking(sock);

    // clang-format off
    struct sockaddr_ll saddrll = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = if_nametoindex("eth1")
    };
    // clang-format on

    logger->info("binding socket to interface");
    int res = bind(sock, (const struct sockaddr*)&saddrll, sizeof(saddrll));
    if (res != 0) {
        logger->error("Error binding the socket address: %s", get_system_error());
        return;
    }

    ++id;

    p_sock.release();
    this->sock = sock;
}

void Sniffer::init() {
    pcap_t* pc = pcap_create("eth1", NULL);
    if (!pc) {
        logger->error("Error at creating pcap isntance");
        return;
    }

    if (pcap_activate(pc) != 0) {
        logger->error("Error at pcap activation");
        return;
    }

    const char* filter = this->get_filter();

    bpf_program program;

    logger->info("compiling %s filter", filter);
    if (pcap_compile(pc, &program, filter, 1, 0) != 0) {
        logger->error("Error at pcap compile");
        return;
    }

    // clang-format off
    sock_fprog kernel_filter = {
        program.bf_len,
        (sock_filter*)program.bf_insns
    };
    // clang-format on

    int res = setsockopt(this->sock, SOL_SOCKET, SO_ATTACH_FILTER, &kernel_filter, sizeof(kernel_filter));
    pcap_freecode(&program);

    if (res != 0) {
        logger->error("fail to attach filter: %s", get_system_error());
        return;
    }

    char buff[50];
    while (recv(this->sock, buff, sizeof(buff), 0) != -1)
        ;
}

Sniffer::~Sniffer() {
    close(this->sock);
}
