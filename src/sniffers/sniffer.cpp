#include "sniffer.h"

#include <fcntl.h>
#include <linux/filter.h>
#include <net/if.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <net/ethernet.h>

#include "../utils/logging.h"
#include "../utils/utils.h"

#include <event2/event.h>

static Logger* logger = Logger::get_logger();

using namespace util;

static void set_nonblocking(int sock) {
    int flags;

    flags = fcntl(sock, F_GETFL, NULL);
    if (!(flags & O_NONBLOCK)) {
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    }
}

Sniffer::Sniffer(Engine* engine, const std::string name, const std::string interface_name, const std::string filter)
    : engine(engine), sock(-1), event(nullptr), name(name), interface_name(interface_name), filter(filter) {}

static void read_callback(int socket, short what, void* arg) {
    (void)what;
    Sniffer* sniffer = (Sniffer*)arg;

    char buffer[BUFFER_SIZE];

    struct sockaddr_ll addr;
    socklen_t addr_len = sizeof(addr);
    int res = recvfrom(socket, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, &addr_len);
    if (res < 0) {
        logger->error("Error reading from socket");
        return;
    }

    if (addr.sll_pkttype == PACKET_OUTGOING) {
        logger->debug("Packet is outgoing");
        return;
    }

    logger->debug("received %d bytes packet", res);
    if (res <= 0) {
        logger->error("error receiving data from socket");
        return;
    }

    sniffer->on_packet(buffer, res);
}

int Sniffer::init() {
    logger->debug("creating socket for sniffer: %s", this->name.c_str());
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1) {
        logger->error("error creating the socket: %s", get_system_error());
        return -1;
    }

    descriptor_ptr p_sock(&sock);

    logger->debug("setting socket to non-blocking on sniffer: %s", this->name.c_str());
    set_nonblocking(sock);

    int interface_index = (int)if_nametoindex(this->interface_name.c_str());
    if (interface_index == 0) {
        logger->error("error getting interface index: %s", get_system_error());
        return -1;
    }

    logger->debug("interface: %s have index: %d", this->interface_name.c_str(), interface_index);

    struct sockaddr_ll saddrll = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = interface_index,
        .sll_hatype = 0,
        .sll_pkttype = 0,
        .sll_halen = 0,
        .sll_addr = {0, 0, 0, 0, 0, 0},
    };

    logger->debug("binding socket to interface on sniffer: %s", this->name.c_str());
    int res = bind(sock, (const struct sockaddr*)&saddrll, sizeof(saddrll));
    if (res != 0) {
        logger->error("error binding the socket address: %s", get_system_error());
        return -1;
    }

    logger->debug("creating pcap handle for sniffer: %s", this->name.c_str());
    pcap_t* pc = pcap_create(this->interface_name.c_str(), NULL);
    if (!pc) {
        logger->error("error at creating pcap isntance");
        return -1;
    }

    logger->debug("activating pcap handle on sniffer: %s", this->name.c_str());
    if (pcap_activate(pc) != 0) {
        pcap_close(pc);
        logger->error("error at pcap activation");
        return -1;
    }

    if(pcap_setdirection(pc, PCAP_D_IN) != 0) {
        pcap_close(pc);
        logger->error("error at pcap set direction");
        return -1;
    }

    bpf_program program;

    logger->debug("compiling \"%s\" filter for sniifer %s", this->filter.c_str(), this->name.c_str());
    if (pcap_compile(pc, &program, this->filter.c_str(), 1, 0) != 0) {
        pcap_close(pc);
        logger->error("error at pcap compile");
        return -1;
    }

    sock_fprog kernel_filter = {
        (unsigned short)program.bf_len,
        (sock_filter*)program.bf_insns
    };

    logger->debug("setting filter on sniffer: %s", this->name.c_str());
    res = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &kernel_filter, sizeof(kernel_filter));
    pcap_freecode(&program);
    pcap_close(pc);

    if (res != 0) {
        logger->error("fail to attach filter: %s", get_system_error());
        return -1;
    }

    char buff[50];

    logger->debug("draining socket on sniffer: %s", this->name.c_str());
    while (recv(sock, buff, sizeof(buff), 0) != -1);

    logger->debug("creating event for sniffer: %s", this->name.c_str());
    struct event* read_ev = event_new(this->engine->base, sock, EV_READ | EV_PERSIST, read_callback, this);
    if (!read_ev) {
        logger->error("error at creating event");
        return -1;
    }

    p_sock.release();
    this->sock = sock;
    this->event = read_ev;
    return 0;
}

int Sniffer::start() {
    return event_add(this->event, NULL);
}

void Sniffer::stop() {
    event_del(this->event);
}

Sniffer::~Sniffer() {
    if (this->event) {
        event_free(this->event);
    }

    if(this->sock != -1) {
        close(this->sock);
    }
}
