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
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>


static Logger* logger = Logger::get_logger();

using namespace util;

uint32_t Sniffer::id{0};
std::vector<Sniffer*> Sniffer::sniffers{};

int parse_packet(const char* buffer, uint32_t length, Packet* out_packet) {
    if (length < sizeof(struct ether_header)) {
        return -1;
    }

    struct ether_header* eth_header = (struct ether_header*) buffer;
    char addr[40];

    sprintf(addr, "%02x:%02x:%02x:%02x:%02x:%02x",
            eth_header->ether_shost[0],
            eth_header->ether_shost[1],
            eth_header->ether_shost[2],
            eth_header->ether_shost[3],
            eth_header->ether_shost[4],
            eth_header->ether_shost[5]);
    out_packet->source_mac = std::string(addr);

    sprintf(addr, "%02x:%02x:%02x:%02x:%02x:%02x",
            eth_header->ether_dhost[0],
            eth_header->ether_dhost[1],
            eth_header->ether_dhost[2],
            eth_header->ether_dhost[3],
            eth_header->ether_dhost[4],
            eth_header->ether_dhost[5]);

    out_packet->dest_mac = std::string(addr);

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        if (length < sizeof(struct ether_header) + sizeof(struct iphdr)) {
            return -1;
        }

        struct iphdr* ip_header = (struct iphdr*) (buffer + sizeof(struct ether_header));

        inet_ntop(AF_INET, (void*)(&ip_header->saddr), addr, sizeof(addr));
        out_packet->source_ip = std::string(addr);

        inet_ntop(AF_INET, (void*)(&ip_header->daddr), addr, sizeof(addr));
        out_packet->dest_ip = std::string(addr);

        if (ip_header->protocol == IPPROTO_TCP) {
            if (length < sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr)) {
                return -1;
            }

            struct tcphdr* tcp_header = (struct tcphdr*) (buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
            out_packet->source_port = ntohs(tcp_header->source);
            out_packet->dest_port = ntohs(tcp_header->dest);
            out_packet->protocol = Protocol::TCP;

            uint32_t headers_len = sizeof(struct ether_header) + sizeof(struct iphdr) + (tcp_header->doff * sizeof(uint32_t));
            out_packet->payload = std::string (buffer + headers_len, buffer + length);

        } else if (ip_header->protocol == IPPROTO_UDP) {
            if (length < sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr)) {
                return -1;
            }

            struct udphdr* udp_header = (struct udphdr*) (buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
            out_packet->source_port = ntohs(udp_header->source);
            out_packet->dest_port = ntohs(udp_header->dest);
            out_packet->protocol = Protocol::UDP;

            uint32_t headers_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr);
            out_packet->payload = std::string(buffer + headers_len);
        } else {
            return -1;
        }
    }

    return 0;
}

static void set_nonblocking(int sock) {
    int flags;

    flags = fcntl(sock, F_GETFL, NULL);
    if (!(flags & O_NONBLOCK)) {
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    }
}

Sniffer::Sniffer(const char* name, const char* interface_name, std::string filter)
    : name(name), interface_name(interface_name), filter(filter), sock(-1) {}

int Sniffer::init() {
    logger->debug("creating socket for sniffer: %s", name);
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1) {
        logger->error("error creating the socket: %s", get_system_error());
        return 1;
    }

    descriptor_ptr p_sock(&sock);

    logger->debug("setting socket to non-blocking on sniffer: %s", name);
    set_nonblocking(sock);

    int interface_index = (int)if_nametoindex(this->interface_name);
    if (interface_index == 0) {
        logger->error("error getting interface index: %s", get_system_error());
        return 1;
    }
    
    logger->debug("interface: %s have index: %d", this->interface_name, interface_index);

    // clang-format off
    struct sockaddr_ll saddrll = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = interface_index
    };
    // clang-format on

    logger->debug("binding socket to interface on sniffer: %s", name);
    int res = bind(sock, (const struct sockaddr*)&saddrll, sizeof(saddrll));
    if (res != 0) {
        logger->error("error binding the socket address: %s", get_system_error());
        return 1;
    }

    ++id;

    logger->debug("creating pcap handle for sniffer: %s", name);
    pcap_t* pc = pcap_create(this->interface_name, NULL);
    if (!pc) {
        logger->error("error at creating pcap isntance");
        return 1;
    }

    logger->debug("activating pcap handle on sniffer: %s", name);
    if (pcap_activate(pc) != 0) {
        logger->error("error at pcap activation");
        return 1;
    }

    bpf_program program;

    logger->debug("compiling \"%s\" filter for sniifer %s", this->filter.c_str(), name);
    if (pcap_compile(pc, &program, this->filter.c_str(), 1, 0) != 0) {
        logger->error("error at pcap compile");
        return 1;
    }

    // clang-format off
    sock_fprog kernel_filter = {
        (unsigned short)program.bf_len,
        (sock_filter*)program.bf_insns
    };
    // clang-format on

    logger->debug("setting filter on sniffer: %s", name);
    res = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &kernel_filter, sizeof(kernel_filter));
    pcap_freecode(&program);

    if (res != 0) {
        logger->error("fail to attach filter: %s", get_system_error());
        return 1;
    }

    char buff[50];

    logger->debug("draining socket on sniffer: %s", name);
    while (recv(sock, buff, sizeof(buff), 0) != -1)
        ;

    p_sock.release();
    this->sock = sock;

    return 0;
}

Sniffer::~Sniffer() {
    if(this->sock != -1)
        close(this->sock);
}
