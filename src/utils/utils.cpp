
#include "utils.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <cctype>
#include "packets.h"
#include "logging.h"
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <regex>
#include <arpa/inet.h>


static Logger* logger = Logger::get_logger();

void util::descriptor_deleter::operator()(int* descriptor) {
    close(*descriptor);
}

const char* util::get_system_error() {
    return strerror(errno);
}

std::string util::get_escaped_packet(const char* packet, int size) {
    std::string output;
    for (int i = 0; i < size; ++i) {
        if (isprint(packet[i])) {
            output.push_back(packet[i]);
            continue;
        }

        char hexa_repr[5];

        snprintf(hexa_repr, 5, "\\%02X", (unsigned char)packet[i]);
        output.append(hexa_repr);
    }

    return output;
}

int util::parse_packet(const char* buffer, uint32_t length, Packet* out_packet) {
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

    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        logger->debug("ether type not supported");
        return -1;
    }

    uint32_t offset = sizeof(struct ether_header);

    if (length < offset + sizeof(struct iphdr)) {
        return -1;
    }

    struct iphdr* ip_header = (struct iphdr*) (buffer + offset);

    inet_ntop(AF_INET, (void*)(&ip_header->saddr), addr, sizeof(addr));
    out_packet->source_ip = std::string(addr);

    inet_ntop(AF_INET, (void*)(&ip_header->daddr), addr, sizeof(addr));
    out_packet->dest_ip = std::string(addr);

    offset += sizeof(iphdr);
    if (ip_header->protocol == IPPROTO_TCP) {
        if (length < offset + sizeof(struct tcphdr)) {
            return -1;
        }

        struct tcphdr* tcp_header = (struct tcphdr*) (buffer + offset);
        out_packet->source_port = ntohs(tcp_header->source);
        out_packet->dest_port = ntohs(tcp_header->dest);
        out_packet->protocol = Protocol::TCP;

        offset += (tcp_header->doff * sizeof(uint32_t));
        out_packet->payload = std::string (buffer + offset, buffer + length);

    } else if (ip_header->protocol == IPPROTO_UDP) {
        if (length < offset + sizeof(struct udphdr)) {
            return -1;
        }

        struct udphdr* udp_header = (struct udphdr*) (buffer + offset);
        out_packet->source_port = ntohs(udp_header->source);
        out_packet->dest_port = ntohs(udp_header->dest);
        out_packet->protocol = Protocol::UDP;

        offset += sizeof(udphdr);
        out_packet->payload = std::string(buffer + offset, buffer + length);
    } else {
        logger->debug("Protocol not supported");
        return -1;
    }

    return 0;
}

static const std::regex http_request_regex("^(GET|POST|PUT|DELETE|HEAD) (.*) HTTP/1\\.[01]\r\n");
static const std::regex http_response_regex("^HTTP/1\\.[01] (\\d+) (.*)\r\n");

static const std::regex header_regex("^([^:]+): (.*)\r\n");

int util::parse_http_packet(Packet* packet, HttpPacket* out_packet) {
    std::smatch match;

    HttpPacketType type;

    std::string method;
    std::string path;

    std::string status;
    std::string reason;

    if (std::regex_search(packet->payload, match, http_request_regex)) {
        type = HttpPacketType::HTTP_REQUEST;
        method = match[1].str();
        path = match[2].str();
    } else if (std::regex_search(packet->payload, match, http_response_regex)) {
        type = HttpPacketType::HTTP_RESPONSE;
        status = match[1].str();
        reason = match[2].str();
    } else {
        logger->debug("packet is not http");
        return -1;
    }

    auto headers = std::map<std::string, std::string>();

    std::string paylaod = packet->payload;

    while(std::regex_search(paylaod, match, header_regex)) {
        headers[match[1].str()] = match[2].str();
        paylaod = match.suffix().str();
    }

    size_t body_start = packet->payload.find("\r\n\r\n");
    if (body_start == std::string::npos) {
        logger->debug("body not found, packet is not http");
        return -1;
    }

    std::string body = packet->payload.substr(body_start + 4);

    out_packet->type = std::move(type);

    out_packet->method = std::move(method);
    out_packet->path = std::move(path);

    out_packet->status = std::move(status);
    out_packet->reason = std::move(reason);

    out_packet->headers = std::move(headers);
    out_packet->body = std::move(body);

    return 0;
}