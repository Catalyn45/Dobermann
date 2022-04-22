#include "http_sniffer.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string>

#include "../utils/logging.h"
#include "../utils/utils.h"
#include <map>
#include <regex>

static Logger* logger = Logger::get_logger();
using namespace util;

struct HttpPacket {
    std::string method;
    std::string path;
    std::map<std::string, std::string> headers;
    std::string body;
};

static const std::regex http_regex("^(GET|POST|PUT|DELETE|HEAD) (.*) HTTP/1\\.[01]\r\n");
static const std::regex header_regex("^([^:]+): (.*)\r\n");

static int parse_http_packet(const char* buffer, uint32_t length, HttpPacket* out_packet) {
    Packet packet;

    int res = parse_packet(buffer, length, &packet);
    if (res != 0) {
        logger->debug("error parsing packet");
        return res;
    }

    if (packet.protocol != Protocol::TCP) {
        logger->info("packet is not tcp");
        return -1;
    }

    std::smatch match;

    std::string method = std::regex_search(packet.payload, match, http_regex) ? match[1].str() : "";
    if (method == "") {
        logger->debug("method or path not found, packet is not http");
        return -1;
    }

    std::string path = match[2].str();
    auto headers = std::map<std::string, std::string>();
    
    std::string paylaod = packet.payload;

    while(std::regex_search(paylaod, match, header_regex)) {
        headers[match[1].str()] = match[2].str();
        paylaod = match.suffix().str();
    }

    size_t body_start = packet.payload.find("\r\n\r\n");
    if (body_start == std::string::npos) {
        logger->info("body not found, packet is not http");
        return -1;
    }

    std::string body = packet.payload.substr(body_start + 4);

    out_packet->method = std::move(method);
    out_packet->path = std::move(path);
    out_packet->headers = std::move(headers);
    out_packet->body = std::move(body);

    return 0;
}


HttpSniffer::HttpSniffer(const char* interface_name, uint16_t port)
    : Sniffer("Http", interface_name, std::string("ip && tcp && dst port ") + std::to_string(port)) {}


void HttpSniffer::on_packet(const char* buffer, uint32_t length) {
    HttpPacket packet;
    if(parse_http_packet(buffer, length, &packet) != 0) {
        return;
    }
    
    logger->info("Got http packet %s %s", packet.method.c_str(), packet.path.c_str());
}