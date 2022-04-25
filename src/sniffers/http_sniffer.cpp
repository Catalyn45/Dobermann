#include "http_sniffer.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string>

#include "../utils/logging.h"
#include "../utils/utils.h"
#include "../detections/http_detections.h"
#include <regex>

static Logger* logger = Logger::get_logger();

static const std::regex http_request_regex("^(GET|POST|PUT|DELETE|HEAD) (.*) HTTP/1\\.[01]\r\n");
static const std::regex http_response_regex("^HTTP/1\\.[01] (\\d+) (.*)\r\n");

static const std::regex header_regex("^([^:]+): (.*)\r\n");

static int parse_http_packet(const char* buffer, uint32_t length, HttpPacket* out_packet) {
    Packet packet;
    if (parse_packet(buffer, length, &packet) != 0) {
        logger->debug("error parsing packet");
        return -1;
    }

    if (packet.protocol != Protocol::TCP) {
        logger->debug("packet is not tcp");
        return -1;
    }

    std::smatch match;

    HttpPacketType type;

    std::string method;
    std::string path;

    std::string status;
    std::string reason;

    if (std::regex_search(packet.payload, match, http_request_regex)) {
        type = HttpPacketType::HTTP_REQUEST;
        method = match[1].str();
        path = match[2].str();
    } else if (std::regex_search(packet.payload, match, http_response_regex)) {
        type = HttpPacketType::HTTP_RESPONSE;
        status = match[1].str();
        reason = match[2].str();
    } else {
        logger->debug("packet is not http");
        return -1;
    }

    auto headers = std::map<std::string, std::string>();
    
    std::string paylaod = packet.payload;

    while(std::regex_search(paylaod, match, header_regex)) {
        headers[match[1].str()] = match[2].str();
        paylaod = match.suffix().str();
    }

    size_t body_start = packet.payload.find("\r\n\r\n");
    if (body_start == std::string::npos) {
        logger->debug("body not found, packet is not http");
        return -1;
    }

    std::string body = packet.payload.substr(body_start + 4);

    out_packet->type = std::move(type);

    out_packet->method = std::move(method);
    out_packet->path = std::move(path);

    out_packet->status = std::move(status);
    out_packet->reason = std::move(reason);

    out_packet->headers = std::move(headers);
    out_packet->body = std::move(body);

    return 0;
}


HttpSniffer::HttpSniffer(Engine* engine, const std::string interface_name, uint16_t port)
    : Sniffer(engine, "Http", std::move(interface_name), std::string("ip && tcp && dst port ") +
                                                 std::to_string(port)) {}

extern http_static_detection_t http_static_detections[];

void HttpSniffer::on_packet(const char* buffer, uint32_t length) {
    HttpPacket packet;
    if(parse_http_packet(buffer, length, &packet) != 0) {
        return;
    }

    CVE cve;
    for(int i = 0; http_static_detections[i] != NULL; i++) {
        if(!http_static_detections[i](&packet, &cve)) {
            continue;
        }

        this->engine->dispatch(&cve);
    }
}