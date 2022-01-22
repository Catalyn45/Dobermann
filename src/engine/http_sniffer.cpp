#include "http_sniffer.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../utils/logging.h"
#include "../utils/utils.h"

static Logger* logger = Logger::get_logger();

using namespace util;

HttpSniffer::HttpSniffer()
    : Sniffer("HttpSniffer") {
}

void HttpSniffer::read(const char* buffer, uint32_t length) {
    static bool first = true;
    std::string output = get_escaped_packet(buffer, length);
    this->cache_buffer.append(output);

    if (this->cache_buffer.find("HTTP") != std::string::npos) {
        logger->info("Found http packet");
        this->cache_buffer.clear();
    }

    if (first) {
        first = false;
        return;
    }

    std::string new_buffer = std::string(this->cache_buffer.c_str() + (this->cache_buffer.length() / 2));
    this->cache_buffer = new_buffer;
}

const char* HttpSniffer::get_filter() {
    return "ip && tcp && dst port 8081";
}