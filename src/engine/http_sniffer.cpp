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
    : Sniffer("HttpSniffer") {}

#define BUFFER_SIZE 250

void HttpSniffer::read(const char* buffer, uint32_t length) {
    logger->info("got packet on sniffer %s : %s", this->name.c_str(), get_escaped_packet(buffer, length).c_str());
}

const char* HttpSniffer::get_filter() {
    return "ip && tcp && dst port 8081";
}