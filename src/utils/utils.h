#ifndef _UTILS_H_
#define _UTILS_H_

#include <memory>
#include <string>
#include "packets.h"

#define BUFFER_SIZE 255

namespace util {

struct descriptor_deleter {
    void operator()(int* descriptor);
};

using descriptor_ptr = std::unique_ptr<int, descriptor_deleter>;

const char* get_system_error();
std::string get_escaped_packet(const char* packet, int size);

int parse_packet(const char* buffer, uint32_t length, Packet* out_packet);
int parse_http_packet(Packet* packet, HttpPacket* out_packet);

}  // namespace util

#endif  // _UTILS_H_