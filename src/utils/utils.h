#ifndef _UTILS_H_
#define _UTILS_H_

#include <memory>
#include <string>

namespace util {

struct descriptor_deleter {
    void operator()(int* descriptor);
};

using descriptor_ptr = std::unique_ptr<int, descriptor_deleter>;

const char* get_system_error();

std::string get_escaped_packet(const char* packet, int size);

}  // namespace util

#endif  // _UTILS_H_