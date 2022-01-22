
#include "utils.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <cctype>

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