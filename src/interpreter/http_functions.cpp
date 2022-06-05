#include "../events/event.h"
#include "../utils/logging.h"
#include "vm.h"
#include <string>
#include "../utils/packets.h"

static int header_contains(vm_args_t& script_args, json args) {
    HttpPacket* packet = (HttpPacket*)script_args["packet"];
    std::vector<std::string> tokens = args["tokens"];

    for (auto& token : tokens) {
        if (packet->path.find(token.c_str()) != std::string::npos) {
            return 0;
        }

        for (auto& header : packet->headers) {
            if (header.second.find(token.c_str()) != std::string::npos) {
                return 0;
            }
        }
    }

    return -1;
}

vm_functions_t http_functions_map = {
    {"header_contains", header_contains}
};
