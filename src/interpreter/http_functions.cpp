#include "../events/event.h"
#include "../utils/logging.h"
#include "vm.h"
#include <string>
#include "../utils/packets.h"

static int http_packet_contains(const vm_args_t& script_args, const json& args) {
    HttpPacket* packet = (HttpPacket*)script_args.at("packet");
    std::vector<std::string> tokens = args["tokens"];

    for (auto& token : tokens) {
        if (packet->path.find(token) != std::string::npos) {
            return 0;
        }

        for (auto& header : packet->headers) {
            if (header.second.find(token) != std::string::npos) {
                return 0;
            }
        }

        if (packet->body.find(token) != std::string::npos) {
            return 0;
        }
    }

    return -1;
}

vm_functions_t http_functions_map = {
    {"http_packet_contains", http_packet_contains}
};
