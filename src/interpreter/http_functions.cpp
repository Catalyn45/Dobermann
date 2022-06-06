#include "../events/event.h"
#include "../utils/logging.h"
#include "vm.h"
#include <string>
#include "../utils/packets.h"
#include "vm_functions.h"

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

static int http_path_contains(const vm_args_t& script_args, const json& args) {
    HttpPacket* packet = (HttpPacket*)script_args.at("packet");
    std::vector<std::string> tokens = args["tokens"];

    for (auto& token : tokens) {
        if (packet->path.find(token) != std::string::npos) {
            return 0;
        }
    }

    return -1;
}

static int http_header_contains(const vm_args_t& script_args, const json& args) {
    HttpPacket* packet = (HttpPacket*)script_args.at("packet");
    std::vector<std::string> tokens = args["tokens"];

    for (auto& header : packet->headers) {
        for (auto& token : tokens) {
            if (header.second.find(token) != std::string::npos) {
                return 0;
            }
        }
    }

    return -1;
}

static int http_body_contains(const vm_args_t& script_args, const json& args) {
    HttpPacket* packet = (HttpPacket*)script_args.at("packet");
    std::vector<std::string> tokens = args["tokens"];

    for (auto& token : tokens) {
        if (packet->body.find(token) != std::string::npos) {
            return 0;
        }
    }

    return -1;
}

static int http_method_is(const vm_args_t& script_args, const json& args) {
    HttpPacket* packet = (HttpPacket*)script_args.at("packet");
    std::string method = args["method"];

    if (packet->method == method) {
        return 0;
    }

    return -1;
}

int load_http_functions(VirtualMachine* vm) {
    return vm->register_functions(
        vm_functions_t({
            {"http_packet_contains", http_packet_contains},
            {"http_path_contains", http_path_contains},
            {"http_header_contains", http_header_contains},
            {"http_body_contains", http_body_contains},
            {"http_method_is", http_method_is}
        })
    );
}