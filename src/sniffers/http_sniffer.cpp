#include "http_sniffer.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string>

#include "../utils/logging.h"
#include "../utils/utils.h"
#include "../repositories/local_repository.h"

static Logger* logger = Logger::get_logger();

HttpSniffer::HttpSniffer(Engine* engine, const std::string interface_name, uint16_t port)
    : Sniffer(engine, "Http", std::move(interface_name), std::string("ip && tcp && dst port ") +
                                                 std::to_string(port)) {
    this->repository = new LocalRepository("./http_scripts.json");
}

HttpSniffer::~HttpSniffer() {
    delete this->repository;
}

int HttpSniffer::init() {
    this->scripts = this->repository->get_http_scripts();
    return Sniffer::init();
}

void HttpSniffer::on_packet(const char* buffer, uint32_t length) {
    Packet packet;
    if (util::parse_packet(buffer, length, &packet) != 0) {
        logger->debug("error parsing packet");
        return;
    }

    if (packet.protocol != Protocol::TCP) {
        logger->debug("packet is not tcp");
        return;
    }

    HttpPacket http_packet;
    if(util::parse_http_packet(&packet, &http_packet) != 0) {
        logger->debug("error parsing http packet");
        return;
    }

    vm_args_t script_args = {
        {"packet", &http_packet}
    };

    for (auto& script : this->scripts) {
        logger->debug("running scripts");
        Event* event = this->engine->vm.run_script(script, script_args);
        if (event != nullptr) {
            event->ip = packet.source_ip;
            this->engine->dispatch(event);
            delete event;
        }
    }
}