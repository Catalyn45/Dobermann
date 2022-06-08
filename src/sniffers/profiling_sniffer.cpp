#include "profiling_sniffer.h"
#include "../utils/logging.h"
#include "../utils/packets.h"
#include "../utils/utils.h"
#include <string>
#include "../repositories/repository.h"
#include "../repositories/local_repository.h"
#include "../repositories/remote_repository.h"
#include "../utils/logging.h"
#include <regex>
#include "../events/vulns.h"

static Logger* logger = Logger::get_logger();

ProfilingSniffer::ProfilingSniffer(const Engine* engine, const std::string& interface_name, uint16_t port)
    : Sniffer(engine, "Profiling Sniffer", interface_name, std::string("(tcp || udp) && port ") + std::to_string(port)), services_count(0), last_service_sent_time(0), last_patterns() {
    // this->repository = new LocalRepository("./profiling_patterns.json");
    this->repository = new RemoteRepository("http://localhost:3000/profiling_patterns");
}

ProfilingSniffer::~ProfilingSniffer() {
    delete this->repository;
}

#define SERVICE_PROFILING_TRESHOLD 3
#define SERVICE_PROFILING_TRESHOLD_TIMEOUT 5

void ProfilingSniffer::on_packet(const char* buffer, uint32_t length) {
    Packet packet;
    if (util::parse_packet(buffer, length, &packet) != 0) {
        logger->debug("Failed to parse packet");
        return;
    }

    if (this->services_count > 0 && (time(NULL) - this->last_service_sent_time > SERVICE_PROFILING_TRESHOLD_TIMEOUT)) {
        this->services_count = 0;
        this->last_service_sent_time = time(NULL);
        this->last_patterns.clear();
    }

    if(this->last_patterns.empty()) {
        if (packet.protocol == Protocol::TCP) {
            this->last_patterns = this->repository->get_tcp_patterns();
        } else if (packet.protocol == Protocol::UDP) {
            this->last_patterns = this->repository->get_udp_patterns();
        }
    }

    for (auto pattern = this->last_patterns.begin(); pattern != this->last_patterns.end(); ++pattern) {
        std::regex regex(*pattern);
        std::smatch match;
        std::regex_search(packet.payload, match, regex);
        if (match.size() > 0) {
            this->services_count++;
            this->last_service_sent_time = time(NULL);
            this->last_patterns.erase(pattern);
            break;
        }
    }

    if (this->services_count >= SERVICE_PROFILING_TRESHOLD) {
        this->engine->dispatch(new PortProfiling(packet.source_ip));
        this->services_count = 0;
        this->last_patterns.clear();
    }
}