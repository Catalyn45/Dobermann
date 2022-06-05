#include "flood_sniffer.h"
#include "../events/vulns.h"
#include "../utils/logging.h"
#include "../utils/packets.h"
#include "../utils/utils.h"

FloodSniffer::FloodSniffer(const Engine* engine, const std::string& interface_name, uint16_t port)
    : Sniffer(engine, "Flood", interface_name, std::string("(tcp[tcpflags] & (tcp-syn) != 0) && (tcp[tcpflags] & (tcp-ack) == 0) && dst port ") + std::to_string(port)), syn_ips() {}

static Logger *logger = Logger::get_logger();

#define FLOOD_THRESHOLD 20
#define FLOOD_TIMEOUT_THRESHOLD 2

void FloodSniffer::on_packet(const char* buffer, uint32_t length) {
    Packet packet;
    if (util::parse_packet(buffer, length, &packet) != 0) {
        return;
    }

    if (this->syn_ips.find(packet.source_ip) == this->syn_ips.end()) {
        this->syn_ips[packet.source_ip] = ip_syn_info{0, time(NULL)};
    }

    ip_syn_info info = this->syn_ips[packet.source_ip];

    if((time(NULL) - info.first_syn_time) > FLOOD_TIMEOUT_THRESHOLD) {
        this->syn_ips.erase(packet.source_ip);
        return;
    }

    info.syn_count++;
    this->syn_ips[packet.source_ip] = info;

    if (info.syn_count > FLOOD_THRESHOLD) {
        this->syn_ips.erase(packet.source_ip);
        Flood flood(packet.source_ip);
        this->engine->dispatch(&flood);
    }
}