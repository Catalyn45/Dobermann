#include "portscan_sniffer.h"
#include "../utils/logging.h"
#include "../utils/utils.h"
#include "../detections/vulns.h"
#include <utility>

static Logger *logger = Logger::get_logger();


ports_t PortScanSniffer::ports;

PortScanSniffer::PortScanSniffer(Engine* engine, const std::string interface_name)
    : Sniffer(engine, "Portscan", interface_name, std::string("(tcp[tcpflags] & (tcp-syn) != 0) && (tcp[tcpflags] & (tcp-ack) == 0)")) {}


#define PORT_SCAN_THRESHOLD 100
#define PORT_SCAN_TIMEOUT_THRESHOLD 5


void PortScanSniffer::on_packet(const char* buffer, uint32_t length) {
    Packet packet;
    parse_packet(buffer, length, &packet);

    if (packet.protocol != TCP ) {
        logger->debug("packet is not tcp");
        return;
    }
    if (ports.find(packet.source_ip) == ports.end()) {
        ports[packet.source_ip] = std::map<uint32_t, long>();
    }

    ports[packet.source_ip][packet.dest_port] = time(NULL);

    for (auto& ip : ports) {
        for (auto it = ip.second.begin(); it != ip.second.end();) {
            if ((time(NULL) - it->second) > PORT_SCAN_TIMEOUT_THRESHOLD) {
                ip.second.erase(it++);
            } else {
                it++;
            }
        }

        ports[ip.first] = ip.second;
    }

    if (ports[packet.source_ip].size() > PORT_SCAN_THRESHOLD) {
        logger->info("size: %d", ports.size());
        ports[packet.source_ip].clear();
        logger->info("port scan detected");
        Portscan portscan(packet.source_ip);
        this->engine->dispatch(&portscan);
    }
}
