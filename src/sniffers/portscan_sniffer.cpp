#include "portscan_sniffer.h"
#include "../utils/logging.h"
#include "../utils/utils.h"
#include "../detections/vulns.h"

Logger *logger = Logger::get_logger();


ports_t PortScanSniffer::ports;

PortScanSniffer::PortScanSniffer(Engine* engine, const std::string interface_name)
    : Sniffer(engine, "Portscan", interface_name, std::string("tcp[tcpflags] & (tcp-syn|tcp-ack) != 0")) {}


#define PORT_SCAN_THRESHOLD 100
#define PORT_SCAN_TIMEOUT_THRESHOLD 5


void PortScanSniffer::on_packet(const char* buffer, uint32_t length) {
    Packet packet;
    parse_packet(buffer, length, &packet);

    if (packet.protocol != TCP ) {
        logger->debug("packet is not tcp");
        return;
    }

    ports[packet.dest_port] = time(NULL);

    for (auto it = ports.begin(); it != ports.end();) {
        if (it->second < time(NULL) - PORT_SCAN_TIMEOUT_THRESHOLD) {
            ports.erase(it++);
        } else {
            it++;
        }
    }

    if (ports.size() > PORT_SCAN_THRESHOLD) {
        ports.clear();
        logger->info("port scan detected");
        Portscan portscan(packet.source_ip);
        this->engine->dispatch(&portscan);
    }
}
