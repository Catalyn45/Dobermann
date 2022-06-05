#ifndef PORTSCAN_SNIFFER_H_
#define PORTSCAN_SNIFFER_H_

#include "sniffer.h"
#include <map>
#include <utility>
#include "../engine.h"

using ports_t = std::map<std::string, std::map<uint32_t, long>>;

class PortScanSniffer : public Sniffer {
private:
    static ports_t ports;
protected:
public:
    PortScanSniffer(Engine* engine, const std::string interface_name);
    void on_packet(const char* buffer, uint32_t length);
};

#endif // PORTSCAN_SNIFFER_H_