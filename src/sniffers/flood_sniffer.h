#ifndef FLOOD_SNIFFER_H_
#define FLOOD_SNIFFER_H_

#include "../engine.h"
#include "sniffer.h"
#include <map>

struct ip_syn_info {
    uint32_t syn_count;
    long first_syn_time;
};

using syn_ips_t = std::map<std::string, ip_syn_info>;

class FloodSniffer : public Sniffer {
private:
    syn_ips_t syn_ips;
protected:
public:
    FloodSniffer(Engine* engine, const std::string interface_name, uint16_t port);
    void on_packet(const char* buffer, uint32_t length);
};

#endif // FLOOD_SNIFFER_H_