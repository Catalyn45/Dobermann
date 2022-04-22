#ifndef _SNIFFER_H_
#define _SNIFFER_H_

#include <event2/event.h>

#include <string>
#include <vector>

enum Protocol {
    TCP,
    UDP
};

enum Family {
    IPV4,
    IPV6
};

struct Packet {
    Family family;

    std::string source_mac;
    std::string dest_mac;

    std::string source_ip;
    std::string dest_ip;

    Protocol protocol;

    uint16_t source_port;
    uint16_t dest_port;

    std::string payload;
};

int parse_packet(const char* buffer, uint32_t length, Packet* out_packet);

class Sniffer {
private:
    static std::vector<Sniffer*> sniffers;
    static event_base* base;

    friend class Engine;

protected:
    int sock;

    static uint32_t id;

    const char* name;
    const char* interface_name;
    std::string filter;

public:
    Sniffer(const char* name, const char* interface_name, std::string filter);
    int init();
    virtual void on_packet(const char* buffer, uint32_t length) = 0;
    virtual ~Sniffer();
};

#endif  // _SNIFFER_H_