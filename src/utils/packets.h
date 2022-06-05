#ifndef PACKETS_H_
#define PACKETS_H_

#include <map>

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

enum HttpPacketType {
    HTTP_REQUEST,
    HTTP_RESPONSE
};

struct HttpPacket {
    HttpPacketType type;

    std::string method;
    std::string path;

    std::string status;
    std::string reason;

    std::map<std::string, std::string> headers;
    std::string body;
};

#endif // PACKETS_H_