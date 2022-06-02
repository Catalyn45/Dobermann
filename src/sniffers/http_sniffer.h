#ifndef _HTTP_SNIFFER_H_
#define _HTTP_SNIFFER_H_

#include "sniffer.h"
#include <map>
#include <string>

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

class HttpSniffer : public Sniffer {
private:
    std::string cache_buffer;

protected:
    void on_packet(const char* buffer, uint32_t length);
public:
    HttpSniffer(Engine* engine, const std::string interface_name, uint16_t port);
};

#endif  // _HTTP_SNIFFER_H_