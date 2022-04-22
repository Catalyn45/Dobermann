#ifndef _HTTP_SNIFFER_H_
#define _HTTP_SNIFFER_H_

#include "sniffer.h"

class HttpSniffer : public Sniffer {
private:
    std::string cache_buffer;

protected:
    void on_packet(const char* buffer, uint32_t length);
public:
    HttpSniffer(const char* interface_name, uint16_t port);
};

#endif  // _HTTP_SNIFFER_H_