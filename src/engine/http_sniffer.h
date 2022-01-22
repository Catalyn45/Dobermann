#ifndef _HTTP_SNIFFER_H_
#define _HTTP_SNIFFER_H_

#include "sniffer.h"

class HttpSniffer : public Sniffer {
private:
    std::string cache_buffer;

public:
    HttpSniffer();
    void read(const char* buffer, uint32_t length);
    const char* get_filter();
};

#endif  // _HTTP_SNIFFER_H_