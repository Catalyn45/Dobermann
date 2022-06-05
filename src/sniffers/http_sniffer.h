#ifndef _HTTP_SNIFFER_H_
#define _HTTP_SNIFFER_H_

#include "sniffer.h"
#include <map>
#include <string>
#include "../repositories/repository.h"
#include "../engine.h"

class HttpSniffer : public Sniffer {
private:
    Repository *repository;
    json scripts;
protected:
    void on_packet(const char* buffer, uint32_t length);
    int init();
public:
    HttpSniffer(const Engine* engine, const std::string& interface_name, uint16_t port);
    ~HttpSniffer();
};

#endif  // _HTTP_SNIFFER_H_