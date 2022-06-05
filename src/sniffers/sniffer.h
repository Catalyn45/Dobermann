#ifndef _SNIFFER_H_
#define _SNIFFER_H_

#include <event2/event.h>

#include <string>
#include <vector>
#include "../engine.h"

class Engine;

class Sniffer {
private:
    static event_base* base;
    static uint32_t id;

    friend class Engine;

protected:

    Engine* engine;
    int sock;
    struct event* event;

    const std::string name;
    const std::string interface_name;
    const std::string filter;
public:
    Sniffer(Engine* engine, const std::string name, const std::string interface_name, const std::string filter);
    virtual int init();
    int start();
    void stop();
    virtual void on_packet(const char* buffer, uint32_t length) = 0;
    virtual ~Sniffer();
};

#endif  // _SNIFFER_H_