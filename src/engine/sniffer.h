#ifndef _SNIFFER_H_
#define _SNIFFER_H_

#include <event2/event.h>

#include <string>
#include <vector>

class Sniffer {
private:
    static std::vector<Sniffer*> sniffers;
    static event_base* base;

    friend class Engine;

protected:
    int sock;

    static uint32_t id;

    virtual const char* get_filter() = 0;
    std::string name;

public:
    void init();
    virtual void read(const char* buffer, uint32_t length) = 0;
    Sniffer(const std::string& name);
    ~Sniffer();
};

#endif  // _SNIFFER_H_