#ifndef _ENGINE_H_
#define _ENGINE_H_

#include <event2/event.h>

#include <memory>
#include <vector>

#include "engine.h"
#include "sniffer.h"

class Engine {
private:
    std::vector<Sniffer*> sniffers;
    event_base* base;
    static std::unique_ptr<Engine> engine;

    Engine();

protected:
public:
    static Engine* get_engine();
    void start();
    void register_sniffer(Sniffer* sniffer);
    ~Engine();
};

#endif  // _ENGINE_H_