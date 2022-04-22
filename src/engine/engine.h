#ifndef _ENGINE_H_
#define _ENGINE_H_

#include <event2/event.h>

#include <memory>
#include <vector>

#include "engine.h"
#include "../sniffers/sniffer.h"

class Engine {
private:
    std::vector<Sniffer*> sniffers;
    event_base* base;

protected:
public:
    Engine();
    int start();
    void register_sniffer(Sniffer* sniffer);
    ~Engine();
};

#endif  // _ENGINE_H_