#ifndef _ENGINE_H_
#define _ENGINE_H_

#include <event2/event.h>

#include <memory>
#include <vector>

#include "../sniffers/sniffer.h"
#include "../dispatchers/dispatcher.h"
#include "engine.h"

class Sniffer;
class Dispatcher;

class Engine {
private:
    std::vector<Sniffer*> sniffers;
    std::vector<Dispatcher*> dispatchers;
    int settings_sock;
    struct event* settings_event;

    Sniffer* get_sniffer(const std::string iterface_name, const std::string name, uint16_t port);

protected:
public:
    event_base* base;

    Engine();
    int start();
    void register_sniffer(Sniffer* sniffer);
    void register_dispatcher(Dispatcher* dispatcher);
    void dispatch(Event* event);

    int config(const std::string file_path);

    ~Engine();
};

#endif  // _ENGINE_H_