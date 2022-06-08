#ifndef _ENGINE_H_
#define _ENGINE_H_

#include <event2/event.h>

#include <memory>
#include <vector>

#include "sniffers/sniffer.h"
#include "dispatchers/dispatcher.h"
#include "engine.h"
#include "interpreter/vm.h"

class Sniffer;
class Dispatcher;

class Engine {
private:
    std::vector<Sniffer*> sniffers;
    std::vector<Dispatcher*> dispatchers;

protected:
public:
    event_base* base;
    VirtualMachine vm;

    Engine();
    int start();
    void register_sniffer(Sniffer* sniffer);
    void register_dispatcher(Dispatcher* dispatcher);
    void dispatch(Event* event) const;

    int config(const std::string& file_path);


    ~Engine();
};

#endif  // _ENGINE_H_