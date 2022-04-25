#ifndef _JSON_DISPATCHER_H_
#define _JSON_DISPATCHER_H_
#include <string>
#include "dispatcher.h"
#include "../engine/engine.h"

class JsonDispatcher : public Dispatcher {
    const std::string path;
public:
    JsonDispatcher(Engine* engine, const std::string path);
    void dispatch(Event* event);
};

#endif // _JSON_DISPATCHER_H_