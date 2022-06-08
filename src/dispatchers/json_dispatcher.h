#ifndef _JSON_DISPATCHER_H_
#define _JSON_DISPATCHER_H_
#include <string>
#include "dispatcher.h"
#include "../engine.h"

class JsonDispatcher : public Dispatcher {
    const std::string path;
public:
    JsonDispatcher(const Engine* engine, const std::string& path);
    void dispatch(const Event* event) const;
};

#endif // _JSON_DISPATCHER_H_