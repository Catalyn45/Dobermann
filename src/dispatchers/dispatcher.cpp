#include "dispatcher.h"
#include "json_dispatcher.h"


Dispatcher::Dispatcher(Engine* engine, const std::string name)
    : engine(engine), name(std::move(name)) {}