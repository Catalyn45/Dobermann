#include "dispatcher.h"
#include "json_dispatcher.h"


Dispatcher::Dispatcher(const Engine* engine, const std::string& name)
    : engine(engine), name(name) {}

Dispatcher::~Dispatcher() {}