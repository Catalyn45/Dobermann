#include "json_dispatcher.h"
#include <fstream>
#include <iostream>
#include "../utils/logging.h"

static Logger* logger = Logger::get_logger();

JsonDispatcher::JsonDispatcher(Engine* engine, const std::string path)
    : Dispatcher(engine, "Json dispatcher"), path(std::move(path)) {}

void JsonDispatcher::dispatch(Event* event) {
    json j = event->serialize();
    logger->detection(j.dump(4).c_str());
    // std::ofstream f(path);
    // f << j << std::endl;
}