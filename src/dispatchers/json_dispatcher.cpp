#include "json_dispatcher.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include "../utils/logging.h"

static Logger* logger = Logger::get_logger();

using json = nlohmann::json;

JsonDispatcher::JsonDispatcher(Engine* engine, const std::string path)
    : Dispatcher(engine, "Json dispatcher"), path(std::move(path)) {}

void JsonDispatcher::dispatch(Event* event) {
    json j_event = event->serialize();
    logger->detection(std::string(j_event["id"]).c_str());

    std::ofstream tmp(this->path, std::ios::app);
    tmp.close();

    std::fstream f(this->path, std::fstream::in | std::fstream::out);
    if (!f.is_open()) {
        logger->error("error opening file: %s", this->path.c_str());
        return;
    }

    std::stringstream content;
    content << f.rdbuf();

    if (content.str().find("[") == std::string::npos) {
        content.str("[]");
    }

    f.seekg(0, std::ios::beg);

    json j_detections = json::parse(content.str());
    j_event["dispatched_time"] = std::time(nullptr);
    j_detections.push_back(j_event);

    logger->detection("%s", j_detections.dump(4).c_str());

    f << j_detections.dump(4);

    f.close();
}