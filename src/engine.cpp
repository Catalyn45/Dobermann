#include "engine.h"
#include "utils/logging.h"
#include "nlohmann/json.hpp"
#include <fstream>
#include "sniffers/http_sniffer.h"
#include "sniffers/portscan_sniffer.h"
#include "sniffers/flood_sniffer.h"
#include <sys/un.h>
#include <unistd.h>
#include "utils/utils.h"
#include "dispatchers/json_dispatcher.h"

using json = nlohmann::json;

static Logger* logger = Logger::get_logger();

extern vm_functions_t http_functions_map;

Engine::Engine()
    : vm() {
    this->base = event_base_new();
    this->vm.register_functions(http_functions_map);
}

Engine::~Engine() {
    for (Sniffer* sniffer : this->sniffers) {
        delete sniffer;
    }

    for (Dispatcher* dispatcher : this->dispatchers) {
        delete dispatcher;
    }

    event_base_free(this->base);
}

int Engine::start() {
    for (Sniffer* sniffer : sniffers) {
        logger->info("starting sniffer: %s on interface %s", sniffer->name.c_str(), sniffer->interface_name.c_str());
        if(sniffer->init() != 0) {
            logger->error("error initializing sniffer: %s", sniffer->name.c_str());
            return -1;
        }

        if(sniffer->start() != 0) {
            logger->error("error starting sniffer: %s", sniffer->name.c_str());
            return -1;
        }
    }

    logger->info("all sniffers started");

    event_base_dispatch(this->base);
    return 0;
}

void Engine::register_sniffer(Sniffer* sniffer) {
    logger->debug("registring sniffer: %s on interface %s", sniffer->name.c_str(), sniffer->interface_name.c_str());
    Engine::sniffers.push_back(sniffer);
}

void Engine::register_dispatcher(Dispatcher* dispatcher) {
    logger->debug("registring dispatcher: %s", dispatcher->name.c_str());
    Engine::dispatchers.push_back(dispatcher);
}

void Engine::dispatch(Event* event) {
    for (Dispatcher* dispatcher : dispatchers) {
        logger->debug("dispatching event to dispatcher: %s", dispatcher->name.c_str());
        dispatcher->dispatch(event);
    }
}

int Engine::config(const std::string file_path) {
    logger->info("configuring engine");

    std::ifstream file(file_path);
    if (!file.is_open()) {
        logger->error("error opening file: %s", file_path.c_str());
        return -1;
    }

    json config;
    file >> config;

    const std::string dispatch_path = config["dispatch"];
    this->register_dispatcher(new JsonDispatcher(this, dispatch_path));

    for (const auto& config_item: config["configs"]) {
        auto interfaces = config_item["interfaces"];
        auto sniffers = config_item["sniffers"];

        for (const auto& interface: interfaces) {

            for (const auto& sniffer: sniffers) {
                std::string name = sniffer["name"];

                uint16_t port = 0;
                if (sniffer.find("port") != sniffer.end()) {
                    port = sniffer["port"];
                }

                Sniffer* sniffer_obj = Sniffer::from_name(this, interface, name, port);
                if (sniffer_obj == nullptr) {
                    logger->error("error creating sniffer: %s", name.c_str());
                    return -1;
                }

                this->register_sniffer(sniffer_obj);
            }
        }
    }

    return 0;
}