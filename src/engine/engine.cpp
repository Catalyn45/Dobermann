#include "engine.h"
#include "../utils/logging.h"
#include "nlohmann/json.hpp"
#include <fstream>
#include "../sniffers/http_sniffer.h"

using json = nlohmann::json;

static Logger* logger = Logger::get_logger();

Engine::Engine() {
    this->base = event_base_new();
}

Engine::~Engine() {
    event_base_free(this->base);

    for (Sniffer* sniffer : this->sniffers) {
        delete sniffer;
    }
}

#define BUFFER_SIZE 255

static void read_callback(int socket, short what, void* arg) {
    Sniffer* sniffer = (Sniffer*)arg;

    char buffer[BUFFER_SIZE];
    int res = recv(socket, buffer, sizeof(buffer), 0);
    logger->debug("received %d bytes packet", res);
    if (res <= 0) {
        logger->error("error receiving data from socket");
        return;
    }

    sniffer->on_packet(buffer, res);
}

int Engine::start() {
    for (Sniffer* sniffer : sniffers) {
        logger->info("starting sniffer: %s on interface %s", sniffer->name.c_str(), sniffer->interface_name.c_str());
        if(sniffer->init() != 0) {
            logger->error("error initializing sniffer: %s", sniffer->name.c_str());
            return -1;
        }

        logger->debug("creating event for sniffer: %s", sniffer->name.c_str());
        event* read_ev = event_new(this->base, sniffer->sock, EV_READ | EV_PERSIST, read_callback, sniffer);
        if (!read_ev) {
            logger->error("error at creating event");
            return -1;
        }

        event_add(read_ev, NULL);
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

Sniffer* Engine::get_sniffer(const std::string interface_name, const std::string name, uint16_t port) {
    if (name == "http") {
        return new HttpSniffer(this, interface_name, port);
    }

    return nullptr;
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

    for (const auto& config_item: config) {
        auto interfaces = config_item["interfaces"];
        auto sniffers = config_item["sniffers"];

        for (const auto& interface: interfaces) {

            for (const auto& sniffer: sniffers) {
                std::string name = sniffer["name"];
                uint16_t port = sniffer["port"];

                Sniffer* sniffer_obj = this->get_sniffer(interface, name, port);
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