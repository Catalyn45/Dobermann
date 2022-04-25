#include "engine.h"
#include "../utils/logging.h"
#include "nlohmann/json.hpp"
#include <fstream>
#include "../sniffers/http_sniffer.h"
#include <sys/un.h>
#include <unistd.h>
#include "../utils/utils.h"
#include "../dispatchers/json_dispatcher.h"

using json = nlohmann::json;

static Logger* logger = Logger::get_logger();

Engine::Engine()
    : settings_sock(-1), settings_event(nullptr) {
    this->base = event_base_new();
}

Engine::~Engine() {
    for (Sniffer* sniffer : this->sniffers) {
        delete sniffer;
    }

    for (Dispatcher* dispatcher : this->dispatchers) {
        delete dispatcher;
    }

    if (this->settings_event != nullptr) {
        event_free(this->settings_event);
    }

    if (this->settings_sock != -1) {
        close(this->settings_sock);
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

    this->listen();
    
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

    const std::string dispatch_path = config["dispatch"];
    this->register_dispatcher(new JsonDispatcher(this, dispatch_path));

    for (const auto& config_item: config["configs"]) {
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

static void setting_callback(int socket, short what, void* arg) {
    Engine *engine = (Engine*)arg;

    char buffer[BUFFER_SIZE];
    int res = recv(socket, buffer, sizeof(buffer) - 1, 0);
    if (res <= 0) {
        logger->error("error receiving data from socket");
        return;
    }

    buffer[res] = '\0';
    logger->info("receivied message: %s", buffer);
}

static void accept_callback(int socket, short what, void* arg) {
    Engine *engine = (Engine*)arg;

    int client = accept(socket, NULL, NULL);
    if (client < 0) {
        logger->error("error accepting connection");
        return;
    }
    logger->info("accepted connection");

    event* setting_ev = event_new(engine->base, client, EV_READ | EV_PERSIST, setting_callback, engine);
    if(!setting_ev) {
        logger->error("error at creating event");
        return;
    }

    if(event_add(setting_ev, NULL) < 0) {
        logger->error("error at creating event");
        return;
    }
}

int Engine::listen() {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        logger->error("error creating socket");
        return -1;
    }

    util::descriptor_ptr sock_ptr(&sock);

    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;

    strcpy(addr.sun_path, "./sniffer");

    unlink("./sniffer");
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        logger->error("error binding socket");
        return -1;
    }

    if (::listen(sock, 5) < 0) {
        logger->error("error listening socket");
        return -1;
    }

    event* accept_ev = event_new(this->base, sock, EV_READ | EV_PERSIST, accept_callback, this);
    if (!accept_ev) {
        logger->error("error at creating event");
        return -1;
    }

    if(event_add(accept_ev, NULL) < 0) {
        event_del(accept_ev);
        logger->error("error at adding event");
        return -1;
    }

    sock_ptr.release();
    this->settings_sock = sock;
    this->settings_event = accept_ev;
    return 0;
}