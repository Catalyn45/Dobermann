#include "engine.h"

#include "../utils/logging.h"

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
        logger->info("starting sniffer: %s", sniffer->name);
        if(sniffer->init() != 0) {
            logger->error("error initializing sniffer: %s", sniffer->name);
            return 1;
        }

        logger->debug("creating event for sniffer: %s", sniffer->name);
        event* read_ev = event_new(this->base, sniffer->sock, EV_READ | EV_PERSIST, read_callback, sniffer);
        if (!read_ev) {
            logger->error("error at creating event");
            return 1;
        }

        event_add(read_ev, NULL);
    }

    logger->info("all sniffers started");
    event_base_dispatch(this->base);
    return 0;
}

void Engine::register_sniffer(Sniffer* sniffer) {
    logger->debug("registring sniffer: %s on interface %s", sniffer->name, sniffer->interface_name);
    Engine::sniffers.push_back(sniffer);
}