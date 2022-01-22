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

std::unique_ptr<Engine> Engine::engine(nullptr);

Engine* Engine::get_engine() {
    if (!engine.get()) {
        engine.reset(new Engine());
    }

    return engine.get();
}

#define BUFFER_SIZE 255

static void read_callback(int socket, short what, void* arg) {
    Sniffer* sniffer = (Sniffer*)arg;

    char buffer[BUFFER_SIZE];
    int res = recv(socket, buffer, sizeof(buffer), 0);
    if (res <= 0) {
        logger->error("error receiving data from socket");
        return;
    }

    sniffer->read(buffer, res);
}

void Engine::start() {
    for (Sniffer* sniffer : sniffers) {
        sniffer->init();
        event* read_ev = event_new(this->base, sniffer->sock, EV_READ | EV_PERSIST, read_callback, sniffer);
        if (!read_ev) {
            logger->error("Error at creating event");
            return;
        }

        event_add(read_ev, NULL);
    }

    event_base_dispatch(this->base);
}

void Engine::register_sniffer(Sniffer* sniffer) {
    Engine::sniffers.push_back(sniffer);
}
