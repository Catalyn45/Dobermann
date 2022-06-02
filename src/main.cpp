#include <event2/event.h>

#include "engine/engine.h"
#include "sniffers/http_sniffer.h"
#include "sniffers/sniffer.h"
#include "utils/logging.h"
#include "utils/utils.h"
#include "dispatchers/json_dispatcher.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

static Logger* logger = Logger::get_logger();

using namespace util;

struct event *signal_event = nullptr;

static void exit_handler(int socket, short what, void* arg) {
    logger->info("exiting...");
    auto engine = (std::unique_ptr<Engine>*)arg;
    
    if (signal_event != nullptr)
        event_free(signal_event);

    engine->reset();
    exit(0);
}

int main(int argc, char* argv[]) {
    const char* interface = "lo";
    uint32_t port = 80;

    const char* log_level = getenv("LOG_LEVEL");
    if (log_level != nullptr) {
        Logger::config(Logger::level_name(log_level));
    }

    auto p_engine = std::make_unique<Engine>();
    Engine* engine = p_engine.get();

    signal_event = evsignal_new(engine->base, SIGINT, exit_handler, &p_engine);
    if (!signal_event || event_add(signal_event, NULL) < 0) {
        logger->error("error creating signal event");
        return -1;
    }

    // engine->register_sniffer(new HttpSniffer(engine, interface, port));
    // engine->register_dispatcher(new JsonDispatcher(engine, "json_dispatcher.json"));

    engine->config("config.json");
    if(engine->start() != 0) {
        logger->error("error starting engine");
        return -1;
    }

    return 0;
}
