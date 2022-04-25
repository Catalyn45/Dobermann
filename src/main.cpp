#include <event2/event.h>

#include "engine/engine.h"
#include "sniffers/http_sniffer.h"
#include "sniffers/sniffer.h"
#include "utils/logging.h"
#include "utils/utils.h"
#include "dispatchers/json_dispatcher.h"
#include <string.h>

static Logger* logger = Logger::get_logger();

using namespace util;

int main(int argc, char* argv[]) {
    const char* interface = "lo";
    uint32_t port = 80;

    Logger::config(Level::INFO);

    auto p_engine = std::make_unique<Engine>();
    Engine* engine = p_engine.get();

    // engine->register_sniffer(new HttpSniffer(engine, interface, port));

    engine->config("config.json");
    engine->register_dispatcher(new JsonDispatcher(engine, "json_dispatcher.json"));

    if(engine->start() != 0) {
        logger->error("error starting engine");
        return -1;
    }

    return 0;
}
