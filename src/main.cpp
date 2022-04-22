#include <event2/event.h>

#include "engine/engine.h"
#include "engine/http_sniffer.h"
#include "engine/sniffer.h"
#include "utils/logging.h"
#include "utils/utils.h"
#include <string.h>

Logger* logger = Logger::get_logger();

using namespace util;

int main(int argc, char* argv[]) {
    char interface[10] = "lo";
    if (argc > 1) {
        strcpy(interface, argv[1]);
    }

    uint32_t port = 80;
    if(argc > 2) {
        port = atoi(argv[2]);
    }

    Logger::config(Level::DEBUG);

    logger->info("creating and registering http sniffer");

    Engine* engine = new Engine();

    engine->register_sniffer(new HttpSniffer(interface, port));

    if(engine->start() != 0) {
        logger->error("error starting engine");
        delete engine;
        return 1;
    }

    delete engine;

    return 0;
}
