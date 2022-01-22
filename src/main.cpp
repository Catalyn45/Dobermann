#include <event2/event.h>

#include "engine/engine.h"
#include "engine/http_sniffer.h"
#include "engine/sniffer.h"
#include "utils/logging.h"
#include "utils/utils.h"

Logger* logger = Logger::get_logger();

using namespace util;

int main() {
    Logger::config(Level::DEBUG);

    logger->info("creating and registering http sniffer");

    Engine* engine = Engine::get_engine();

    engine->register_sniffer(new HttpSniffer());
    logger->info("starting http sniffers");
    engine->start();

    return 0;
}
