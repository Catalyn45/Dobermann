#include "event.h"
#include "../utils/logging.h"
#include "vulns.h"

static Logger *logger = Logger::get_logger();

Event::Event(EventType event_type, const std::string& src_ip):
    type(event_type), ip(src_ip) {}

Event::Event(EventType event_type):
    type(event_type) {}

std::string Event::type_to_string() const {
    switch (this->type) {
        case EventType::EXPLOIT:
            return std::string("Exploit");
        case EventType::ATTACK:
            return std::string("Attack");
        case EventType::PORT_SCAN:
            return std::string("Portscan");
        case EventType::FLOOD:
            return std::string("Flood");
        case EventType::SCAN:
            return std::string("Scan");
        case EventType::SPOOF:
            return std::string("Spoof");
        default:
            return std::string("Unknown");
    }
}

Event* Event::from_json(const std::string& type, const json& data) {
    if (type == "CVE") {
        return new CVE(data["id"], data["type"], data["score"]);
    }

    logger->error("unknown event type: %s", type.c_str());
    return nullptr;
}
