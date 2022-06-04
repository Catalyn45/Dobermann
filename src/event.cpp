#include "event.h"

Event::Event(EventType event_type, std::string src_ip):
    type(event_type), ip(src_ip) {}

std::string Event::type_to_string() {
    switch (this->type) {
        case EventType::EXPLOIT:
            return std::string("Exploit");
        case EventType::ATTACK:
            return std::string("Attack");
        case EventType::PORT_SCAN:
            return std::string("Portscan");
        case EventType::SCAN:
            return std::string("Scan");
        case EventType::SPOOF:
            return std::string("Spoof");
        default:
            return std::string("Unknown");
    }
}