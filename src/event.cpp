#include "event.h"

Event::Event(EventType event_type, std::string src_ip):
    type(event_type), ip(src_ip) {}
