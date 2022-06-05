#include "vulns.h"
#include <string>
#include "event.h"

CVE::CVE()
    : Event(EventType::EXPLOIT), id(), type(), score() {}

CVE::CVE(std::string ip)
    : Event(EventType::EXPLOIT, ip), id(), type(), score() {}

CVE::CVE(std::string ip, std::string id, std::string type, float score)
    : Event(EventType::EXPLOIT, ip), id(id), type(type), score(score) {}

CVE::CVE(std::string id, std::string type, float score)
    : Event(EventType::EXPLOIT), id(id), type(type), score(score) {}

json CVE::serialize() {
    json j;
    j["id"] = id;
    j["type"] = type;
    j["score"] = score;
    return j;
}

Portscan::Portscan()
    : Event(EventType::PORT_SCAN) {}

Portscan::Portscan(std::string ip)
    : Event(EventType::PORT_SCAN, ip) {}

json Portscan::serialize() {
    json j;
    j["description"] = "Portscan attempted";
    return j;
}

Flood::Flood()
    : Event(EventType::FLOOD) {}

Flood::Flood(std::string ip)
    : Event(EventType::FLOOD, ip) {}

json Flood::serialize() {
    json j;
    j["description"] = "Flood attempted";
    return j;
}