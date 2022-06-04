#include "vulns.h"
#include <string>
#include "../event.h"

CVE::CVE(std::string ip)
    : Event(EventType::EXPLOIT, ip), id(), type(), score() {}

CVE::CVE(std::string ip, std::string id, std::string type, float score)
    : Event(EventType::EXPLOIT, ip), id(id), type(type), score(score) {}


json CVE::serialize() {
    json j;
    j["id"] = id;
    j["type"] = type;
    j["score"] = score;
    return j;
}

Portscan::Portscan(std::string ip)
    : Event(EventType::PORT_SCAN, ip) {}

json Portscan::serialize() {
    json j;
    j["description"] = "Portscan attempted";
    return j;
}
