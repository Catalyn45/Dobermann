#include "vulns.h"
#include <string>
#include "event.h"

CVE::CVE()
    : Event(EventType::EXPLOIT), id(), type(), score() {}

CVE::CVE(const std::string& ip)
    : Event(EventType::EXPLOIT, ip), id(), type(), score() {}

CVE::CVE(const std::string& ip, const std::string& id, const std::string& type, float score)
    : Event(EventType::EXPLOIT, ip), id(id), type(type), score(score) {}

CVE::CVE(const std::string& id, const std::string& type, float score)
    : Event(EventType::EXPLOIT), id(id), type(type), score(score) {}

json CVE::serialize() const {
    json j;
    j["id"] = id;
    j["type"] = type;
    j["score"] = score;
    return j;
}

Portscan::Portscan()
    : Event(EventType::PORT_SCAN) {}

Portscan::Portscan(const std::string& ip)
    : Event(EventType::PORT_SCAN, ip) {}

json Portscan::serialize() const {
    json j;
    j["description"] = "Portscan attempted";
    return j;
}

Flood::Flood()
    : Event(EventType::FLOOD) {}

Flood::Flood(const std::string& ip)
    : Event(EventType::FLOOD, ip) {}

json Flood::serialize() const {
    json j;
    j["description"] = "Flood attempted";
    return j;
}

PortProfiling::PortProfiling()
    : Event(EventType::PORT_PROFILING) {}

PortProfiling::PortProfiling(const std::string& ip)
    : Event(EventType::PORT_PROFILING, ip) {}

json PortProfiling::serialize() const {
    json j;
    j["description"] = "Port profiling attempted";
    return j;
}