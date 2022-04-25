#include "vulns.h"
#include <string>
#include "../event.h"

CVE::CVE()
    : Event(EventType::EXPLOIT), id(), type(), score() {}

CVE::CVE(std::string id, std::string type, float score)
    : Event(EventType::EXPLOIT), id(id), type(type), score(score) {}


json CVE::serialize() {
    json j;
    j["id"] = id;
    j["type"] = type;
    j["score"] = score;
    return j;
}