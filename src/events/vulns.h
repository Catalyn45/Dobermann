#ifndef _VULNS_H_
#define _VULNS_H_

#include <string>
#include "event.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

struct CVE: public Event{
    CVE();
    CVE(std::string ip);
    CVE(std::string ip, std::string id, std::string type, float score);
    CVE(std::string id, std::string type, float score);
    CVE(const CVE& other) = default;
    CVE(CVE&& other) = default;

    std::string id;
    std::string type;
    float score;

    json serialize();
};

struct Portscan: public Event {
    Portscan();
    Portscan(std::string ip);

    Portscan(const Portscan& other) = default;
    Portscan(Portscan&& other) = default;

    json serialize();
};

struct Flood: public Event {
    Flood();
    Flood(std::string ip);

    Flood(const Flood& other) = default;
    Flood(Flood&& other) = default;

    json serialize();
};

#endif // _VULNS_H_