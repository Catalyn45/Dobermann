#ifndef _VULNS_H_
#define _VULNS_H_

#include <string>
#include "event.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

struct CVE: public Event{
    CVE();
    CVE(const std::string& ip);
    CVE(const std::string& ip, const std::string& id, const std::string& type, float score);
    CVE(const std::string& id, const std::string& type, float score);
    CVE(const CVE& other) = default;
    CVE(CVE&& other) = default;

    std::string id;
    std::string type;
    float score;

    json serialize() const;
};

struct Portscan: public Event {
    Portscan();
    Portscan(const std::string& ip);

    Portscan(const Portscan& other) = default;
    Portscan(Portscan&& other) = default;

    json serialize() const;
};

struct Flood: public Event {
    Flood();
    Flood(const std::string& ip);

    Flood(const Flood& other) = default;
    Flood(Flood&& other) = default;

    json serialize() const;
};

struct PortProfiling: public Event {
    PortProfiling();
    PortProfiling(const std::string& ip);

    PortProfiling(const PortProfiling& other) = default;
    PortProfiling(PortProfiling&& other) = default;

    json serialize() const;
};

#endif // _VULNS_H_