#ifndef _VULNS_H_
#define _VULNS_H_

#include <string>
#include "../event.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

struct CVE: public Event{
    CVE(std::string id, std::string type, float score);
    CVE();
    CVE(const CVE& other) = default;
    CVE(CVE&& other) = default;

    std::string id;
    std::string type;
    float score;

    json serialize();
};

#endif // _VULNS_H_