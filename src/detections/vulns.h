#ifndef _VULNS_H_
#define _VULNS_H_

#include <string>

struct CVE {
    std::string id;
    std::string type;
    float score;
};

#endif // _VULNS_H_