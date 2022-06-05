#ifndef REPOSITORY_H_
#define REPOSITORY_H_

#include <nlohmann/json.hpp>

using json = nlohmann::json;

class Repository {
public:
    virtual json get_http_scripts() = 0;
    virtual ~Repository() {};
};

#endif // REPOSITORY_H_