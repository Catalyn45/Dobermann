#ifndef WEB_CLIENT_H_
#define WEB_CLIENT_H_

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace request {
    json get(std::string url, const std::map<std::string, std::string>& parameters);
    json post(const std::string& url, const json& data);
};

#endif // WEB_CLIENT_H_