#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace request {
    json get(std::string url, std::map<std::string, std::string>* parameters);
    json post(std::string url, json data);
};