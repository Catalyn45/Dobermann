#include "local_repository.h"
#include <fstream>
#include <vector>

using json = nlohmann::json;

LocalRepository::LocalRepository(std::string path)
    : path(path) {}

LocalRepository::~LocalRepository() {}

json LocalRepository::get_http_scripts() {
    std::ifstream file(path);
    if (!file.is_open()) {
        return json();
    }

    json scripts;
    file >> scripts;
    return scripts;
}

std::vector<std::string> LocalRepository::get_tcp_patterns() {
    std::ifstream file(path);
    if (!file.is_open()) {
        return json();
    }

    json patterns;
    file >> patterns;

    return patterns["tcp"];
}

std::vector<std::string> LocalRepository::get_udp_patterns() {
    std::ifstream file(path);
    if (!file.is_open()) {
        return json();
    }

    json patterns;
    file >> patterns;

    return patterns["udp"];
}