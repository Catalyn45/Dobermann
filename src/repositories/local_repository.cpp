#include "local_repository.h"
#include <fstream>

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