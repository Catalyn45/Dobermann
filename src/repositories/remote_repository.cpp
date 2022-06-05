#include "remote_repository.h"
#include "../utils/web_client.h"
#include <time.h>

RemoteRepository::RemoteRepository(const std::string& url)
    : url(url), last_update(0), scripts_cache() {};

RemoteRepository::~RemoteRepository() {}

#define UPDATE_INTERVAL 1 * 60 * 60 // hours

json RemoteRepository::get_http_scripts() {
    if (time(NULL) - last_update < UPDATE_INTERVAL) {
        return this->scripts_cache;
    }

    std::map<std::string, std::string> parameters;
    parameters["type"] = "http";

    json response = request::get(this->url, parameters);
    this->last_update = time(NULL);
    this->scripts_cache = response;

    return response;
}