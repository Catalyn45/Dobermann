#include "remote_repository.h"
#include "../utils/web_client.h"
#include <time.h>

RemoteRepository::RemoteRepository(const std::string& url)
    : url(url) {};

RemoteRepository::~RemoteRepository() {}

#define UPDATE_INTERVAL 1 * 60 * 60 // hours

json RemoteRepository::get_http_scripts() {
    if (time(NULL) - this->last_scripts_update < UPDATE_INTERVAL) {
        return this->scripts_cache;
    }

    std::map<std::string, std::string> parameters;
    parameters["type"] = "http";

    json response = request::get(this->url, parameters);
    this->last_scripts_update = time(NULL);
    this->scripts_cache = response;

    return response;
}

std::vector<std::string> RemoteRepository::get_tcp_patterns() {
    if (time(NULL) - this->last_tcp_update < UPDATE_INTERVAL) {
        return this->tcp_patterns_cache;
    }

    std::map<std::string, std::string> parameters;
    parameters["type"] = "tcp";

    json response = request::get(this->url, parameters);
    this->last_tcp_update = time(NULL);
    this->tcp_patterns_cache = response;

    return response;
}

std::vector<std::string> RemoteRepository::get_udp_patterns() {
    if (time(NULL) - this->last_udp_update < UPDATE_INTERVAL) {
        return this->udp_patterns_cache;
    }

    std::map<std::string, std::string> parameters;
    parameters["type"] = "udp";

    json response = request::get(this->url, parameters);
    this->last_udp_update = time(NULL);
    this->udp_patterns_cache = response;

    return response;
}