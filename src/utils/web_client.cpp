#include "web_client.h"
#include <curl/curl.h>

json request::get(std::string url, std::map<std::string, std::string>* parameters) {
    return json();
}

json request::post(std::string url, json data) {
    return json();
}