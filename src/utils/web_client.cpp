#include "web_client.h"
#include <curl/curl.h>
#include "logging.h"
#include <nlohmann/json.hpp>
#include <iostream>

using json = nlohmann::json;

static Logger* logger = Logger::get_logger();

static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream) {
    std::string* data = (std::string*)stream;
    data->append((char*)ptr, size * nmemb);
    return size * nmemb;
}

json request::get(std::string url, const std::map<std::string, std::string>& parameters) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        logger->error("curl_easy_init failed");
        return json();
    }

    url += "?";

    for (auto& parameter : parameters) {
        url += parameter.first + "=" + parameter.second + "&";
    }
    url.pop_back();

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);

    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        logger->error("curl_easy_perform failed: %s", curl_easy_strerror(res));
        return json();
    }

    return json::parse(response);
}

json request::post(const std::string& url, const json& data) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        logger->error("curl_easy_init failed");
        return json();
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.dump().c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);

    struct curl_slist* hs = NULL;
    hs = curl_slist_append(hs, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hs);

    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        logger->error("curl_easy_perform failed: %s", curl_easy_strerror(res));
        return json();
    }

    return json::parse(response);
}