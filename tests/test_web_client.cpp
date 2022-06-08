#include <iostream>
#include <nlohmann/json.hpp>
#include "../src/utils/web_client.h"
#include <map>
#include <gtest/gtest.h>

TEST(WebClient, Get) {
    std::map<std::string, std::string> parameters;
    parameters["key"] = "value";
    std::string url = "https://httpbin.org/get";
    json response = request::get(url, parameters);

    ASSERT_NE(response.size(), 0);
}

TEST(WebClient, Post) {
    json data;
    data["key"] = "value";
    std::string url = "https://httpbin.org/post";
    json response = request::post(url, data);

    ASSERT_NE(response.size(), 0);
}