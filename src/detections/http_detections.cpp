#include "http_detections.h"

static bool CVE_2021_44228(const HttpPacket* packet, CVE* out_cve) {
    if (packet->type == HTTP_RESPONSE)
        return false;
    
    static const char* log4j_tokens[] = {"${jndi:ldap", "${jndi:dns"};
    bool detected = false;

    for (const char* token : log4j_tokens) {
        if (packet->path.find(token) != std::string::npos) {
            detected = true;
            break;
        }

        if (packet->body.find(token) != std::string::npos) {
            detected = true;
            break;
        }

        for (const auto& header : packet->headers) {
            if (header.second.find(token) != std::string::npos) {
                detected = true;
                break;
            }
        }
    }

    if (detected) {
        out_cve->id = "CVE-2021-44228";
        out_cve->type = "REMOTE_CODE_EXECUTION";
        out_cve->score = 9.4;
    }

    return detected;
}


http_static_detection_t http_static_detections[] = {
    CVE_2021_44228,
    NULL
};