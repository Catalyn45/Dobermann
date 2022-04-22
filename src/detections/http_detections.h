#ifndef _HTTP_DETECTIONS_H_
#define _HTTP_DETECTIONS_H_

#include "../engine/http_sniffer.h"
#include "vulns.h"

class HttpDynamicDetection {
public:
    virtual bool detect(HttpPacket* packet, CVE* out_cve) = 0;
};

typedef bool (*http_static_detection_t) (HttpPacket* packet, CVE* out_cve);

#endif  // _HTTP_DETECTIONS_H_
