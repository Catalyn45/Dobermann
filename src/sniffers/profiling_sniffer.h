#ifndef PROFILER_SNIFFER_H_
#define PROFILER_SNIFFER_H_

#include "sniffer.h"
#include "../repositories/repository.h"

class ProfilingSniffer : public Sniffer {
    private:
        uint32_t services_count;
        long last_service_sent_time;
        std::vector<std::string> last_patterns;
        Repository *repository;
    protected:
        void on_packet(const char* buffer, uint32_t length);
    public:
        ProfilingSniffer(const Engine* engine, const std::string& interface_name, uint16_t port);
        ~ProfilingSniffer();
};

#endif // PROFILER_SNIFFER_H_