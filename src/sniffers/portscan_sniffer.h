#include "sniffer.h"
#include <map>

using ports_t = std::map<uint16_t, uint32_t>;

class PortScanSniffer : public Sniffer {
private:
    static ports_t ports;
protected:
public:
    PortScanSniffer(Engine* engine, const std::string interface_name);
    void on_packet(const char* buffer, uint32_t length);
};