#ifndef _EVENT_H_
#define _EVENT_H_

#include <nlohmann/json.hpp>
using json = nlohmann::json;

enum EventType {
    EXPLOIT,
    ATTACK,
    PORT_SCAN,
    PORT_PROFILING,
    FLOOD,
    SCAN,
    SPOOF
};

class Event {
    public:
        Event(EventType type, const std::string& ip);
        Event(EventType type);
        virtual ~Event() {};
        EventType type;
        std::string ip;
        virtual json serialize() const = 0;

        std::string type_to_string() const;

        static Event* from_json(const std::string& type, const json& data);
    private:
    protected:
};

#endif // _EVENT_H_