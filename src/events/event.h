#ifndef _EVENT_H_
#define _EVENT_H_

#include <nlohmann/json.hpp>
using json = nlohmann::json;

enum EventType {
    EXPLOIT,
    ATTACK,
    PORT_SCAN,
    FLOOD,
    SCAN,
    SPOOF
};

class Event {
    public:
        Event(EventType type, std::string ip);
        Event(EventType type);
        virtual ~Event() {};
        EventType type;
        std::string ip;
        virtual json serialize() = 0;

        std::string type_to_string();

        static Event* from_json(std::string type, json data);
    private:
    protected:
};

#endif // _EVENT_H_