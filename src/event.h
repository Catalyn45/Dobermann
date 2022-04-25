#ifndef _EVENT_H_
#define _EVENT_H_

#include <nlohmann/json.hpp>
using json = nlohmann::json;

enum EventType {
    EXPLOIT,
    ATTACK,
    SCAN,
    SPOOF
};

class Event {
    public:
        Event(EventType type);
        EventType type;
        virtual json serialize() = 0;
    private:
    protected:
};

#endif // _EVENT_H_