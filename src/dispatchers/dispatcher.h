#ifndef _DISPATCHER_H_
#define _DISPATCHER_H_

#include "../events/event.h"
#include "../engine.h"

class Engine;

class Dispatcher {
    public:
        Engine* engine;
        const std::string name;

        Dispatcher(Engine* engine, const std::string name);
        virtual void dispatch(Event* event) = 0;

        virtual ~Dispatcher();
    protected:
    private:
};

#endif // _DISPATCHER_H_