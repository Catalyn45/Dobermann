#include "vm.h"
#include "../utils/logging.h"
#include "../events/vulns.h"

VirtualMachine::VirtualMachine() {}

VirtualMachine::~VirtualMachine() {}

static Logger* logger = Logger::get_logger();

int VirtualMachine::register_functions(vm_functions_t functions) {
    this->functions = functions;
    return 0;
}

InstructionResult VirtualMachine::run_instruction(json instruction, vm_args_t& script_args, json* result) {
    if(instruction.find("function_pass") != instruction.end()) {
        std::string function_name = instruction["function_pass"];
        json args = instruction["args"];

        if (this->functions.find(function_name) == this->functions.end()) {
            logger->error("function: %s not found", function_name.c_str());
            return ERROR;
        }

        return this->functions[function_name](script_args, args) == 0 ? SUCCESS : FAILED;
    }

    if(instruction.find("return") != instruction.end()) {
        *result = instruction["return"];
        return SCRIPT_FINISHED;
    }

    logger->error("unknown instruction: %s", instruction.dump().c_str());
    return ERROR;
}

static Event* json_to_event(std::string type, json data) {
    if (type == "CVE") {
        return new CVE(data["id"], data["type"], data["score"]);
    }

    logger->error("unknown event type: %s", type.c_str());
    return nullptr;
}

Event* VirtualMachine::run_script(json script, vm_args_t& args) {
    std::string name = script["name"];
    std::string version = script["version"];
    std::string author = script["author"];
    std::string type = script["type"];

    logger->debug("running script: %s version: %s, author: %s", name.c_str(), version.c_str(), author.c_str());

    json steps = script["steps"];

    json result_event;

    for(json& step : steps) {
        InstructionResult result = run_instruction(step, args, &result_event);
        if (result == ERROR) {
            logger->error("error running instruction: %s", step.dump().c_str());
            return nullptr;
        }

        if (result == FAILED) {
            logger->debug("script: %s did not pass", name.c_str());
            return nullptr;
        }

        if (result == SCRIPT_FINISHED) {
            logger->debug("script: %s matched", name.c_str());
            return json_to_event(type, result_event);
        }
    }

    logger->error("script did not finish");
    return nullptr;
}
