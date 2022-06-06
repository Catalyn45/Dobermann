#include "vm.h"
#include "../utils/logging.h"
#include "../events/vulns.h"

VirtualMachine::VirtualMachine()
    : functions() {}

VirtualMachine::~VirtualMachine() {}

static Logger* logger = Logger::get_logger();

int VirtualMachine::register_functions(const vm_functions_t& functions) {
    this->functions.insert(functions.begin(), functions.end());
    return 0;
}

#define CHECK_INSTRUCTION(instruction_name) \
    if(instruction.find(instruction_name) != instruction.end())

InstructionResult VirtualMachine::run_instruction(const json& instruction, const vm_args_t& script_args, json* result_event) const {
    CHECK_INSTRUCTION("function_pass") {
        std::string function_name = instruction["function_pass"];
        json args = instruction["args"];

        if (this->functions.find(function_name) == this->functions.end()) {
            logger->error("function: %s not found", function_name.c_str());
            return ERROR;
        }

        return this->functions.at(function_name)(script_args, args) == 0 ? SUCCESS : FAILED;
    }

    CHECK_INSTRUCTION("or") {
        std::vector<json> or_conditions = instruction["or"];

        for (auto& condition : or_conditions) {
            InstructionResult result = this->run_instruction(condition, script_args, result_event);
            if(result != FAILED)
                return result;
        }

        return FAILED;
    }

    CHECK_INSTRUCTION("and") {
        std::vector<json> and_conditions = instruction["and"];

        for (auto& condition : and_conditions) {
            InstructionResult result = this->run_instruction(condition, script_args, result_event);
            if (result != SUCCESS)
                return result;
        }

        return SUCCESS;
    }

    CHECK_INSTRUCTION("not") {
        InstructionResult result = this->run_instruction(instruction["not"], script_args, result_event);
        if (result == SUCCESS)
            return FAILED;

        if (result == FAILED)
            return SUCCESS;

        return result;
    }

    CHECK_INSTRUCTION("return") {
        *result_event = instruction["return"];
        return SCRIPT_FINISHED;
    }

    logger->error("unknown instruction: %s", instruction.dump().c_str());
    return ERROR;
}

Event* VirtualMachine::run_script(const json& script, const vm_args_t& args) const {
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
            return Event::from_json(type, result_event);
        }
    }

    logger->error("script did not finish");
    return nullptr;
}
