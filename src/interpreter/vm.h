#ifndef VM_H_
#define VM_H_

#include <nlohmann/json.hpp>
#include "../events/event.h"

using json = nlohmann::json;

using vm_args_t = std::map<std::string, void*>;

using vm_function_t = int (*)(const vm_args_t& script_args, const json& args);
using vm_functions_t = std::map<std::string, vm_function_t>;

enum InstructionResult {
    SUCCESS,
    FAILED,
    ERROR,
    SCRIPT_FINISHED
};

class VirtualMachine {
private:
    vm_functions_t functions;

    InstructionResult run_instruction(const json& instruction, const vm_args_t& script_args, json* result) const;
public:
    VirtualMachine();

    int register_functions(const vm_functions_t& functions);
    Event* run_script(const json& script, const vm_args_t& args) const;

    ~VirtualMachine();
};

#endif // VM_H_