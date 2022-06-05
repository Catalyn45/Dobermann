#ifndef VM_H_
#define VM_H_

#include <nlohmann/json.hpp>
#include "../events/event.h"

using json = nlohmann::json;

using vm_args_t = std::map<std::string, void*>;

using vm_function_t = int (*)(vm_args_t& script_args, json args);
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

    InstructionResult run_instruction(json instruction, vm_args_t& script_args, json* result);
public:
    VirtualMachine();

    int register_functions(vm_functions_t functions);
    Event* run_script(json script, vm_args_t& args);

    ~VirtualMachine();
};

#endif // VM_H_