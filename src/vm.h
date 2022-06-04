#ifndef VM_H_
#define VM_H_

#include <nlohmann/json.hpp>

using json = nlohmann::json;
using vm_args_t = std::map<std::string, void*>
using vm_functions_t = std::map<std::string, vm_function_t>

typedef int (*vm_function_t)(vm_args_t script_args, vm_args_t args);

class VirtualMachine {
private:
    vm_functions_t functions;

public:
    VirtualMachine();

    int register_functions(vm_functions_t functions);
    int run_script(json script, vm_args_t args);

    ~VirtualMachine();
};

#endif // VM_H_