#!/usr/bin/python3

import argparse
from ast import main
import os
import sys
import time

from .analyzer import Analyzer
from .variable import Variable

# A symex passo il nome delle due funzioni, il binario e la signature non parsata
# Creo una funzione qua dentro per fare il parsing della signature

TYPE_SIZES = {
    "short": 2,
    "int": 4,
    "long": 8,
    "ptr": 8,
    "char": 1,
    "void": 0,
    "float": 4,
    "double": 8,
    "long double": 16,
    "long long": 8,
    "unsigned long long": 8,
    "unsigned short": 2,
    "unsigned int": 4,
    "unsigned long": 8,
    "unsigned char": 1,
    "bool": 1
}

def parse_signature(signature: str):
    
    results = []

    for i, param in enumerate(signature.split(', ')):
        param_type = param.replace("*", "").strip()

        if param_type not in TYPE_SIZES:
            results.append(Variable(f"param_{i}", param_type, None))
        elif param != "void":
            if "*" in param:
                param_type = "ptr"
            size = TYPE_SIZES[param_type]
            results.append(Variable(f"param_{i}", param_type, size))

    return results


def symex(fn_name: str, target_fn_name: str, signature: str, binary: str, out_file: str):
    params = parse_signature(signature=signature) 

    analyzer = Analyzer(binary_name=binary, function_name=fn_name, target_function=target_fn_name)
    execute = True

    with open(out_file, 'w') as f:
        
        if any(param.size is None for param in params):
            execute = False
            f.write(f"[!] Skipping execution of function {fn_name}:\n")
            for param in params:
                if param.size is None:
                    f.write(f"\t[!] Unknown type {param.type}\n")

        start = time.time()
        while execute:
            f.write(f"[+] Starting symbolic execution of function {fn_name}\n")
            found = analyzer.symbolically_execute(parameters=params)
            execute = False

            if found:
                # Find constraints on global variables
                global_constraints = analyzer.find_globals(found)
                for c in global_constraints:
                    if 'if' in c or 'else' in c or 'then' in c:
                        f.write("[+] Complex constraint on global variable found. Executing again.\n")
                        execute = True

                if not execute:
                    if len(params) != 0:
                        # Evaluate parameters involved in constraints.
                        evaluated_params = analyzer.eval_args(found)
                        for i, param in enumerate(evaluated_params):
                            params[i].value = param
                            params[i].concrete = True

                        if len(evaluated_params) != 0:
                            f.write("[+] Function arguments\n")
                            evaluated_params = analyzer.eval_args(found)
                            if len(evaluated_params) == 0 and analyzer.args_number() != 0:
                                f.write("\tNo parameter was involved in any constraint.\n")

                            for i, param in enumerate(evaluated_params):
                                f.write(f"\t[{i+1}/{len(evaluated_params)}] {params[i].name} = {param}")
                        else:
                            f.write("[!] No parameter was involved in any constraint.\n")
                    else:
                        f.write("[!] No function parameter to evaluate.\n")


                    parsed_constraints = analyzer.parse_constraints(global_constraints)
                    if len(parsed_constraints) != 0:
                        f.write("[+] Global variables\n")
                        for i, constraint in enumerate(parsed_constraints):
                            f.write(f"\t[{i+1}/{len(parsed_constraints)}] Global found at offset {hex(constraint.address)} (section {constraint.name}) with size {constraint.size}\n")
                            f.write(f"\t[{i+1}/{len(parsed_constraints)}] Value of the global should be: {analyzer.dump_memory_content(constraint.address, constraint.size, found)}\n")
                    else:
                        f.write("[!] No global variable found in the constraints.\n")

                    f.write("[+] Constraints\n")
                    constraints = found.solver.constraints
                    for i, constraint in enumerate(constraints):
                        f.write(f"{[i+1]/len(constraints)} {constraint}")

            else:
                f.write("[!] No solution could be found.\n")

        end = time.time()
        f.write(f"[+] Symbolic execution of function {fn_name} completed in {end - start} seconds.")

if __name__ == '__main__':
    symex(*sys.argv[1:])
