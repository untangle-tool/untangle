#!/usr/bin/python3

import time
import logging
from typing import List
from collections import deque

from .analyzer import Analyzer
from .variable import Variable
from .extract import parse_struct_ptr
from .memory import CustomMemory


logger = logging.getLogger('symex')


SCALARS = {
    'bool'              : 1,
    'char'              : 1,
    'unsigned char'     : 1,
    'short'             : 2,
    'unsigned short'    : 2,
    'int'               : 4,
    'unsigned int'      : 4,
    'long'              : 8,
    'unsigned long'     : 8,
    'long long'         : 8,
    'unsigned long long': 8,
    'float'             : 4,
    'double'            : 8,
    'long double'       : 16,
    'ptr'               : 8,
}


def parse_signature(signature: str, structs: dict) -> List[Variable]:
    res = []
    signature = signature.split(', ')

    for i, param in enumerate(signature):
        typ = param.replace('*', '').strip()

        if param == 'void':
            assert len(signature) == 1
            return []

        if typ in SCALARS:
            size = SCALARS[typ]
            res.append(Variable(f'param_{i}', typ, size))
        else:
            if param.count('*') == 1 and typ in structs:
                p = parse_struct_ptr(typ, structs)
                if p is None:
                    logger.warning('Unknown type %r', typ)

                res.append(p)
                continue

            if '*' in param:
                typ = 'ptr'
                size = 8
            else:
                size = SCALARS[typ]

            res.append(Variable(f'param_{i}', typ, size))

    assert len(res) == len(signature), f'{signature!r}\n{res!r}'
    return res


def symex(fn_name: str, target_fn_name: str, signature: str, structs: dict, binary: str, out_file: str):
    params = parse_signature(signature, structs)
    analyzer = Analyzer(binary, fn_name, target_fn_name)
    execute = True

    # TODO: maybe take these as parameters
    timeout = 15 * 60 # 15 min
    max_mem = 16 * 1000 * 1000 * 1000 # 16GB

    with open(out_file, 'w') as f:
        if any(param.size is None for param in params):
            execute = False
            f.write(f"[!] Skipping execution of function {fn_name}:\n")
            for param in params:
                if param.size is None:
                    f.write(f"\t[!] Unknown type {param.type}\n")

        start = time.monotonic()
        while execute:
            f.write(f"[+] Starting symbolic execution of function {fn_name}\n")
            found = analyzer.symbolically_execute(params, timeout, max_mem)
            # TODO: CustomMemory.eval_tracked_objects()

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

        end = time.monotonic()
        f.write(f"[+] Symbolic execution of function {fn_name} completed in {end - start} seconds.")
