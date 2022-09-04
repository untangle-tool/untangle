#!/usr/bin/python3

import os
import time
import logging
from typing import List
from collections import deque

from .variable import Variable
from .extract import parse_struct_ptr
from .memory import CustomMemory
from .utils import cur_memory_usage
from .analyzer import Analyzer, SymbolNotFound, OutOfMemory, TimeoutExceeded
from .analyzer import SymexecFailed


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
        if param[-1] == ']':
            # Turn `type[n]` into `type *`
            param = param[:param.rfind('[')] + ' *'

        typ = param.replace('*', '').strip()

        if param == 'void':
            assert len(signature) == 1
            return []

        if typ in SCALARS:
            size = SCALARS[typ]
            res.append(Variable(f'param_{i}', typ, size))
        else:
            if param.count('*') == 1 and typ in structs:
                p = parse_struct_ptr(f'param_{i}', typ, structs)
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


def symex(fn_name: str, signature: str, call_loc_info: dict, structs: dict, binary: str, out_file: str):
    params = parse_signature(signature, structs)
    analyzer = Analyzer(binary)
    execute = True

    timeout = 15 * 60 # 15 min
    max_mem = 16 << 30 # 16GiB

    with open(out_file, 'w') as fout:
        if any(param.size is None for param in params):
            execute = False
            fout.write(f"[!] Skipping execution of function {fn_name}:\n")
            for param in params:
                if param.size is None:
                    fout.write(f"\t[!] Unknown type {param.type}\n")

        mem_usage = cur_memory_usage()
        start = time.monotonic()

        while execute:
            fout.write(f"[+] Starting symbolic execution of function {fn_name}\n")

            try:
                found, exec_mem_usage = analyzer.symbolically_execute(fn_name, params, timeout, max_mem)
            except (SymbolNotFound, OutOfMemory, TimeoutExceeded, SymexecFailed) as e:
                err = repr(e)
                logger.error(err)
                fout.write('[!] ' + err + '\n')
                break

            mem_usage = max(mem_usage, exec_mem_usage)
            execute = False

            if found is not None:
                call_id = analyzer.call_id_from_found_state(found)
                fptr_name, location = call_loc_info[call_id]
                fname, lineno = location[:2]
                fout.write(f'[+] Reached call to {fptr_name} at {fname} line {lineno}\n')

                # Find constraints on global variables
                global_constraints = analyzer.find_globals(found)
                for c in global_constraints:
                    if 'if' in c or 'else' in c or 'then' in c:
                        logger.info('Complex constraint on global variable found, executing again.')
                        fout.write('[+] Complex constraint on global variable found, executing again.\n')
                        execute = True

                if not execute:
                    if len(params) != 0:
                        # Evaluate parameters involved in constraints.
                        evaluated_params = analyzer.eval_args(found)

                        if not evaluated_params or all(p is None for p in evaluated_params):
                            fout.write("[!] No function argument was involved in any constraint.\n")
                        else:
                            fout.write("[+] Function arguments\n")
                            for i, param in enumerate(evaluated_params):
                                if param is None:
                                    fout.write(f"\t[{i+1}/{len(evaluated_params)}] {params[i].name} = <unconstrained>\n")
                                else:
                                    fout.write(f"\t[{i+1}/{len(evaluated_params)}] {params[i].name} = {param}\n")
                    else:
                        fout.write("[!] No function argument to evaluate.\n")

                    parsed_constraints = analyzer.parse_constraints(global_constraints)
                    if len(parsed_constraints) != 0:
                        fout.write("[+] Global variables\n")
                        for i, constraint in enumerate(parsed_constraints):
                            off = hex(constraint.address - analyzer.BASE_ADDR)
                            fout.write(f"\t[{i+1}/{len(parsed_constraints)}] Global found at offset {off} (section {constraint.name}) with size {constraint.size}\n")
                            fout.write(f"\t[{i+1}/{len(parsed_constraints)}] Value of the global should be: {analyzer.dump_memory_content(constraint.address, constraint.size, found)}\n")
                    else:
                        fout.write("[!] No global variable found in the constraints.\n")

                    fout.write("[+] Constraints\n")
                    constraints = found.solver.constraints
                    for i, constraint in enumerate(constraints):
                        fout.write(f"\t{i+1}/{len(constraints)} {constraint}\n")

            else:
                fout.write("[!] No solution could be found.\n")

        end = time.monotonic()
        fout.write(f"[+] Completed in {end - start:.0f} seconds, using {mem_usage / 1024 / 1024:.0f} MiB of memory.\n")
