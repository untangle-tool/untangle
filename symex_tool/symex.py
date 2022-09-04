#!/usr/bin/python3

import os
import time
import logging
from typing import List
from collections import deque

from .variables import Variable
from .parser import parse_signature
from .memory import CustomMemory
from .utils import cur_memory_usage
from .executor import Executor, SymbolNotFound, OutOfMemory, TimeoutExceeded, SymexecFailed


logger = logging.getLogger('symex')


def symex(fn_name: str, signature: str, call_loc_info: dict, structs: dict, binary: str, out_file: str):
    params = parse_signature(signature, structs)
    executor = Executor(binary)
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
                found, exec_mem_usage = executor.symbolically_execute(fn_name, params, timeout, max_mem)
            except (SymbolNotFound, OutOfMemory, TimeoutExceeded, SymexecFailed) as e:
                err = repr(e)
                logger.error(err)
                fout.write('[!] ' + err + '\n')
                break

            mem_usage = max(mem_usage, exec_mem_usage)
            execute = False

            if found is not None:
                call_id = executor.call_id_from_found_state(found)
                fptr_name, location = call_loc_info[call_id]
                fname, lineno = location[:2]
                fout.write(f'[+] Reached call to {fptr_name} at {fname} line {lineno}\n')

                # Find constraints on global variables
                global_constraints = executor.find_globals(found)
                for c in global_constraints:
                    if 'if' in c or 'else' in c or 'then' in c:
                        logger.info('Complex constraint on global variable found, executing again.')
                        fout.write('[+] Complex constraint on global variable found, executing again.\n')
                        execute = True

                if not execute:
                    if len(params) != 0:
                        # Evaluate parameters involved in constraints.
                        evaluated_params = executor.eval_args(found)

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

                    parsed_constraints = executor.parse_constraints(global_constraints)
                    if len(parsed_constraints) != 0:
                        fout.write("[+] Global variables\n")
                        for i, constraint in enumerate(parsed_constraints):
                            off = hex(constraint.address - executor.BASE_ADDR)
                            fout.write(f"\t[{i+1}/{len(parsed_constraints)}] Global found at offset {off} (section {constraint.name}) with size {constraint.size}\n")
                            fout.write(f"\t[{i+1}/{len(parsed_constraints)}] Value of the global should be: {executor.dump_memory_content(constraint.address, constraint.size, found)}\n")
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
