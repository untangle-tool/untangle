#!/usr/bin/python3

import os
import sys
import time
import logging
import angr
import claripy
from typing import List
from collections import deque
from subprocess import check_output, check_call, DEVNULL, CalledProcessError
from tempfile import NamedTemporaryFile
from multiprocessing import Process

from .variables import Variable, StructPointer
from .parser import parse_signature
from .memory import CustomMemory
from .utils import cur_memory_usage
from .executor import Executor, MatchNotFound, SymbolNotFound, SymexecFailed


logger = logging.getLogger('symex')


def find_symbol_offset(binary: str, name: str):
    for line in check_output(['nm', binary], text=True).splitlines():
        if line.startswith(' '):
            continue

        line = line.strip().split()
        if line[-1] == name:
            return int(line[0], 16)

    return None


def symex(fn_name: str, signature: str, call_loc_info: dict,
        structs: dict, binary: str, verify: bool, dfs: bool, out_file: str,
        filter_fptr, filter_loc: str):
    params = parse_signature(signature, structs)
    executor = Executor(binary, call_loc_info, filter_fptr, filter_loc)
    execute = True

    found = None
    discard_output = False

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
            fout.write(f"[*] Starting symbolic execution of function {fn_name}\n")

            try:
                found, exec_mem_usage = executor.symbolically_execute(fn_name, params, dfs)
            except (SymbolNotFound, SymexecFailed) as e:
                err = repr(e)
                logger.error(err)
                fout.write('[!] ' + err + '\n')
                break
            except MatchNotFound as e:
                logger.debug(e.args[0])
                discard_output = True
                break

            mem_usage = max(mem_usage, exec_mem_usage)
            execute = False

            if found is not None:
                call_id = executor.call_id_from_found_state(found)
                fptr_name, location, _ = call_loc_info[call_id]
                fname, lineno = location[:2]
                fout.write(f'[+] Reached call to {fptr_name} at {fname} line {lineno}\n')

                # Find constraints on global variables
                global_constraints = executor.find_globals(found)
                for c in global_constraints:
                    if 'if' in c or 'else' in c or 'then' in c:
                        logger.info('Complex constraint on global variable found, executing again.')
                        fout.write('[*] Complex constraint on global variable found, executing again.\n')
                        execute = True

                if not execute:
                    if len(params) != 0:
                        # Evaluate parameters involved in constraints.

                        try:
                            evaluated_params = executor.eval_args(found)
                        except (angr.errors.SimUnsatError, claripy.errors.UnsatError) as e:
                            # Pretty weird, but apparently claripy/angr can report unsat even
                            # after getting to the solution... can't do much about it other
                            # than bail out.
                            err = repr(e)
                            logger.error('Failed evaluating parameters: %s', err)
                            fout.write('[!] Function argument evaluation failed: ' + err + '\n')
                            execute = False
                            found = None
                            break

                        if not evaluated_params or all(p is None for p in evaluated_params):
                            fout.write("[-] No function argument was involved in any constraint.\n")
                        else:
                            fout.write("[+] Function arguments\n")
                            for i, param in enumerate(evaluated_params):
                                if param is None:
                                    fout.write(f"\t[{i+1}/{len(evaluated_params)}] {params[i].name} = <unconstrained>\n")
                                else:
                                    fout.write(f"\t[{i+1}/{len(evaluated_params)}] {params[i].name} = {param}\n")
                    else:
                        fout.write("[-] No function argument to evaluate.\n")

                    parsed_constraints = executor.parse_constraints(global_constraints)
                    if len(parsed_constraints) != 0:
                        fout.write("[+] Global variables\n")
                        for i, constraint in enumerate(parsed_constraints):
                            off = hex(constraint.address - executor.BASE_ADDR)
                            fout.write(f"\t[{i+1}/{len(parsed_constraints)}] Global found at offset {off} (section {constraint.name}) with size {constraint.size}\n")
                            fout.write(f"\t[{i+1}/{len(parsed_constraints)}] Value of the global should be: {executor.dump_memory_content(constraint.address, constraint.size, found)}\n")
                    else:
                        fout.write("[-] No global variable found in the constraints.\n")

                    fout.write("[+] Constraints\n")
                    constraints = found.solver.constraints
                    for i, constraint in enumerate(constraints):
                        fout.write(f"\t{i+1}/{len(constraints)} {constraint}\n")

            else:
                fout.write("[-] No solution could be found.\n")

        if not discard_output:

            end = time.monotonic()
            fout.write(f"[+] Completed in {end - start:.0f} seconds, using {mem_usage / 1024 / 1024:.0f} MiB of memory.\n")

            if not verify or found is None:
                return

            # Try to verify correctness of solution compiling and running a test

            mem = found.memory.dump_tracked_memory()
            mem_content = ''

            if mem is not None:
                for b in mem:
                    mem_content += f'\\x{b:02x}'

            args = []
            argdefs = []
            argtypes = []

            for i, arg in enumerate(executor.args):
                if isinstance(arg, StructPointer):
                    for ptr in found.memory.tracked:
                        if arg.name == ptr.name:
                            args.append(ptr)
                            break
                    else:
                        args.append(arg)
                else:
                    args.append(arg)

            for i, arg in enumerate(args):
                if isinstance(arg, StructPointer):
                    if arg.value is not None:
                        off = arg.value - found.memory.alloc_base
                        argdefs.append(f'void *param_{i} = mem + 0x{off:x};')
                    else:
                        argdefs.append(f'void *param_{i} = NULL;')
                    argtypes.append('void *')
                else:
                    # Is this some tracked struct ptr + some offset?
                    val = found.solver.eval(arg.bv)
                    ptr, off = found.memory.tracked_pointer_offset(val)
                    if ptr is not None:
                        ptr_off = ptr.value - found.memory.alloc_base
                        argdefs.append(f'void *param_{i} = mem + 0x{ptr_off:x} + 0x{off:x};')
                        argtypes.append('void *')
                        continue

                    val = found.solver.eval(arg.bv)
                    argtype = 'void *' if arg.type == '*' else arg.type
                    argdefs.append(f'{argtype} param_{i} = ({argtype})0x{val:x};')
                    argtypes.append(argtype)

            symbol_offset = find_symbol_offset(binary, fn_name)
            if symbol_offset is None:
                logger.error('Verification error: could not find symbol "%s" in binary', fn_name)
                fout.write('[!] Verification errored')
                return

            with NamedTemporaryFile('w', prefix='symex-test', suffix='.c', delete=False) as f:
                f.write(VERIFY_C_SOURCE_TEMPLATE.format(
                    mem_content=mem_content,
                    libpath=binary,
                    symbol_offset=symbol_offset,
                    alloc_base=hex(found.memory.alloc_base),
                    argdefs='\n\t'.join(argdefs),
                    signature=', '.join(argtypes),
                    args=', '.join(f'param_{i}' for i in range(len(argdefs)))
                ))
                f.flush()
                f.truncate()

                try:
                    check_call(f'gcc -g -o /tmp/test "{f.name}" -ldl', shell=True, stdout=DEVNULL, stderr=DEVNULL)
                except CalledProcessError as e:
                    logger.error('Verification error while compiling: %r', e)
                    fout.write('[!] Verification errored while compiling test')
                    return

            os.remove(f.name)

            with NamedTemporaryFile('w', prefix='symex-test', suffix='.gdb', delete=False) as f:
                f.write(VERIFY_GDB_SCRIPT_TEMPLATE.format(
                    binary_name='/tmp/test',
                    libpath=binary,
                    symbol=f'SYMEX_TARGET_{fptr_name}_{call_id}'
                ))
                f.flush()
                f.truncate()

                try:
                    out = check_output(f'gdb -batch -x {f.name}', stderr=DEVNULL, shell=True, text=True)
                except CalledProcessError as e:
                    logger.error('Verification error while running GDB: %r', e)
                    fout.write('[!] Verification errored while running test')
                    return

            os.remove(f.name)

            if 'REACHED!' in out:
                logger.info('Verification OK')
                fout.write('[+] Verification successful')
                return

            logger.info('Verification FAIL')
            fout.write('[-] Verification failed')

    if discard_output:
        os.remove(out_file)


def symex_wrapper(fn_name: str, signature: str, call_loc_info: dict,
        structs: dict, binary: str, verify: bool, dfs: bool, out_file: str,
        max_mem: int, max_time: float, filter_fptr = None,
        filter_loc: str = None):
    max_mem *= 1024 * 1024 # MiB -> B
    args = (fn_name, signature, call_loc_info, structs, binary, verify, dfs, out_file, filter_fptr, filter_loc)
    proc = Process(target=symex, args=args, daemon=True)
    proc.start()

    start = time.monotonic()
    cur_mem = cur_memory_usage(proc.pid)
    cur_time = time.monotonic() - start

    while 1:
        proc.join(1)
        if proc.exitcode is not None:
            break

        cur_mem  = cur_memory_usage(proc.pid)
        cur_time = time.monotonic() - start

        if cur_mem > max_mem:
            proc.kill()
            info = f'{cur_mem / 1024 / 1024:.0f} MiB > {max_mem / 1024 / 1024:.0f} MiB'
            logger.error('Exceeded maximum memory usage: %s', info)

            with open(out_file, 'w') as f:
                f.write(f'[!] Exceeded maximum memory usage: {info}\n')
                f.write(f"[+] Completed in {cur_time:.0f} seconds, using {cur_mem / 1024 / 1024:.0f} MiB of memory.\n")
            break

        if cur_time > max_time:
            proc.kill()
            info = f'{cur_time:.2f}s > {max_time:.2f}s'
            logger.error('Exceeded maximum execution time: %s', info)

            with open(out_file, 'w') as f:
                f.write(f'[!] Exceeded maximum execution time: {info}\n')
                f.write(f"[+] Completed in {cur_time:.0f} seconds, using {cur_mem / 1024 / 1024:.0f} MiB of memory.\n")
            break

    if proc.exitcode is not None and proc.exitcode != 0:
        with open(out_file, 'w') as f:
            f.write(f'[!] Symexec failed: process returned {proc.exitcode}\n')
            f.write(f"[+] Completed in {cur_time:.0f} seconds, using {cur_mem / 1024 / 1024:.0f} MiB of memory.\n")


################################################################################


VERIFY_C_SOURCE_TEMPLATE = '''\
#include <dlfcn.h>
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>

const char mem_content[] = "{mem_content}";
const char libpath[] = "{libpath}";
unsigned long *lib;
unsigned char *mem;

void test_wrapper(void *fptr) {{
	{argdefs}
	((void (*)({signature}))fptr)({args});
}}

int main(void) {{
	mem = mmap((void *){alloc_base}, 0x100000, 0x7, MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	assert(mem != MAP_FAILED);

	memcpy(mem, mem_content, sizeof(mem_content));

	lib = dlopen("{libpath}", RTLD_LAZY);
	assert(lib != NULL);

	void *fptr = (void *)(*lib + {symbol_offset});
	test_wrapper(fptr);

	return 0;
}}
'''

VERIFY_GDB_SCRIPT_TEMPLATE = '''\
file {binary_name}
b test_wrapper
run
del

set $addr = *(unsigned long*)lib
add-symbol-file {libpath} -readnow -o $addr
b {symbol}
command
	silent
	printf "REACHED!\\n"
end

continue
'''
