import os
import time
import angr
import claripy
import psutil
import logging
from typing import List, Union
from angr.sim_type import SimTypeFunction

from .variables import Variable, StructPointer
from .memory import CustomMemory
from .utils import malloc_trim, cur_memory_usage

logger = logging.getLogger('executor')


class MatchNotFound(Exception):
    '''Raised when no location to reach is found according to the given filters
    on function pointer name and location.
    '''
    pass


class SymbolNotFound(Exception):
    '''Raised when a symbol is not found in the given binary.'''
    pass


class SymexecFailed(Exception):
    '''Raised when an internal angr/claripy error caused symbolic execution to
    fail.'''
    pass


# Angr can only deal with CLOCK_REALTIME... force CLOCK_REALTIME regardless of
# the requested clock for simplicity's sake.
class clock_gettime(angr.SimProcedure):
    def run(self, which_clock, timespec_ptr):
        which_clock = 0 # CLOCK_REALTIME

        if self.state.solver.is_true(timespec_ptr == 0):
            return -1

        if angr.options.USE_SYSTEM_TIMES in self.state.options:
            flt = time.time()
            result = {'tv_sec': int(flt), 'tv_nsec': int(flt * 1000000000)}
        else:
            result = {
                'tv_sec': self.state.solver.BVS('tv_sec', self.arch.bits, key=('api', 'clock_gettime', 'tv_sec')),
                'tv_nsec': self.state.solver.BVS('tv_nsec', self.arch.bits, key=('api', 'clock_gettime', 'tv_nsec')),
            }

        self.state.mem[timespec_ptr].struct.timespec = result
        return 0


class Executor:
    BASE_ADDR = 0x400000

    def __init__(self, binary_name: str, call_loc_info: dict, filter_fptr = None, filter_loc: str = None):
        self.binary_name = binary_name
        self.symbolic_sections = []
        self.call_loc_info = call_loc_info
        self.filter_fptr = filter_fptr
        self.filter_loc = filter_loc
        self.proj = angr.Project(f'./{self.binary_name}', main_opts={'base_addr': self.BASE_ADDR})
        self.proj.hook_symbol('clock_gettime', clock_gettime(), replace=True)

    def __make_section_symbolic(self, section_name: str, state: angr.sim_state.SimState):
        section = claripy.BVS(section_name, self.proj.loader.main_object.sections_map[section_name].memsize * 8)
        state.memory.store(self.proj.loader.main_object.sections_map[section_name].vaddr, section)

        self.symbolic_sections.append(section)

    def find_globals(self, state: angr.sim_state.SimState):
        constraints = state.solver.constraints

        global_constraints = []
        for c in constraints:
            if '.bss' in str(c) or '.data' in str(c):
                global_constraints.append(str(c))

        return global_constraints

    def parse_constraints(self, constraints: List[str]):
        '''Parse the constraints and return a list of tuples containing section,
        size and address.
        '''
        parsed_constraints = []
        for c in constraints:
            start_index = c.find('[')
            end_index = c.find(']')

            size_slice = c[start_index+1:end_index]
            max_pos, min_pos = size_slice.split(':')
            max_pos, min_pos = int(max_pos), int(min_pos)

            size = (max_pos - min_pos + 1) // 8

            if '.bss' in c:
                section = '.bss'
            elif '.data' in c:
                section = '.data'
            else:
                logger.error('Could not find .bss or .data in constraint.')

            address = self.proj.loader.main_object.sections_map[section].vaddr + self.proj.loader.main_object.sections_map[section].memsize - ((max_pos+1) // 8)
            parsed_constraints.append(Variable(name=section, size=size, address=address))
        return parsed_constraints

    def dump_memory_content(self, at_address: int, size: int, state: angr.sim_state.SimState):
        '''Dump the memory content at the given address.'''
        return state.solver.eval(state.memory.load(at_address, size), cast_to=bytes).hex()

    def eval_args(self, state: angr.sim_state.SimState):
        '''Evaluate the arguments of the target function with the solver of the
         given state.
        '''
        res = []
        constraints = state.solver.constraints

        # Somehow the StructPointer objs here are not the same as the ones in
        # state.memory.tracked. Use those instead.
        args = []

        for i, arg in enumerate(self.args):
            if isinstance(arg, StructPointer):
                for ptr in state.memory.tracked:
                    if arg.name == ptr.name:
                        args.append(ptr)
                        break
                else:
                    args.append(arg)
            else:
                args.append(arg)

        for arg in args:
            if isinstance(arg, StructPointer):
                res.append(arg.eval(state, indent=1))
            else:
                # The name of a bitvector is stored in BV.args[0]
                involved_constraints = [c for c in constraints if arg.bv.args[0] in str(c)]

                if len(involved_constraints) > 0:
                    # Is this some tracked struct ptr + some offset?
                    val = state.solver.eval(arg.bv)
                    ptr, off = state.memory.tracked_pointer_offset(val)
                    if ptr is not None:
                        res.append(f'{ptr.full_name} + 0x{off:x}')
                        continue

                    arg.value = state.solver.eval(arg.bv, cast_to=bytes).hex()
                    arg.concrete = True
                    res.append(arg.value)
                else:
                    res.append(None)

        return res

    def call_id_from_target_symbol_name(self, name: str):
        '''Extract the call location id from a found state.
        '''
        assert name.startswith('SYMEX_TARGET_')
        return int(name[name.rfind('_') + 1:])

    def call_id_from_found_state(self, state: angr.sim_state.SimState):
        '''Extract the call location id from a found state.
        '''
        sym = self.proj.loader.find_symbol(state.addr)
        return self.call_id_from_target_symbol_name(sym.name)

    def symbolically_execute(self, function_name: str,
            parameters: List[Union[Variable,StructPointer]],
            dfs: bool = False):
        self.args = []
        self.ptrs = []

        sym_args  = []
        targets = {}
        mem_usage = cur_memory_usage()
        malloc_trim()

        for sym in self.proj.loader.symbols:
            if not sym.name.startswith('SYMEX_TARGET_'):
                continue

            call_id = self.call_id_from_target_symbol_name(sym.name)
            fptr_name, call_loc, reachable_from = self.call_loc_info[call_id]
            if function_name not in reachable_from:
                continue

            call_loc_str = ':'.join(map(str, call_loc))
            loc_ok = self.filter_loc is None or call_loc_str == self.filter_loc
            fptr_ok = self.filter_fptr is None or self.filter_fptr.search(fptr_name) is not None

            if loc_ok and fptr_ok:
                targets[sym.rebased_addr] = (fptr_name, call_loc_str)

        target_addrs = list(targets)

        if self.filter_loc is not None or self.filter_fptr is not None:
            if len(target_addrs) == 0:
                raise MatchNotFound(f'No function pointer call reachable from "{function_name}" matches the given filters')
            elif len(target_addrs) == 1:
                fptr_name, call_loc_str = targets[target_addrs[0]]
                logger.info('Symbolically executing %s to reach the call to %s at %s', function_name, fptr_name, call_loc_str)
            else:
                logger.info('Symbolically executing %s to reach any of %d target locations', function_name, len(targets))

        for param in parameters:
            if isinstance(param, StructPointer):
                self.args.append(param)
                self.ptrs.append(param)
                sym_args.append(param.bv)
            else:
                if param.concrete:
                    param.bv = claripy.BVV(param.value, param.size * 8)
                    self.args.append(param)
                else:
                    param.bv = claripy.BVS(param.name, param.size * 8)
                    self.args.append(param)

                sym_args.append(param.bv)

        sym = self.proj.loader.find_symbol(function_name)
        if sym is None:
            raise SymbolNotFound(function_name)

        function_addr = sym.rebased_addr
        state_options = {
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
        }

        mem = CustomMemory(memory_id='mem', project=self.proj, tracked_ptrs=self.ptrs)

        prototype = SimTypeFunction([], None)
        state = self.proj.factory.call_state(
            function_addr,
            *sym_args,
            add_options=state_options,
            cc=self.proj.factory.cc(),
            prototype=prototype,
            plugins={'memory': mem}
        )

        if angr.options.ALL_FILES_EXIST in state.options:
            state.options.remove(angr.options.ALL_FILES_EXIST)

        self.__make_section_symbolic('.bss', state)
        self.__make_section_symbolic('.data', state)

        simgr = self.proj.factory.simulation_manager(state)
        if dfs:
            simgr.use_technique(tech=angr.exploration_techniques.DFS())

        start = time.monotonic()

        while 1:
            try:
                simgr.explore(find=target_addrs, n=1)
            except angr.errors.SimUnsatError as e:
                logger.error('Angr reported SimUnsatError: %r', e)
                raise SymexecFailed(e)
            except claripy.errors.UnsatError:
                logger.error('Claripy reported SimUnsatError: %r', e)
                raise SymexecFailed(e)
            except angr.errors.SimMemoryError as e:
                logger.error('Angr reported SimMemoryError: %r', e)
                raise SymexecFailed(e)
            except UnicodeDecodeError as e:
                # Really angr? Come on...
                logger.error('Angr choked on UTF-8: %s', e.reason)
                raise SymexecFailed(e)
            except ReferenceError as e:
                logger.error('ReferenceError during symbolic execution: %r', e)
                raise SymexecFailed(e)
            except AttributeError as e:
                if "'ErrorRecord' object has no attribute 'history'" in rerp(e):
                    logger.error('Angr choked while trying to report a SimUnsatError: %r', e)
                    raise SymexecFailed(e)
                raise e
            except ValueError as e:
                if 'arg is an empty sequence' in repr(e):
                    logger.error('Angr choked: %r', e)
                    raise SymexecFailed(e)
                raise e


            if simgr.found:
                return simgr.found[0], mem_usage

            if not simgr.active:
                break

            mem_usage = max(mem_usage, cur_memory_usage())
            malloc_trim()

        return None, mem_usage
