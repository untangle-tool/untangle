import angr
import claripy
from exception import SectionException

from variable import Variable

class Analyzer:
    BASE_ADDR = 0x000000

    def __init__(self, binary_name: str, target_function: str, parameters: list[Variable]):
        self.binary_name = binary_name
        self.target_function = target_function
        self.parameters = parameters

        self.proj = angr.Project(f'./{self.binary_name}', main_opts={'base_addr': self.BASE_ADDR})
        self.symbolic_sections = []

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
    def symbolically_execute(self):
        """ Setup symbolic execution and search a path to the target function. Then, print the values of the parameters. """
        args = [f'./{self.binary_name}']
        for param in self.parameters:
            args.append(claripy.BVS(param.name, param.size))

        target_sym = self.proj.loader.find_symbol(self.target_function)

        state = self.proj.factory.entry_state(args=args, add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY})
        self.__make_section_symbolic('.bss', state)
        self.__make_section_symbolic('.data', state)

        simgr = self.proj.factory.simulation_manager(state)
        simgr.explore(find=target_sym.rebased_addr)

        if len(simgr.found) > 0:
            found = simgr.found[0]
            print("Values of the parameters:")
            for i, arg in enumerate(args[1:]):
                print(f"{self.parameters[i].name} = {found.solver.eval(arg, cast_to=bytes).decode()}")

            for arg in args[1:]:
                print(arg)

            for sect in self.symbolic_sections:
                print(f"{sect} = {found.solver.eval(sect, cast_to=bytes)}")
