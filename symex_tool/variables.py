import angr
import claripy
from typing import List
from copy import deepcopy
from collections import namedtuple

Struct      = namedtuple('Struct', ('size', 'fields'))
StructField = namedtuple('StructField', ('name', 'type', 'offset', 'size'))

class Variable:
    def __init__(self, name=None, type=None, size=0, address=0, concrete=False, value=None):
        '''This class will represent a "simple" variable in the program.
        If type is None, then it is assumed to be a global variable.
        '''

        self.name     = name
        self.type     = type
        self.size     = size
        self.address  = address
        self.concrete = concrete
        self.value    = value
        self.bv       = None

    def __repr__(self):
        return f'<Variable name={self.name}, type={self.type}, size=0x{self.size:x}, addr={hex(self.address)}>'

class StructPointer:
    '''This class will represent a function pointer function parameter, which
    needs more complex handling.
    '''
    def __init__(self, struct_name: str, name: str, size: int, fields: dict):
        self.struct_name = struct_name
        self.name        = name
        self.size        = size
        self.fields      = fields
        self.value       = None # Address to assign if/when concretized

        # Pointer as a bitvector for symbolic execution
        self.bv = claripy.BVS(f'ptr_{self.name}_{id(self)}', 64)

    def __repr__(self):
        v = hex(self.value) if self.value is not None else None
        return f'<Pointer to {self.name!r}, bv={self.bv!r}, size=0x{self.size:x}, value={v}>'

    def flatten(self) -> List['Pointer']:
        res = [self]
        for field in self.fields.values():
            if isinstance(field, self.__class__):
                res += field.flatten()
        return res

    def eval(self, state: angr.sim_state.SimState, indent=0) -> dict:
        res = '<struct pointer> ' + self.struct_name + ' {\n'
        others = []
        solver = state.solver

        if self.value is None:
            data = solver.eval(state.memory.load(self.bv, self.size), cast_to=bytes)
        else:
            data = solver.eval(state.memory.load(self.value, self.size), cast_to=bytes)

        for off, field in self.fields.items():
            if isinstance(field, self.__class__):
                if field.value is None:
                    res += '\t' * indent + f'\t{field.name} = {solver.eval(field.bv, cast_to=bytes).hex()}\n'
                else:
                    sub = field.eval(state, indent + 1)
                    res += '\t' * indent + f'\t{field.name} = {sub}\n'
            else:
                name, size = field
                res += '\t' * indent + f'\t{name} = {data[off:off + size].hex()}\n'

        return res + '\t' * indent + '}'
