import claripy
from copy import deepcopy

class Variable:
    def __init__(self, name=None, type=None, size=0, address=0, concrete=False, value=None):
        """ This class will represent a variable in the program.
            If type is None, then it is assumed to be a global variable.
        """

        self.name = name
        self.type = type
        self.size = size
        self.address = address
        self.concrete = concrete
        self.value = value

    def __repr__(self):
        return f'<Variable name={self.name}, type={self.type}, size=0x{self.size:x}, addr={hex(self.address)}>'

class Pointer:
    def __init__(self, name: str, size: int, fields: dict):
        self.name   = name
        self.size   = size
        self.fields = fields
        self.value  = None # Address to assign if/when concretized

        # Bitvector for symbolic execution
        self.bv = claripy.BVS(f'ptr_{self.name}_{id(self)}', 64)

    def __repr__(self):
        v = hex(self.value) if self.value is not None else None
        return f'<Pointer to {self.name!r}, bv={self.bv!r}, size=0x{self.size:x}, value={v}>'

    def flatten(self) -> list['Pointer']:
        res = [self]
        for field in self.fields.values():
            if isinstance(field, self.__class__):
                res += field.flatten()
        return res
