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
        return f"Name:{self.name}, type:{self.type}, size {self.size}, addr {hex(self.address)}"