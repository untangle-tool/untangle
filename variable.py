class Variable:
    def __init__(self, name=None, type=None, size=0, address=0):
        """ This class will represent a variable in the program. 
            If type is None, then it is assumed to be a global variable.
        """

        self.name = name
        self.type = type
        self.size = size

    def set_address(self, address):
        self.address = address