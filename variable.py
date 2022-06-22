class Variable:
    def __init__(self, name, type, size):
        self.name = name
        self.type = type
        self.size = size

    def set_address(self, address):
        self.address = address