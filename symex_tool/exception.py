class SectionException(Exception):
    """ Raised when neither .bss or .data can be found in the constraint."""
    pass
