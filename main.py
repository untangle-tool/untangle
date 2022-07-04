#!/usr/bin/python3

import argparse
import os
import sys

from analyzer import Analyzer
from variable import Variable

C_FILE_NAME = "temp"
BASE_ADDR = 0x400000

def parseArguments():
    """ Parse the program's arguments. """

    description = """
        Symbolic Execution tool to find the values that need to be passed to parameters to get to a vulnerable function call.
    """

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('library_name', help="Name of the library containing the function.")
    parser.add_argument('function_name', help="Name of the function containing the vulnerable function call.")
    parser.add_argument('-p', '--parameter', action='append', nargs=3, metavar=('param_name', 'param_type', 'param_size'), help="Name, type and size of the parameter(s) of the function.")
    parser.add_argument('target_fn_name', help="Name of the target function to be reached through symbolical execution.")

    return vars(parser.parse_args())

def create_C_file(library_name: str, function_name: str, params: list[Variable]):
    """ Function that creates a C file (from a template) that links the specified library and calls the specified function. """
    code = f"#include \"{library_name}.h\"\n"
    code += "#include <stdio.h>\n"
    code += "#include <stdlib.h>\n"
    code += "int main(int argc, char ** argv){\n"

    for i, param in enumerate(params, start=1):
        if param.type == "char":
            code += f"\t{param.type} {param.name} = *argv[{i}];\n"
        elif param.type == "char*":
            code += f"\t{param.type} {param.name} = argv[{i}];\n"
        elif param.type == "void*":
            code += f"\t{param.type} {param.name} = argv[{i}];\n" 
        elif param.type == "float":
            code += f"\t{param.type} {param.name} = atof(argv[{i}]);\n"
        else:
            code += f"\t{param.type} {param.name} = atoi(argv[{i}]);\n"

    code += f"\t{function_name}("
    for param in params:
        code += f"{param.name}, "
    
    if len(params) != 0:
        # If the function has one or more parameters, truncate the last ", ".
        code = code[:-2] 
    
    code += ");\n"
    code += "\treturn 0;\n}"
    
    with open(C_FILE_NAME + ".c", "w") as f:
        f.write(code)

def create_binary(library_name: str):
    os.system(f"gcc -o {C_FILE_NAME} {C_FILE_NAME}.c {library_name}.a")

def main():
    args = parseArguments()
    
    library_name = args['library_name']
    function_name = args['function_name']
    target_fn_name = args['target_fn_name']
    params = []
    if args['parameter']:
        for p in args['parameter']:
            try:
                params.append(Variable(p[0], p[1], int(p[2])))
            except ValueError:
                print("The size should be an integer.")
                sys.exit(0)

    create_C_file(library_name=library_name, function_name=function_name, params=params)
    create_binary(library_name=library_name)

    analyzer = Analyzer(C_FILE_NAME, target_function=target_fn_name, parameters=params)
    found = analyzer.symbolically_execute()
    if found:
        print("<--- Function arguments --->")
        evaluated_params = analyzer.eval_args(found)
        for i, param in enumerate(evaluated_params):
            print(f"*\t{params[i].name} = {param}")

        print("<--- Global variables --->")
        global_constraints = analyzer.find_globals(found)
        parsed_constraints = analyzer.parse_constraints(global_constraints)
        for constraint in parsed_constraints:
            print(f"*\tGlobal found at offset {hex(constraint.address)} (section {constraint.name}) with size {constraint.size}")
            print(f"*\tValue of the global should be: {analyzer.dump_memory_content(constraint.address, constraint.size, found)}")
    else:
        print("No solution could be found.")

if __name__ == '__main__':
    main()