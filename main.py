#!/usr/bin/python3

import angr
import argparse
import os
import sys

C_FILE_NAME = "temp"

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

def create_C_file(library_name: str, function_name: str, params: list):
    """ Function that creates a C file (from a template) that links the specified library and calls the specified function. """
    code = f"#include \"{library_name}.h\"\n"
    code += "#include <stdio.h>\n"
    code += "#include <stdlib.h>\n"
    code += "int main(int argc, char ** argv){\n"

    for i, param in enumerate(params, start=1):
        if param[1] == "char":
            code += f"\t{param[1]} {param[0]} = *argv[{i}];\n"
        elif param[1] == "char*":
            code += f"\t{param[1]} {param[0]} = argv[{i}];\n"
        elif param[1] == "float":
            code += f"\t{param[1]} {param[0]} = atof(argv[{i}]);\n"
        else:
            code += f"\t{param[1]} {param[0]} = atoi(argv[{i}]);\n"
    
    code += f"\t{function_name}("
    for param in params:
        code += f"{param[0]}, "
    
    if len(params) != 0:
        # If the function has one or more parameters, truncate the last ", ".
        code = code[:-2] 
    
    code += ");\n"
    code += "\treturn 0;\n}"
    
    with open(C_FILE_NAME + ".c", "w") as f:
        f.write(code)

def create_binary(library_name: str):
    os.system(f"gcc -o {C_FILE_NAME} {C_FILE_NAME}.c {library_name}.a")

def symbolically_execute(function_name: str, params: list):
    proj = angr.Project(f'./{C_FILE_NAME}')

def main():
    args = parseArguments()
    
    library_name = args['library_name']
    function_name = args['function_name']
    target_fn_name = args['target_fn_name']
    params = []
    if args['parameter']:
        for p in args['parameter']:
            try:
                params.append([p[0], p[1], int(p[2])])
            except ValueError:
                print("The size should be an integer.")
                sys.exit(0)

    create_C_file(library_name=library_name, function_name=function_name, params=params)
    create_binary(library_name=library_name)
    symbolically_execute(function_name=function_name, params=params)


if __name__ == '__main__':
    main()