#!/usr/bin/python3

import argparse
import os
import sys

from analyzer import Analyzer
from variable import Variable

C_FILE_NAME = "temp"
LIBS_DIR = "libs"

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

def main():
    args = parseArguments()
    
    library_name = args['library_name']
    function_name = args['function_name']
    target_fn_name = args['target_fn_name']
    params = []
    if args['parameter']:
        for param in args['parameter']:
            try:
                params.append(Variable(param[0], param[1], int(param[2])))
            except ValueError:
                print("The size should be an integer.")
                sys.exit(0)

    
    analyzer = Analyzer(binary_name=os.path.join('libs', library_name), function_name=function_name, target_function=target_fn_name)
    execute = True

    while execute:
        found = analyzer.symbolically_execute(parameters=params)
        execute = False

        if found:
            print("<--- Function arguments --->")
            evaluated_params = analyzer.eval_args(found)
            for i, param in enumerate(evaluated_params):
                params[i].value = param
                params[i].concrete = True
                print(f"*\t{params[i].name} = {param}")

            print("<--- Global variables --->")
            global_constraints = analyzer.find_globals(found)

            for c in global_constraints:
                if 'if' in c or 'else' in c or 'then' in c:
                    print("Possible global array found. Executing again.")
                    execute = True

            if not execute:
                parsed_constraints = analyzer.parse_constraints(global_constraints)
                for constraint in parsed_constraints:
                    print(f"*\tGlobal found at offset {hex(constraint.address)} (section {constraint.name}) with size {constraint.size}")
                    print(f"*\tValue of the global should be: {analyzer.dump_memory_content(constraint.address, constraint.size, found)}")
        else:
            print("No solution could be found.")

if __name__ == '__main__':
    main()