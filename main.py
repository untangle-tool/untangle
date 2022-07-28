#! /usr/bin/env python
import argparse
import os
import subprocess
import sys

def parse_arguments():
    """ Parse the program's arguments. """

    description = """
        Full pipeline including function pointer discovery and symbolic execution.
    """

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('codeql_db', nargs='+', help="Path to the CodeQL database.")

    return vars(parser.parse_args())

def find_function_pointers(codeql_db_path: str, out_file_name: str):
    """
    Find function pointers in the given CodeQL database.
    """
    with open(out_file_name, 'w') as f:
            subprocess.run(['./find_func_ptrs.py', codeql_db_path], stdout=f)

# This function probably needs additional arguments (library src path, build command)
def recompile_library(out_file):
    """
    Recompile the libraries substituting the call to the function pointer with a call to TARGETFUNC.
    """
    # Filter the lines in out_file containing "called from X at filename"
    # For each line:
    # - Get the filename
    # - Get the line and column number
    # - Create a function with the following signature: void TARGETFUNC(void)
    # - Substitute the call to the function pointer with a call to TARGETFUNC
    # - Write the new source to the src file
    pass

def resolve_type_size(type_name: str):
    """
    Returns the size of the given type.
    """
    match type_name:
        case 'int':
            size = 4
        case 'long':
            size = 8
        case type_name if '*' in type_name:
            size = 8
        case 'char':
            size = 1
        case 'void':
            size = 0
        case 'float':
            size = 4
        case 'double':
            size = 8
        case 'long double':
            size = 16
        case 'long long':
            size = 8
        case 'unsigned long long':
            size = 8
        case 'unsigned int':
            size = 4
        case 'unsigned long':
            size = 8
        case 'unsigned char':
            size = 1
        case 'unsigned short':
            size = 2
        case _:
            size = 0
    return size

def parse_results(out_file_name: str):
    """
    Parse the results from the output file of find_func_ptrs.py and convert them into the format requested by symex.py.
    The result will be a list of dictionaries the form:
    [
        {
            'function_name': 'fname1',
            'function_ptr_name': 'fptr1',
            'params_sizes': [size1, size2, ...]
        },
        ...
    ]
    """
    with open(out_file_name, 'r') as f:
        lines = f.readlines()
    
    output_hierarchy = {}
    for line in lines:
        if 'declared' in line:
            func_ptr_name = line.split(' ')[0].strip()
            curr_func_ptr = func_ptr_name
            output_hierarchy[curr_func_ptr] = {}
        elif 'called from' in line:
            caller_name = line.split(' ')[2].strip()
            curr_caller = caller_name
            output_hierarchy[curr_func_ptr][curr_caller] = []
        else:
            output_hierarchy[curr_func_ptr][curr_caller].append(line.strip())

    parsed_results = []
    for func_ptr in output_hierarchy:
        for caller in output_hierarchy[func_ptr]:
            result = {}
            result['function_ptr_name'] = func_ptr
            
            function_list = output_hierarchy[func_ptr][caller]
            for func in function_list:
                function_name = func.split(' ')[2].strip()
                result['function_name'] = function_name
                result['params_sizes'] = []
                signature = func.split('signature')[1].strip().split(', ')
                for param in signature:
                    result['params_sizes'].append(resolve_type_size(param))

            parsed_results.append(result)
    
    return parsed_results

def symex(args, out_file):
    """
    Run symex.py with the given arguments, using out_file as the output file.
    """
    pass

def main():
    
    # Parse arguments
    # - List of codeql databases

    # For each CodeQL database:
    # - Run find_func_ptrs.py as subprocess, saving its output to a file

    # - Parse the results from the output file of find_func_ptrs.py
    # - Convert the results in the appropriate format for symex.py

    # - Create an output file for each library / function pointer (TBD)
    # - Run symex.py, with the appropriate arguments, as subprocess, recording the time it takes to run

    # The output of the two scripts should only be placed in appropriate files.
    # The output of this script should only be things like:
    # - Found function pointers for library X
    # - Executing function X out of Y for library Z

    OUT_DIR = 'output_dir'
    if not os.path.exists(OUT_DIR):
        os.mkdir(OUT_DIR)

    codeql_dbs = parse_arguments()['codeql_db']

    for db in codeql_dbs:
        funcptr_out_file = os.path.join(OUT_DIR, 'funcptr_out_' + os.path.basename(db))
        find_function_pointers(db, funcptr_out_file)
        # recompile_library(funcptr_out_file)
        parsed_results = parse_results(funcptr_out_file)
        for func in parsed_results:
            # Build the arguments for symex.py
            # - Library name
            # - Function name (func['function_name'])
            # - Target function name (TARGETFUNC)
            # - List of parameters (auto-generated names, sizes taken from func['params_sizes'])
            symex_out_file = os.path.join(OUT_DIR, 'symex_out_' + func)


if __name__ == '__main__':
    main()