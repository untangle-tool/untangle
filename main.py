#! /usr/bin/env python
import argparse
import os
import subprocess
import sys
import time

OUT_DIR = 'output_dir'

def parse_arguments():
    """ Parse the program's arguments. """

    description = """
        Full pipeline including function pointer discovery and symbolic execution.
    """

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-i', '--input', action='append', nargs=2, metavar=('input_file', 'lib_name'), help="Name of the input file and of the library.")

    return vars(parser.parse_args())

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
    
    # Replicate the hierarchy "function pointer" -> "caller" -> "function to execute"
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

    # Convert the output into the format requested by symex.py
    temporary_results = []
    for func_ptr in output_hierarchy:
        for caller in output_hierarchy[func_ptr]:
            function_list = output_hierarchy[func_ptr][caller]
            for func in function_list:
                function_name = func.split(' ')[2].strip()
                result = {}
                result['function_ptr_name'] = func_ptr
                result['function_name'] = function_name
                result['params_sizes'] = []
                signature = func.split('signature')[1].strip().split(', ')
                for param in signature:
                    result['params_sizes'].append(resolve_type_size(param))
                temporary_results.append(result)
    
    # Remove duplicates
    parsed_results = []
    for result in temporary_results:
        if result not in parsed_results:
            parsed_results.append(result)
    
    return parsed_results

def symex(args, out_file):
    """
    Run symex.py with the given arguments, using out_file as the output file.
    """
    pass

def main():
    
    if not os.path.exists(OUT_DIR):
        os.mkdir(OUT_DIR)

    inputs = parse_arguments()['input']

    for i, entry in enumerate(inputs):
        funcptr_out_fname = entry[0]
        lib_name = entry[1]

        print(f"[*] Starting analysis {i+1} out of {len(inputs)}: library {lib_name}")

        if not os.path.exists(os.path.join(OUT_DIR, lib_name)):
            os.mkdir(os.path.join(OUT_DIR, lib_name))
        
        parsed_results = parse_results(funcptr_out_fname)
        for result in parsed_results:
            print(f"\t[*] Starting symbolic execution of function {result['function_name']}")
            symex_out_file = os.path.join(OUT_DIR, lib_name, 'symex_out_' + result['function_ptr_name'] + '_' + result['function_name'] + '.txt')
            symex_args = [lib_name]
            symex_args.append(result['function_name'])
            symex_args.append("TARGETFUNC")
            for j, param_size in enumerate(result['params_sizes']):
                symex_args.append("-p")
                symex_args.append(f"param_{j}")
                symex_args.append("type")
                symex_args.append(f"{param_size}")
            
            with open(symex_out_file, "w") as f:
                start = time.time()
                subprocess.run(['python', 'symex.py', *symex_args], stdout=f)
                total_time = time.time() - start
                f.write(f"\n\n[*] Total time: {total_time}")

        print(*parsed_results, sep='\n')
        print(len(parsed_results))

if __name__ == '__main__':
    main()