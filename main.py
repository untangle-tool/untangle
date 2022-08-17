#! /usr/bin/env python
import argparse
import os
import subprocess
import sys
import time

OUT_DIR = 'output_dir'
TYPE_SIZES = {
    "short": 8,
    "int": 4,
    "long": 8,
    "ptr": 8,
    "char": 1,
    "void": 0,
    "float": 4,
    "double": 8,
    "long double": 16,
    "long long": 8,
    "unsigned long long": 8,
    "unsigned short": 2,
    "unsigned int": 4,
    "unsigned long": 8,
    "unsigned char": 1,
    "bool": 1
}

def parse_arguments():
    """ Parse the program's arguments. """

    description = """
        Full pipeline including function pointer discovery and symbolic execution.
    """

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-i', '--input', action='append', nargs=2, metavar=('input_file', 'lib_name'), help="Name of the input file and of the library.")

    return vars(parser.parse_args())

def parse_results(out_file_name: str):
    """
    Parse the results from the output file of find_func_ptrs.py and convert them into the format requested by symex.py.
    The result will be a list of dictionaries the form:
    [
        {
            'function_name': 'fname1',
            'function_ptr_name': 'fptr1',
            'params_sizes': [size1, size2, ...],
            'pointer': [True, False, ...]
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
        for i, caller in enumerate(output_hierarchy[func_ptr]):
            function_list = output_hierarchy[func_ptr][caller]
            for func in function_list:
                function_sig = ' '.join(func.split(' ')[2:])
                function_name = func.split(' ')[2].strip()
                result = {
                    'function_ptr_name': func_ptr,
                    'function_name': function_name, 
                    'params_sizes': [],
                    'pointer': [],
                    'error': '',
                    'function_sig': function_sig,
                    'target_func': f"TARGET_{func_ptr}_{i}"
                }
                param_list = func.split('signature')[1].strip().split(', ')
                for param in param_list:
                    param_type = param.replace("*", "").strip()
                    if param_type not in TYPE_SIZES:
                        result['error'] += f"Unknown parameter type {param_type}\n"
                        result['params_sizes'].append(None)
                    else:
                        if "*" in param:
                            param_type = "ptr"
                        size = TYPE_SIZES[param_type]
                        result['params_sizes'].append(size)
                        
                    result['pointer'].append('*' in param)
                temporary_results.append(result)
    
    # Remove duplicates
    parsed_results = []
    for result in temporary_results:
        if not any([x['function_name'] == result['function_name'] and x['target_func'] == result['target_func'] for x in parsed_results]):
            parsed_results.append(result)
    
    return parsed_results

def main():
    
    if not os.path.exists(OUT_DIR):
        os.mkdir(OUT_DIR)

    inputs = parse_arguments()['input']

    for i, entry in enumerate(inputs):
        funcptr_out_fname = entry[0]
        lib_path = entry[1]

        lib_name = lib_path.split('/')[-1]

        print(f"[*] Starting analysis {i+1} out of {len(inputs)}: {lib_name}")

        if not os.path.exists(os.path.join(OUT_DIR, lib_name)):
            os.mkdir(os.path.join(OUT_DIR, lib_name))
        
        parsed_results = parse_results(funcptr_out_fname)
        for j, result in enumerate(parsed_results):
            print(f"\t[{j+1}/{len(parsed_results)}] Starting symbolic execution of function {result['function_name']}, target is {result['target_func']}")
            symex_out_file = os.path.join(OUT_DIR, lib_name, result['function_name'] + '_' + result['target_func'] + '.txt')
            symex_args = [lib_name]
            symex_args.append(result['function_name'])
            symex_args.append(result['target_func'])

            exec_func = True
            for k, param_size in enumerate(result['params_sizes']):
                if param_size is None:
                    print(f"\t\t[!] Could not resolve type of one of the parameters, skipping execution.")
                    for line in result['error'].split('\n'):    
                        print(f"\t\t[!] {line}")
                    exec_func = False
                    break
                if param_size != 0:
                    symex_args.append("-p")
                    symex_args.append(f"param_{k}")
                    symex_args.append("type")
                    symex_args.append(f"{param_size*8}")

            if exec_func:
                with open(symex_out_file, "w") as f:
                    start = time.time()
                    subprocess.run(['python', 'symex.py', *symex_args], stdout=f)
                    total_time = time.time() - start
                    f.write(f"\n\n[*] {result['function_sig']}")
                    f.write(f"\n[*] Total time: {total_time}")

if __name__ == '__main__':
    main()