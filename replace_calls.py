import argparse
from collections import defaultdict
import os
import shutil

def parse_arguments():
    """ Parse the program's arguments."""

    description = """
        Replace the calls to function pointers in a library with calls to TARGETFUNC.
    """

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('lib_src_folder', help="Name of the folder containing the source code of the library.")
    parser.add_argument('funcptr_out_file', help="Name of the file containing the function pointer information.")

    return vars(parser.parse_args())

def organize_funcptr_info(lines: str):
    """ Organize the function pointer information in a hierarchical dictionary. """
    function_pointers = {}
    for line in lines:
        if 'declared' in line:
            func_ptr_name = line.split(' ')[0].strip()
            curr_func_ptr = func_ptr_name
            function_pointers[curr_func_ptr] = []
        elif 'called from' in line:
            function_pointers[curr_func_ptr].append(line.strip())

    return function_pointers
    
def monoline_function_call(line: str):
    """ Check if the function call is on one line. """
    return line.count('(') == line.count(')')

def generate_fn_definition(func_ptr: str, call_num: int, actual_call: str):
    definition = []
    definition.append(f"#define WRAPPER_{func_ptr}_{call_num}(...) (TARGET_{func_ptr}_{call_num}(), ({{{actual_call}(__VA_ARGS__);}}))\n")
    definition.append(f"static int NOOPT_TARGET_{func_ptr}_{call_num} = 0;\n")
    definition.append(f"void* TARGET_{func_ptr}_{call_num}(void){{\n")
    definition.append(f"\tNOOPT_TARGET_{func_ptr}_{call_num} = 1;\n")
    definition.append("}\n")

    return definition

def main():
    
    args = parse_arguments()
    lib_src_path = args['lib_src_folder']
    funcptr_out_file = args['funcptr_out_file']

    modified_lib_src_path = lib_src_path + '_modified'

    # Create a copy of the source code. If it already exists, delete it and create a new one.
    if not os.path.exists(modified_lib_src_path):
        shutil.copytree(lib_src_path, modified_lib_src_path)
    else:
        shutil.rmtree(modified_lib_src_path)
        shutil.copytree(lib_src_path, modified_lib_src_path)
    print(f"[*] Library copy created in {modified_lib_src_path}")

    # Read the output of find_func_ptrs.py
    with open(funcptr_out_file, "r") as f:
        lines = f.readlines()

    # Create a hierarchical dictionary of the function pointer information.
    function_pointers = organize_funcptr_info(lines)

    number_lines_added = defaultdict(lambda: 0)
    for func_ptr in function_pointers:

        for i, caller in enumerate(function_pointers[func_ptr]):

            location = caller.split(' ')[-1].strip()
            file_name  = location.split(':')[0]
            start_line, start_column, end_line, end_column = list(map(int, location.split(':')[1:]))
            file_path = os.path.join(modified_lib_src_path, file_name)
            
            with open(file_path, "r") as f:
                file_lines = f.readlines()
            
            # Create the define based on the actuall function call
            line_no = start_line + number_lines_added[file_path] - 1
            first_parenthesis = file_lines[line_no].find("(", start_column)
            if first_parenthesis == -1:
                actual_call = file_lines[line_no][start_column-1:end_column]
            else:
                actual_call = file_lines[line_no][start_column-1:first_parenthesis]

            definition = generate_fn_definition(func_ptr=func_ptr, call_num=i, actual_call=actual_call)
            
            # Insert the function definition
            for j, line in enumerate(definition):
                file_lines.insert(j, line)
            number_lines_added[file_path] += len(definition)
            line_no += len(definition)
            
            # Replace only the characters between "start_column" and the first parenthesis found.
            if first_parenthesis != -1:
                file_lines[line_no] = file_lines[line_no][:start_column-1] + f"WRAPPER_{func_ptr}_{i}" + file_lines[line_no][first_parenthesis:]
            else:
                # If no parenthesis is found, add also an empty couple of parentheses, a semi-colon and a newline.
                file_lines[line_no] = file_lines[line_no][:start_column-1] + f"WRAPPER_{func_ptr}_{i}();\n"
            
            # If the call is on one line and there is no semi-colon, add one.
            if monoline_function_call(file_lines[line_no]) and not ';\n' in file_lines[line_no]:
                file_lines[line_no] = file_lines[line_no].strip() + ';\n'

            with open(file_path, "w") as f:
                f.writelines(file_lines)
            
            print(f"\t[*] Function pointer {func_ptr} replaced with a wrapper to TARGET_{func_ptr}_{i} in {file_path}")


if __name__ == '__main__':
    main()