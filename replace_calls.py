import argparse
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
    function_pointers = {}
    for line in lines:
        if 'declared' in line:
            func_ptr_name = line.split(' ')[0].strip()
            curr_func_ptr = func_ptr_name
            function_pointers[curr_func_ptr] = []
        elif 'called from' in line:
            function_pointers[curr_func_ptr].append(line.strip())
    
    targetfunc_def = "void* TARGETFUNC(){}\n"
    targetfunc_extern = "extern void* TARGETFUNC();\n"
    defined = False

    lines_added = dict()
    for func_ptr in function_pointers:
        for caller in function_pointers[func_ptr]:
            location = caller.split(' ')[-1].strip()
            file_name  = location.split(':')[0]
            start_line, start_column, end_line, end_column = list(map(int, location.split(':')[1:]))
            file_path = os.path.join(modified_lib_src_path, file_name)
            
            with open(file_path, "r") as f:
                file_lines = f.readlines()

            # Insert the definition of TARGETFUNC if it is not already defined.
            # Else, insert an extern declaration of the function.
            if not defined:
                file_lines.insert(0, targetfunc_def)
                lines_added[file_path] = 1
                defined = True
            elif defined and not targetfunc_extern in file_lines and not targetfunc_def in file_lines:
                file_lines.insert(0, targetfunc_extern)
                lines_added[file_path] = 1

            line_no = start_line + lines_added[file_path] - 1
            
            # Replace only the characters between "start_column" and the first parenthesis found.
            first_parenthesis = file_lines[line_no].find("(", start_column)
            if first_parenthesis != -1:
                file_lines[line_no] = file_lines[line_no][:start_column-1] + "TARGETFUNC" + file_lines[line_no][first_parenthesis:]
            else:
                # If no parenthesis is found, add also an empty couple of parentheses, a semi-colon and a newline.
                file_lines[line_no] = file_lines[line_no][:start_column-1] + "TARGETFUNC();\n"

            with open(file_path, "w") as f:
                f.writelines(file_lines)
            
            print(f"\t[*] Function pointer {func_ptr} replaced with TARGETFUNC in {file_path}")


if __name__ == '__main__':
    main()