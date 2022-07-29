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

            # This handles multiline definitions.
            if start_line != end_line:
                for i in range(start_line+lines_added[file_path], end_line+lines_added[file_path]):
                    file_lines[i] = "\n"
                end_of_line = True
            
            line_no = start_line + lines_added[file_path] - 1
            if start_line == end_line:
                end_of_line = file_lines[line_no][end_column] == ";"
            else:
                end_column = len(file_lines[line_no]) - 1
            
            if end_of_line:
                file_lines[line_no] = file_lines[line_no][:start_column-1] + "TARGETFUNC();" + file_lines[line_no][end_column:]
                file_lines[line_no] = file_lines[line_no].replace(";;", ";")

                # TO-DO: Find a way to replace multiple function pointer indirections with a single function call.
            else:
                file_lines[line_no] = file_lines[line_no][:start_column-1] + "TARGETFUNC()" + file_lines[line_no][end_column:].strip() + "\n"
            

            with open(file_path, "w") as f:
                f.writelines(file_lines)
            
            print(f"\t[*] Function pointer {func_ptr} replaced with TARGETFUNC in {file_path}")


if __name__ == '__main__':
    main()