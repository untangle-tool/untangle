import os
import logging
from collections import defaultdict

logger = logging.getLogger('instrumenter')


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


def generate_fn_definition(func_ptr: str, call_loc_id: int, actual_call: str):
    return [
        f"#define SYMEX_WRAPPER_{func_ptr}_{call_loc_id}(...) (SYMEX_TARGET_{func_ptr}_{call_loc_id}(), ({{{actual_call}(__VA_ARGS__);}}))\n",
        f"unsigned SYMEX_NOOPT_{func_ptr}_{call_loc_id} = 0;\n",
        f"void SYMEX_TARGET_{func_ptr}_{call_loc_id}(void);\n",
        f"void __attribute__((noinline)) SYMEX_TARGET_{func_ptr}_{call_loc_id}(void){{\n",
        f"\tSYMEX_NOOPT_{func_ptr}_{call_loc_id}++;\n",
        "}\n",
    ]


def instrument_library_source(lib_src_path, function_pointers):
    number_lines_added = defaultdict(int)
    seen = set()
    headers = set()

    for func_ptr, call_loc, call_loc_id, _, _ in function_pointers:
        if call_loc_id in seen:
            continue

        seen.add(call_loc_id)

        file_name = call_loc[0]
        file_path = os.path.join(lib_src_path, file_name)
        start_line, start_column, end_line, end_column = call_loc[1:]

        try:
            with open(file_path, "r") as f:
                file_lines = f.readlines()
        except FileNotFoundError:
            continue

        # Create the define based on the actual function call
        line_no = start_line + number_lines_added[file_path] - 1
        first_parenthesis = file_lines[line_no].find("(", start_column)

        if first_parenthesis == -1:
            actual_call = file_lines[line_no][start_column-1:end_column].strip()
        else:
            actual_call = file_lines[line_no][start_column-1:first_parenthesis]

        definition = generate_fn_definition(func_ptr, call_loc_id, actual_call)

        # Insert the function definition
        for j, line in enumerate(definition):
            file_lines.insert(j, line)
        number_lines_added[file_path] += len(definition)
        line_no += len(definition)

        # Replace only the characters between "start_column" and the first parenthesis found.
        if first_parenthesis != -1:
            file_lines[line_no] = file_lines[line_no][:start_column-1] + f"SYMEX_WRAPPER_{func_ptr}_{call_loc_id}" + file_lines[line_no][first_parenthesis:]
        else:
            # If no parenthesis is found, the arguments could just be on the next row, no need to worry
            file_lines[line_no] = file_lines[line_no][:start_column-1] + f"SYMEX_WRAPPER_{func_ptr}_{call_loc_id}\n"

        # If the call is on one line and there is no semi-colon, add one.
        # if monoline_function_call(file_lines[line_no]) and not ';' in file_lines[line_no]:
            # file_lines[line_no] = file_lines[line_no].strip() + ';\n'

        with open(file_path, "w") as f:
            f.writelines(file_lines)

        if file_path.endswith('.h'):
            headers.add(file_path)

        # A little bit too verbose
        # logger.debug(f"Function pointer {func_ptr} replaced with a wrapper to TARGET_{func_ptr}_{call_loc_id} in {file_path}")

    # Move include guards to include the inserted stuff
    for h in headers:
        with open(h, 'r+') as f:
            lines = f.readlines()
            assert f.seek(0) == 0

            for i in range(len(lines) - 1, - 1, -1):
                if lines[i].strip().startswith('#endif'):
                    for j in range(i):
                        # Move include guard up to the top of the file
                        if lines[j].startswith('#ifndef'):
                            l = lines.pop(j)
                            lines.insert(0, l)
                    break
            else:
                # No include guard?
                f.write('#pragma once\n')

            f.writelines(lines)
