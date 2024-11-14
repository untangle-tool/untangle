import os
import logging
import re
from collections import defaultdict
from .utils import search_all

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
        f"#ifndef SYMEX_WRAPPER_{func_ptr}_{call_loc_id}\n",
        f"#define SYMEX_WRAPPER_{func_ptr}_{call_loc_id}(...) (SYMEX_TARGET_{func_ptr}_{call_loc_id}(), ({{{actual_call}(__VA_ARGS__);}}))\n",
        f"unsigned SYMEX_NOOPT_{func_ptr}_{call_loc_id} = 0;\n",
        f"void SYMEX_TARGET_{func_ptr}_{call_loc_id}(void);\n",
        f"void __attribute__((noinline)) SYMEX_TARGET_{func_ptr}_{call_loc_id}(void){{\n",
        f"\tSYMEX_NOOPT_{func_ptr}_{call_loc_id}++;\n",
        "}\n",
        "#endif\n"
    ]

def get_right_hand_side(line: str) -> str:

    if line.count("=") == 1 and not "!=" in line:
        two_sides = line.split("=")
        if len(two_sides) > 1:
            right_hand_side = two_sides[1]
        else:
            right_hand_side = two_sides[0]
    else:
        right_hand_side = line
    return right_hand_side

def is_member_call(line: str, funcptr: str) -> bool:
    right_hand_side = get_right_hand_side(line)
    # Understand if func_ptr is preceded by "->" or "."
    funcptr_start = right_hand_side.find(funcptr)
    substr = right_hand_side[:funcptr_start]
    if "." in substr:
        call_symbol_start = substr.rfind(".")
        call_symbol_end = call_symbol_start + len(".")
    elif "->" in substr:
        call_symbol_start = substr.rfind("->")
        call_symbol_end = call_symbol_start + len("->")
    else:
        return False
    
    substring_between = right_hand_side[call_symbol_end:funcptr_start]
    return substring_between.isspace() or substring_between == ""

def get_call_chain(line: str, funcptr: str):
    regex = r'((\([a-zA-Z_&\d\[\]]*\)|[a-zA-Z_&\d\[\]]*)\s*(->|\.)\s*[\(]*[a-zA-Z_&\d]*[\)]*)+'
    # return re.search(regex, line[:line.find(funcptr)+len(funcptr)]).group(0)
    matches = search_all(regex, line[:line.find(funcptr)+len(funcptr)])
    match = ""
    for m in matches:
        if funcptr in m:
            match = m
            break
    return match

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

        # Look if it is a member call of a struct
        if is_member_call(file_lines[line_no], funcptr=func_ptr):
            logger.info(f"Found struct call (funcptr {func_ptr}): {file_lines[line_no].strip()}")
            # Replace entire call chain
            last_command = file_lines[line_no].rfind(";", 0, file_lines[line_no].find(func_ptr))
            
            if last_command == -1:
                actual_call = get_call_chain(file_lines[line_no], func_ptr).strip()
            else:
                actual_call = get_call_chain(file_lines[line_no][last_command:], func_ptr).strip()
            logger.info(f"Complete call: {actual_call}")
            start_column = file_lines[line_no].find(actual_call)
            logger.info(f"Call is at {call_loc}, column {start_column}")
        else:
            if first_parenthesis == -1:
                actual_call = file_lines[line_no][start_column-1:end_column].strip()
            else:
                actual_call = file_lines[line_no][start_column-1:first_parenthesis]
            start_column -= 1

        definition = generate_fn_definition(func_ptr, call_loc_id, actual_call)

        # Insert the function definition
        for j, line in enumerate(definition):
            file_lines.insert(j, line)
        number_lines_added[file_path] += len(definition)
        line_no += len(definition)

        # Replace only the characters between "start_column" and the first parenthesis found.
        if first_parenthesis != -1:
            file_lines[line_no] = file_lines[line_no][:start_column] + f"SYMEX_WRAPPER_{func_ptr}_{call_loc_id}" + file_lines[line_no][first_parenthesis:]
        else:
            # If no parenthesis is found, the arguments could just be on the next row, no need to worry
            file_lines[line_no] = file_lines[line_no][:start_column] + f"SYMEX_WRAPPER_{func_ptr}_{call_loc_id}\n"

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
