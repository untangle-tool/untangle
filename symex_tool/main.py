import os
import sys
import time
import argparse
import subprocess
import logging
from pathlib import Path

from .codeql import build_codeql_db
from .finder import find_function_pointers
from .replacer import replace_calls
from .utils import ensure_command

logger = logging.getLogger('main')

# TODO: move this (along with the parsing) somewhere elsewhere
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
    parser = argparse.ArgumentParser()

    sub = parser.add_subparsers(dest='subcommand')
    build = sub.add_parser('build', description='Build the given library and a CodeQL database for subsequent analysis')
    build.add_argument('library_path' , metavar='LIBRARY_PATH'  , help='Path to library source directory')
    build.add_argument('db_path'      , metavar='OUT_DB_NAME'   , help='Name of the CodeQL database to create')
    build.add_argument('build_command', metavar='BUILD_COMMAND' , help='Command to use to build the libray')
    build.add_argument('clean_command', metavar='CLEAN_COMMAND' , nargs='?', default=None, help='Command to use to clean library sources before re-building')

    analyze = sub.add_parser('analyze', description='Run a complete analysis of a previously built library')
    analyze.add_argument('db_path' , metavar='CODEQL_DB_PATH', help='Path to library source directory')
    analyze.add_argument('binary'  , metavar='BINARY'        , help='Binary of the built library (e.g. shared object)')
    analyze.add_argument('out_path', metavar='OUTPUT_PATH'   , help='Output directory (created if needed)')

    return parser.parse_args()


def setup_logging(level):
    orig_factory = logging.getLogRecordFactory()

    if os.isatty(sys.stderr.fileno()):
        fmt = '%(color)s[%(name)s:%(levelname)s] %(message)s%(color_reset)s'
        level_colors = {
            logging.CRITICAL: '\x1b[1;31m',
            logging.ERROR   : '\x1b[31m',
            logging.WARNING : '\x1b[33m',
            logging.INFO    : '\x1b[32m',
            logging.DEBUG   : '\x1b[34m',
        }

        def record_factory(*args, **kwargs):
            record = orig_factory(*args, **kwargs)
            lvl = record.levelno
            record.color = level_colors.get(lvl, '')
            record.color_reset = '\x1b[0m'
            record.levelname = 'FATAL' if lvl == logging.CRITICAL else record.levelname
            return record
    else:
        fmt = '[%(name)s:%(levelname)s] %(message)s'

        def record_factory(*args, **kwargs):
            record = orig_factory(*args, **kwargs)
            record.levelname = 'FATAL' if record.levelno == logging.CRITICAL else record.levelname
            return record

    logging.basicConfig(level=level, format=fmt)
    logging.setLogRecordFactory(record_factory)


def parse_results(function_pointers):
    # TODO: move this parsing elsewhere

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

    # Convert the output into the format requested by symex.py
    temporary_results = []

    for func_ptr, calls in function_pointers.items():
        for i, (_, exported_funcs) in enumerate(calls.items()):
            for exported_func, signature in exported_funcs:
                result = {
                    'function_ptr_name': func_ptr,
                    'function_name': exported_func,
                    'params_sizes': [],
                    'pointer': [],
                    'error': '',
                    'function_sig': signature,
                    'target_func': f"TARGET_{func_ptr}_{i}"
                }

                for param in signature.split(', '):
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


def build(library_path, out_db_path, build_command, clean_command=None):
    '''Build library at the given source directory path using build_command and
    create a CodeQL database for it.
    '''
    if clean_command is not None:
        logger.info('Cleaning original library')
        ensure_command(clean_command, cwd=library_path)

    logger.info('Building original library and CodeQL database')
    build_codeql_db(library_path, out_db_path, build_command)
    logger.info('Database built at "%s"', out_db_path)

    logger.info('Extracting function pointers from CodeQL database')
    fptrs = find_function_pointers(out_db_path)

    logger.info('Replacing calls to function pointers in library source')
    modified_library_path = replace_calls(library_path, fptrs)

    if clean_command is not None:
        logger.info('Cleaning library')
        ensure_command(clean_command, cwd=modified_library_path)

    logger.info('Re-building modified library')
    ensure_command(build_command, cwd=modified_library_path)
    logger.info('Done! Built library at "%s"', modified_library_path)


def analyze(db_path, binary_path, out_path):
    logger.info('Extracting function pointers from CodeQL database')
    fptrs = find_function_pointers(db_path)

    logger.info('Analyzing library "%s"', binary_path)
    out_path.mkdir(exist_ok=True)
    parsed_results = parse_results(fptrs)

    # TODO: turn symex.py into a module from which we can import a function to
    #       simply tun with python objs and not awkward command line args

    for j, result in enumerate(parsed_results):
        logger.debug(f"[{j+1}/{len(parsed_results)}] Starting symbolic execution of function {result['function_name']}, target is {result['target_func']}")
        symex_out_file = out_path / (result['function_name'] + '_' + result['target_func'] + '.txt')
        symex_args = [binary_path]
        symex_args.append(result['function_name'])
        symex_args.append(result['target_func'])

        exec_func = True
        for k, param_size in enumerate(result['params_sizes']):
            if param_size is None:
                logger.warning(f"Could not resolve type of one of the parameters, skipping execution.")
                for line in result['error'].split('\n'):
                    logger.warning(f"{line}")
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

                subprocess.run(['python3', '-m', 'symex_tool.symex', *symex_args], stdout=f)
                total_time = time.time() - start
                f.write(f"\n\n[*] {result['function_sig']}")
                f.write(f"\n[*] Total time: {total_time}")


def main():
    args = parse_arguments()
    setup_logging(logging.INFO)

    db = Path(args.db_path).absolute()

    if args.subcommand == 'build':
        lib = Path(args.library_path).absolute()
        build(lib, db, args.build_command, args.clean_command)
    else:
        lbin = Path(args.binary)
        out = Path(args.out_path)
        analyze(db, lbin, out)


if __name__ == '__main__':
    main()
