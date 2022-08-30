import os
import sys
import argparse
import logging
from pathlib import Path

from .codeql import build_codeql_db
from .finder import find_function_pointers
from .replacer import replace_calls
from .symex import symex
from .utils import ensure_command

logger = logging.getLogger('main')

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

    total_idx = 1
    for fptr in fptrs:
        fptr_idx = 0
        for call_loc in fptrs[fptr]:
            for f in fptrs[fptr][call_loc]:
                exported_func = f[0]
                signature = f[1]
                target_func = f"TARGET_{fptr}_{fptr_idx}"

                symex_out_file = out_path / (exported_func + '_' + target_func + '.txt')

                logger.debug(f"[{total_idx}] Starting symbolic execution of function {exported_func}, target is {target_func}")
                symex(fn_name=exported_func, target_fn_name=target_func, signature=signature, binary=binary_path, out_file=symex_out_file)


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
