import os
import sys
import argparse
import logging
import shutil
from pathlib import Path

from .codeql import build_codeql_db
from .extract import extract_function_pointers, extract_structs
from .replacer import replace_calls
from .symex import symex
from .utils import ensure_command, save_object

logger = logging.getLogger('main')


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true', help='enable verbose logging')

    sub = parser.add_subparsers(dest='subcommand')
    build = sub.add_parser('build', description='Build the given library and a CodeQL database for subsequent analysis')
    build.add_argument('library_path' , metavar='LIBRARY_PATH' , help='path to library source directory')
    build.add_argument('db_path'      , metavar='OUT_DB_NAME'  , help='name of the CodeQL database to create')
    build.add_argument('build_command', metavar='BUILD_COMMAND', help='command to use to build the libray')

    analyze = sub.add_parser('analyze' , description='Run a complete analysis of a previously built library')
    analyze.add_argument('library_path', metavar='BUILT_LIBRARY_PATH', help='path to library build directory (created by the "build" subcommand)')
    analyze.add_argument('db_path'     , metavar='CODEQL_DB_PATH'    , help='path to CodeQL database for the library')
    analyze.add_argument('binary'      , metavar='BINARY'            , help='binary of the built library (e.g. shared object)')
    analyze.add_argument('out_path'    , metavar='OUTPUT_PATH'       , help='output directory (created if needed)')

    return parser.parse_args()


def setup_logging(level):
    orig_factory = logging.getLogRecordFactory()

    if os.isatty(sys.stderr.fileno()):
        fmt = '%(asctime)s %(color)s[%(levelname)s:%(name)s] %(message)s%(color_reset)s'
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
        fmt = '%(asctime)s [%(levelname)s:%(name)s] %(message)s'

        def record_factory(*args, **kwargs):
            record = orig_factory(*args, **kwargs)
            record.levelname = 'FATAL' if record.levelno == logging.CRITICAL else record.levelname
            return record

    # Angr will set the logger how it wants on import... annoying
    log = logging.getLogger()
    for h in log.handlers[:]:
        log.removeHandler(h)

    # Set these to warning to reduce noise
    logging.getLogger('angr').setLevel(logging.WARNING)
    logging.getLogger('claripy').setLevel(logging.WARNING)
    logging.getLogger('cle').setLevel(logging.WARNING)
    logging.getLogger('pyvex').setLevel(logging.WARNING)
    logging.getLogger('asyncio').setLevel(logging.WARNING)

    # This gets too noisy complaining that "Exit state has over 256 possible
    # solutions. Likely unconstrained; skipping."
    logging.getLogger('angr.engines.successors').setLevel(logging.ERROR)

    # The program is accessing register with an unspecified value. BLABLABLA...
    logging.getLogger('angr.storage.memory_mixins.default_filler_mixin').setLevel(logging.ERROR)

    logging.basicConfig(level=level, format=fmt)
    logging.setLogRecordFactory(record_factory)


def build(library_path, out_db_path, build_command):
    '''Build library at the given source directory path using build_command and
    create a CodeQL database for it.
    '''
    # Create a copy of the source code. If it already exists, delete it and
    # create a new one.
    new_library_path = Path(str(library_path) + '_build')
    if not os.path.exists(new_library_path):
        shutil.copytree(library_path, new_library_path)
    else:
        shutil.rmtree(new_library_path)
        shutil.copytree(library_path, new_library_path)

    logger.info('Library copy created at %s', new_library_path)

    logger.info('Building original library and CodeQL database')
    build_codeql_db(library_path, out_db_path, build_command)
    logger.info('Database built at "%s"', out_db_path)

    logger.info('Extracting function pointers from CodeQL database')
    fptrs = extract_function_pointers(out_db_path)

    logger.info('Replacing calls to function pointers in copied library source')
    replace_calls(new_library_path, fptrs)

    logger.info('Re-building library copy')
    ensure_command(build_command, cwd=new_library_path)

    save_object(fptrs, new_library_path / '.symex_fptrs')

    logger.info('Extracting struct definitions from CodeQL database')
    extract_structs(out_db_path, new_library_path / '.symex_structs')

    print('Built library ready at', new_library_path)


def analyze(db_path, built_library_path, binary_path, out_path):
    fptrs   = extract_function_pointers(db_path, built_library_path / '.symex_fptrs')
    structs = extract_structs(db_path, built_library_path / '.symex_structs')

    logger.info('Analyzing library "%s"', binary_path)
    out_path.mkdir(exist_ok=True)

    exported_funcs = {}
    call_location_info = {}

    for func_ptr_name, call_loc, call_id, exported_func, signature in fptrs:
        exported_funcs[exported_func] = signature
        call_location_info[call_id] = (func_ptr_name, call_loc)

    n = len(exported_funcs)

    for i, (exported_func, signature) in enumerate(exported_funcs.items(), 1):
        if i < 254:
            continue

        logger.info('[%d/%d] Starting symbolic execution of %s', i, n, exported_func)
        symex_out_file = out_path / (f'{i:03d}_{exported_func}.txt')
        symex(exported_func, signature, call_location_info, structs, binary_path, symex_out_file)


def main():
    args = parse_arguments()
    setup_logging(logging.DEBUG if args.verbose else logging.INFO)

    db = Path(args.db_path).absolute()

    if args.subcommand == 'build':
        lib = Path(args.library_path).absolute()
        build(lib, db, args.build_command)
    else:
        lib  = Path(args.library_path)
        lbin = Path(args.binary)
        out = Path(args.out_path)
        analyze(db, lib, lbin, out)


if __name__ == '__main__':
    main()
