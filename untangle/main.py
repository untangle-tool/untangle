import os
import re
import sys
import argparse
import logging
import shutil
from pathlib import Path
from collections import defaultdict
from multiprocessing import Process

from .codeql import build_codeql_db
from .analyzer import extract_function_pointers, extract_structs
from .instrumenter import instrument_library_source
from .symex import symex_wrapper
from .utils import ensure_command, save_object, exported_functions


logger = logging.getLogger('main')


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true', help='enable verbose logging')

    sub = parser.add_subparsers(dest='subcommand')
    build = sub.add_parser('build', description='Build a CodeQL database and built an instrument version of the given library for subsequent symbolic execution')
    build.add_argument('--autobuild', action="store_true", help='Let CodeQL automatically build the database')
    build.add_argument('library_path' , metavar='LIBRARY_PATH'  , help='path to library source directory')
    build.add_argument('build_path'   , metavar='OUT_BUILD_PATH', help='path to directory where the library will be copied and built')
    build.add_argument('db_path'      , metavar='OUT_DB_NAME'   , help='name of the CodeQL database to create')
    build.add_argument('build_command', metavar='BUILD_COMMAND' , help='command to use to build the libray')
    

    list_ = sub.add_parser('list', description='List information about all discovered function pointer call sites')
    list_.add_argument('library_path', metavar='BUILT_LIBRARY_PATH', help='path to library build directory (created by the "build" subcommand)')
    list_.add_argument('db_path'     , metavar='CODEQL_DB_PATH'    , help='path to CodeQL database for the library')

    exec_ = sub.add_parser('exec', description='Run a complete symbolic execution anlysis of a previously built library')
    exec_.add_argument('--verify'    , action='store_true'         , help='try verifying correctness of the results by compiling and running a test')
    exec_.add_argument('--dfs'       , action='store_true'         , help='use DFS (depth first search) exploration policy for angr (lower memory usage)')
    exec_.add_argument('--resume'    , metavar='N', type=int, default=1, help='resume from the Nth function instead of re-starting from scratch')
    exec_.add_argument('--timeout'   , metavar='SECONDS', type=int, default=15 * 60, help='timeout for each symbolix execution run (default: 15 min)')
    exec_.add_argument('--memory'    , metavar='MEGABYTES', type=int, default=16384, help='maximum amount of memory (RSS) to use during each symbolic execution run (default: 16GiB)')
    exec_.add_argument('library_path', metavar='BUILT_LIBRARY_PATH', help='path to library build directory (created by the "build" subcommand)')
    exec_.add_argument('db_path'     , metavar='CODEQL_DB_PATH'    , help='path to CodeQL database for the library')
    exec_.add_argument('out_path'    , metavar='OUTPUT_PATH'       , help='output directory (created if needed)')
    exec_.add_argument('binary'      , metavar='BINARY', nargs='+' , help='binary of the built library (e.g. shared object), more than one can be specified')

    exec_filter = sub.add_parser('exec-filter', description='Run symbolic execution only for the matching function pointer calls')
    exec_filter.add_argument('--dfs'       , action='store_true'         , help='use DFS (depth first search) exploration policy for angr (lower memory usage)')
    exec_filter.add_argument('--verify'    , action='store_true'         , help='try verifying correctness of the results by compiling and running a test')
    exec_filter.add_argument('--timeout'   , metavar='SECONDS', type=int, default=15 * 60, help='timeout for each symbolix execution run (default: 15 min)')
    exec_filter.add_argument('--memory'    , metavar='MEGABYTES', type=int, default=16384, help='maximum amount of memory (RSS) to use during each symbolic execution run (default: 16GiB)')
    exec_filter.add_argument('--function'  , metavar='FUNCTION_FILTER'   , help='only test starting library functions with name matching this Python regexp (even partially)')
    exec_filter.add_argument('--fptr'      , metavar='FPTR_FILTER'       , help='only test reachability of function pointers with name matching this Python regexp (even partially)')
    exec_filter.add_argument('--loc'       , metavar='LOC_FILTER'        , help='only test reachability of this exact function pointer call location')
    exec_filter.add_argument('library_path', metavar='BUILT_LIBRARY_PATH', help='path to library build directory (created by the "build" subcommand)')
    exec_filter.add_argument('db_path'     , metavar='CODEQL_DB_PATH'    , help='path to CodeQL database for the library')
    exec_filter.add_argument('out_path'    , metavar='OUTPUT_PATH'       , help='output directory (created if needed)')
    exec_filter.add_argument('binary'      , metavar='BINARY', nargs='+' , help='binary of the built library (e.g. shared object), more than one can be specified')

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

    if level > logging.DEBUG:
        # "Exit state has over 256 possible solutions. Likely unconstrained; skipping."
        logging.getLogger('angr.engines.successors').setLevel(logging.ERROR)
        # "The program is accessing register with an unspecified value. BLABLABLA..."
        logging.getLogger('angr.storage.memory_mixins.default_filler_mixin').setLevel(logging.ERROR)
        # "Allocation request of X bytes exceeded maximum of Y bytes; allocating Y bytes"
        logging.getLogger('angr.state_plugins.heap.heap_base').setLevel(logging.ERROR)
        # "memcpy upper bound of X outside limit, limiting to 0x1000 instead"
        logging.getLogger('angr.procedures.libc.memcpy').setLevel(logging.ERROR)
        # "Tried to look up a symbolic fd ..."
        logging.getLogger('angr.state_plugins.posix').setLevel(logging.ERROR)
        # Badly supported instructions
        logging.getLogger('pyvex.lifting.gym.x86_spotter').setLevel(logging.ERROR)
        # "The provided object has an invalid tls_data_size. Skip TLS loading."
        logging.getLogger('cle.backends.tls').setLevel(logging.ERROR)

    logging.basicConfig(level=level, format=fmt, datefmt='%Y-%m-%d %H:%M:%S')
    logging.setLogRecordFactory(record_factory)


def build(library_path, build_path, out_db_path, build_command, autobuild):
    '''Build library at the given source directory path using build_command and
    create a CodeQL database for it.
    '''
    # Create a copy of the source code. If it already exists, delete it and
    # create a new one.
    if os.path.exists(build_path):
        shutil.rmtree(build_path)
    shutil.copytree(library_path, build_path, symlinks=True)

    logger.info('Library copy created at %s', build_path)

    logger.info('Building CodeQL database for the original library')
    build_codeql_db(library_path, out_db_path, build_command, autobuild)

    logger.info('Extracting function pointers from CodeQL database')
    fptrs = extract_function_pointers(out_db_path)

    if len(fptrs) > 0:
        logger.info('Found %d possible paths to reach function pointer calls', len(fptrs))
    else:
        logger.fatal('No interesting function pointers in this library!')
        sys.exit(1)

    logger.info('Instrumenting library copy')
    instrument_library_source(build_path, fptrs)

    logger.info('Building instrumented library')
    ensure_command(build_command, cwd=build_path)

    save_object(fptrs, build_path / '.symex_fptrs')

    logger.info('Extracting struct definitions from CodeQL database')
    extract_structs(out_db_path, build_path / '.symex_structs')

    print('Built library ready at', build_path)
    print('CodeQL database ready at', out_db_path)


def is_exported(library_func, binaries):
    for b in binaries:
        if library_func in exported_functions(b):
            return True
    return False


def exec_all(db_path, built_library_path, binaries, out_path, resume_idx,
        verify, dfs, max_mem, max_time):
    fptrs   = extract_function_pointers(db_path, built_library_path / '.symex_fptrs')
    structs = extract_structs(db_path, built_library_path / '.symex_structs')

    out_path.mkdir(exist_ok=True)
    library_funcs = {}
    call_loc_info  = {}

    for func_ptr_name, call_loc, call_id, library_func, signature in fptrs:
        library_funcs[library_func] = signature
        if call_id not in call_loc_info:
            call_loc_info[call_id] = (func_ptr_name, call_loc, set())
        call_loc_info[call_id][-1].add(library_func)

    n = len(library_funcs)

    for i, (library_func, signature) in enumerate(library_funcs.items(), 1):
        if i < resume_idx:
            continue

        if not is_exported(library_func, binaries):
            logger.info('[%d/%d] Skipping unexported function %s', i, n, library_func)
            continue

        logger.info('[%d/%d] Function %s', i, n, library_func)
        symex_out_file = out_path / (f'{i:04d}_{library_func}.txt')
        symex_wrapper(library_func, signature, call_loc_info, structs,
            binaries, verify, dfs, symex_out_file, max_mem, max_time)


def exec_filter(db_path, built_library_path, binary_path, out_path, verify, dfs,
        filter_func, filter_fptr, filter_loc, max_mem, max_time):
    if filter_func is not None:
        try:
            filter_func = re.compile(filter_func)
        except Exception as e:
            logger.critical('Failed to compile filter regexp: %r', filter_func)
            logger.critical('%r', e)
            sys.exit(1)

    if filter_fptr is not None:
        try:
            filter_fptr = re.compile(filter_fptr)
        except Exception as e:
            logger.critical('Failed to compile filter regexp: %r', filter_fptr)
            logger.critical('%r', e)
            sys.exit(1)

    fptrs   = extract_function_pointers(db_path, built_library_path / '.symex_fptrs')
    structs = extract_structs(db_path, built_library_path / '.symex_structs')

    out_path.mkdir(exist_ok=True)
    library_funcs = {}
    call_loc_info  = {}

    for func_ptr_name, call_loc, call_id, library_func, signature in fptrs:
        library_funcs[library_func] = signature
        if call_id not in call_loc_info:
            call_loc_info[call_id] = (func_ptr_name, call_loc, set())
        call_loc_info[call_id][-1].add(library_func)


    for library_func, signature in library_funcs.items():
        if not is_exported(library_func, binaries):
            logger.info('Skipping unexported function %s', i, n, library_func)
            continue

        if filter_func is not None and filter_func.search(library_func) is None:
            logger.debug('Skipping function %s based on provided filter', library_func)
            continue

        symex_out_file = out_path / (library_func + '.txt')
        symex_wrapper(library_func, signature, call_loc_info, structs,
            binaries, verify, dfs, symex_out_file, max_mem, max_time,
            filter_fptr, filter_loc)


def list_all(db_path, built_library_path):
    fptrs = extract_function_pointers(db_path, built_library_path / '.symex_fptrs')
    by_fptr = defaultdict(set)

    for fptr, call_loc, call_id, library_func, signature in fptrs:
        by_fptr[fptr].add((library_func, call_loc))

    print('{:40s} {:40s} {}'.format('Function pointer', 'Library function', 'Call location'))

    for fptr, subset in sorted(by_fptr.items()):
        for library_func, call_loc in sorted(subset):
            call_loc = ':'.join(map(str, call_loc))
            print('{:40s} {:40s} {}'.format(fptr, library_func, call_loc))

    print("Summary:")
    print(f"Found {len(fptrs)} function pointer call sites")
    print(f"Found {len(by_fptr)} unique function pointers")
    print(f"Found {len(set(f[3] for f in fptrs))} unique library functions")
    print(f"Found {len(set(f[2] for f in fptrs))} unique call sites")


def main():
    args = parse_arguments()
    setup_logging(logging.DEBUG if args.verbose else logging.INFO)

    db = Path(args.db_path).absolute()

    if args.subcommand == 'build':
        lib = Path(args.library_path).absolute()
        lib_build = Path(args.build_path).absolute()
        build(lib, lib_build, db, args.build_command, args.autobuild)
    elif args.subcommand == 'list':
        lib = Path(args.library_path).absolute()
        list_all(db, lib)
    elif args.subcommand == 'exec-filter':
        lib  = Path(args.library_path)
        lbins = list(map(Path, args.binary))
        out = Path(args.out_path)
        exec_filter(db, lib, lbins, out, args.verify, args.dfs, args.function,
            args.fptr, args.loc, args.memory, args.timeout)
    else:
        lib  = Path(args.library_path)
        lbins = list(map(Path, args.binary))
        out = Path(args.out_path)
        exec_all(db, lib, lbins, out, args.resume, args.verify, args.dfs,
            args.memory, args.timeout)


if __name__ == '__main__':
    main()
