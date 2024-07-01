import sys
import logging
from subprocess import Popen, PIPE
from pathlib import Path
from textwrap import indent
from tempfile import TemporaryDirectory

from .utils import ensure_command

logger = logging.getLogger('codeql')

def build_codeql_db(library_path, out_db_path, build_command, autobuild):
    '''Create a CodeQL database for a given libary by building it using a given
    build command.
    '''
    if autobuild:
        args = ('codeql', 'database', 'create', out_db_path,
        '--language=cpp', '--overwrite')
    else:
        args = (
            'codeql', 'database', 'create', out_db_path,
            '--language=cpp', '--overwrite', '--command', build_command
        )

    ensure_command(args, cwd=library_path)

def run_codeql_query(db_path, query):
    '''Run a CodeQL query and return results as a list of tuples.
    '''
    with TemporaryDirectory(prefix='codeql-query-') as tmpdir:
        tmpdir     = Path(tmpdir)
        query_path = tmpdir / 'query.ql'
        query_file = query_path.open('w')
        pack_file  = (tmpdir / 'qlpack.yml').open('w')

        # Silly workaround, codeql does not seem to like PIPE for stdout
        out_path = tmpdir / 'out'
        out_file = out_path.open('wb+')

        query_file.write(query)
        query_file.flush()
        pack_file.write('name: whatever\nversion: 0.0.0\nextractor: cpp\nlibraryPathDependencies: codeql/cpp-all\n')
        pack_file.flush()
        cmd = ['codeql', 'query', 'run', '-d', db_path, query_path.as_posix()]

        p = Popen(cmd, stdout=out_file, stderr=PIPE)
        exit_code = p.wait()

    if exit_code != 0:
        err = indent(p.stderr.read().decode(), '\t')
        logger.fatal('Failed to run command: %s\n%s', cmd, err)
        sys.exit(1)

    out_file.seek(0)
    for line in out_file:
        if line.startswith(b'+-') and line.rstrip().endswith(b'-+'):
            break

    res = []
    for line in out_file:
        if not line.startswith(b'|'):
            break

        res.append(tuple(map(str.strip, line.decode().split('|')))[1:-1])

    return res
