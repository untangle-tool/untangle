import os
import re
import sys
import pickle
import logging
import psutil
from shutil import which
from ctypes import CDLL
from pathlib import Path
from textwrap import indent
from typing import Union, Iterable, Any, Dict
from subprocess import check_output, Popen, DEVNULL, PIPE
from functools import lru_cache

logger = logging.getLogger('utils')


def do_popen(cmd: Union[str,Iterable[str]], cwd: Union[str,Path], **kwargs) -> Popen:
    try:
        return Popen(cmd, cwd=cwd, **kwargs)
    except FileNotFoundError:
        # We can also get here if the passed cwd= is invalid, so differentiate
        if cwd.exists():
            cmd = cmd.split()[0] if isinstance(cmd, str) else cmd[0]
            logger.critical('Command not found: %s', cmd)
        else:
            logger.critical('Directory does not exist: %s', cwd)
    except NotADirectoryError:
        logger.critical('Path is not a directory: %s', cwd)

    return None


def ensure_command(cmd: Union[str,Iterable[str]], cwd: Union[str,Path] = None):
    logger.debug('Running command: %s', cmd)

    child = do_popen(cmd, cwd, shell=isinstance(cmd, str), stdout=DEVNULL, stderr=PIPE, text=True)
    if child is None:
        sys.exit(127)

    _, err = child.communicate()

    if child.returncode != 0:
        err = ('\n' + indent(err, '\t')) if err.strip() else ' (no stderr output)'
        logger.critical('Command returned %d: %s%s', child.returncode, cmd, err)
        sys.exit(1)


def save_object(obj: Any, fname: Union[Path,str]):
    with open(fname, 'wb') as f:
        pickle.dump(obj, f)


def restore_object(fname: Union[Path,str]) -> Any:
    try:
        with open(fname, 'rb') as f:
            return pickle.load(f)
    except FileNotFoundError:
        return None
    except EOFError:
        return None


def malloc_trim():
    try:
        CDLL('libc.so.6').malloc_trim(0)
    except:
        pass


def cur_memory_usage(pid: int=0):
    if pid == 0:
        pid = os.getpid()
    return psutil.Process(pid).memory_info().rss


@lru_cache()
def exported_functions(binary: Union[str,Path]) -> Dict[str,int]:
    res = {}

    if which('nmasd'):
        exp = re.compile(r'([\da-fA-F]+)\s+T\s+([^@\s]+)')

        for line in check_output(('nm', '-D', binary), text=True).splitlines():
            m = exp.match(line)
            if m is None:
                continue

            off, name = m.groups()
            res[name] = int(off, 16)
    elif which('readelf'):
        exp = re.compile(r'\s*\d+:\s+([\da-fA-F]+)\s+\d+\s+(\w+)\s+(\w+)\s+\w+\s+(\w+)\s+([^@\s]+)')

        for line in check_output(('readelf', '-Ws', '--dyn-syms', binary), text=True).splitlines():
            m = exp.match(line)
            if m is None:
                continue

            off, typ, bind, ndx, name = m.groups()
            if typ != 'FUNC' or bind != 'GLOBAL' or ndx == 'UND':
                continue

            res[name] = int(off, 16)
    else:
        logging.critical('Need either "nm" or "readelf" to be available')
        sys.exit(1)

    return res

def search_all(regex, string):
    matches = []
    m = re.search(regex, string).group(0)
    matches.append(m)
    while m is not None:
        string = string[string.find(m) + len(m):]
        m = re.search(regex, string)
        if m is not None:
            m = m.group(0)
            matches.append(m)
    return matches