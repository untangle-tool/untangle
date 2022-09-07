import os
import sys
import pickle
import logging
import psutil
from ctypes import CDLL
from pathlib import Path
from textwrap import indent
from typing import Union, Iterable, Any
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
def nm(binary: str):
    res = {}

    for line in check_output(['nm', binary], text=True).splitlines():
        if line.startswith(' '):
            continue

        line = line.strip().split()
        name = line[-1]
        res[name] = int(line[0], 16)

    return res
