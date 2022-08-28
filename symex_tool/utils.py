import sys
import logging
from pathlib import Path
from textwrap import indent
from typing import Union, Iterable
from subprocess import Popen, DEVNULL, PIPE

logger = logging.getLogger('utils')

def do_popen(cmd: Union[str,Iterable[str]], cwd: Union[str,Path], **kwargs) -> Popen:
	try:
		return Popen(cmd, cwd=cwd, **kwargs)
	except FileNotFoundError:
		# We can also get here if the passed cwd= is invalid, so differentiate
		# between the two. Yes this is racy... see if I care.
		if cwd.exists():
			cmd = cmd.split()[0] if isinstance(cmd, str) else cmd[0]
			logger.critical('Command not found: %s', cmd)
		else:
			logger.critical('Directory does not exist: %s', cwd)
	except NotADirectoryError:
		logger.critical('Path is not a directory: %s', cwd)

	return None

def ensure_command(cmd: Union[str,Iterable[str]], cwd: Union[str,Path] = None) -> str:
	logger.debug('Running command: %s', cmd)

	child = do_popen(cmd, cwd, shell=isinstance(cmd, str), stdout=DEVNULL, stderr=PIPE, text=True)
	if child is None:
		sys.exit(127)

	_, err = child.communicate()

	if child.returncode != 0:
		err = ('\n' + indent(err, '\t')) if err.strip() else ' (no stderr output)'
		logger.critical('Command returned %d: %s%s', child.returncode, cmd, err)
		sys.exit(1)
