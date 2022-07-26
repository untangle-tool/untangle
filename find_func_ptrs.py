#!/usr/bin/env python3

import os
import sys
import tempfile
from pathlib import Path
from subprocess import Popen, PIPE, DEVNULL
from textwrap import indent
from collections import defaultdict

def log(*a, **kwa):
	print(*a, **kwa, file=sys.stderr, flush=True)


def run_codeql_query(db_path, query):
	'''Run a CodeQL query and return results as a list of tuples.'''

	n_cores = max(len(os.sched_getaffinity(0)) - 1, 1)

	with tempfile.TemporaryDirectory(prefix='codeql-query-') as tmpdir:
		tmpdir     = Path(tmpdir)
		tmpdir     = Path('.')
		query_path = tmpdir / 'query.ql'
		query_file = query_path.open('w')
		pack_file  = (tmpdir / 'qlpack.yml').open('w')

		# Silly workaround, codeql does not seem to like subprocess.PIPE for stdout :|
		out_path = tmpdir / 'out'
		out_file = out_path.open('wb+')

		query_file.write(query)
		query_file.flush()
		pack_file.write('name: whatever\nversion: 0.0.0\nextractor: cpp\nlibraryPathDependencies: codeql/cpp-all')
		pack_file.flush()
		cmd = ['codeql', 'query', 'run', f'-j{n_cores}', '-d', db_path, query_path.as_posix()]

		p = Popen(cmd, stdout=out_file, stderr=PIPE)
		exit_code = p.wait()

	if exit_code != 0:
		log('Failed to run command:', cmd, end='\n\n')
		log(indent(p.stderr.read().decode(), '\t'))
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


def main(argv):
	if len(argv) != 2:
		log('Usage:', argv[0], 'CODEQL_DB_PATH')
		sys.exit(1)

	db_path = argv[1]
	results = run_codeql_query(db_path, FUNC_PTRS_QUERY)

	fptr_decls = {}
	fptr_calls = defaultdict(lambda: defaultdict(list))

	for name, typ, decl_loc, *call_loc, exported_func, exported_loc, sig in results:
		fptr_decls[name] = decl_loc
		fptr_calls[name][tuple(call_loc)].append((exported_func, exported_loc, sig))

	for name, decl_loc in fptr_decls.items():
		print(name, 'declared at', decl_loc)
		calls = fptr_calls[name]

		for call_loc in calls:
			caller, *loc = call_loc
			print('\tcalled from', caller, 'at', ':'.join(loc))

			for exp_func, exp_loc, sig in calls[call_loc]:
				print('\t\treachable from', exp_func, 'defined at', exp_loc, 'with signature', sig)


################################################################################


FUNC_PTRS_QUERY = '''
import cpp

class FancyFunc extends Function {
	predicate isExported() {
		not this.isStatic()
	}

	FancyFunc getACaller() {
		result = this.getACallToThisFunction().getEnclosingFunction()
	}

	FancyFunc getARootExportedFunc() {
		result = this.getACaller*() and result.isExported()
	}

	private string stringifyParam(Parameter p) {
		if p.getUnderlyingType() instanceof Enum
		then result = "int" // NOTE: C++11 enums may have different enum-base
		else result = p.getUnderlyingType().getUnspecifiedType().toString()
	}

	private string sig(Parameter cur, int nLeft) {
		if nLeft = 0
		then result = this.stringifyParam(cur)
		else result = (this.stringifyParam(cur) + ", "
			+ this.sig(this.getParameter(this.getNumberOfParameters() - nLeft), nLeft - 1))
	}

	string getSimplifiedSignature() {
		(this.getNumberOfParameters() = 0 and result = "void")
		or
		result = this.sig(this.getParameter(0), this.getNumberOfParameters() - 1)
	}
}

from
	GlobalVariable v,
	Type t,
	FunctionPointerIshType f,
	VariableCall vc,
	VariableAccess va,
	Location l,
	FancyFunc leaf,
	FancyFunc root
where
	not v.isConst()
	and t = v.getType()
	and (f = t or f = t.getUnderlyingType())
	and va = vc.getExpr()
	and v = va.getTarget()
	and l = va.getLocation()
	and leaf = va.getEnclosingFunction()
	and root = leaf.getARootExportedFunc()
select
	v as Variable,
	t as Type,
	v.getLocation().getFile().getRelativePath() + ":" + v.getLocation().getStartLine() as DeclLocation,
	leaf.getQualifiedName() as CallerFunc,
	l.getFile().getRelativePath() as CallFile,
	l.getStartLine() as CallStartRow,
	l.getStartColumn() as CallStartCol,
	l.getEndLine() as CallEndRow,
	l.getEndColumn() as CallEndCol,
	root.getQualifiedName() as ExportedFunc,
	root.getLocation().getFile().getRelativePath() + ":" + root.getLocation().getStartLine() as Location,
	root.getSimplifiedSignature() as Signature
'''

if __name__ == '__main__':
	main(sys.argv)
