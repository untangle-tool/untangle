#!/usr/bin/env python3
#
# Parse results in output directory and report interesting statistics.
#

import sys
import os
import re
from pathlib import Path

if len(sys.argv) != 2:
	sys.exit(f'Usage: {sys.argv[0]} RESULT_DIR')

res_dir = Path(sys.argv[1])
time_mem_exp = re.compile(r'Completed in ([\d.]+) seconds, using (\d+) MiB of memory')

class Res:
	funcname: str
	time: float
	mem: float
	found: bool
	errored: bool
	error: str
	verified: str
	ver_outcome: str
	__slots__ = (
		'funcname',
		'time',
		'mem',
		'found',
		'errored',
		'error',
		'verified',
		'ver_outcome',
	)

def merge(r1, r2):
	if r1.errored and not r2.errored:
		return r2
	if r2.errored and not r1.errored:
		return r1
	if r1.found and not r2.found:
		return r1
	if r2.found and not r1.found:
		return r2
	if r1.verified and not r2.verified:
		return r1
	if r2.verified and not r1.verified:
		return r2

	if r1.verified and r2.verified:
		if r1.ver_outcome == 'ok' and r2.ver_outcome != 'ok':
			return r1
		if r2.ver_outcome == 'ok' and r1.ver_outcome != 'ok':
			return r2

	assert r1.found == r2.found
	assert r1.errored == r2.errored
	assert r1.verified == r2.verified

	r = Res()
	r.time     = r1.time + r2.time
	r.mem      = max(r1.mem, r2.mem)
	r.found    = r1.found or r2.found
	r.errored  = r1.errored
	r.verified = r1.verified

	if r1.errored:
		# r1 and r2 errors could be different, not important
		r.error = r1.error

	if r1.verified:
		assert r1.ver_outcome == r2.ver_outcome, f'{r1.ver_outcome} != {r2.ver_outcome}'
		r.ver_outcome = r1.ver_outcome

	return r


funcs = {}

for f in res_dir.iterdir():
	data = f.open().read()
	funcname = f.stem[f.stem.find('_') + 1:]

	m = time_mem_exp.search(data)
	if not m:
		# Stop at first incomplete file
		break

	cur = Res()
	# assert m, f'{f} does not have time/mem info?'
	cur.time, cur.mem = float(m.group(1)), float(m.group(2))

	if 'Exceeded maximum memory usage' in data:
		cur.errored = True
		cur.error = 'mem'
	elif 'Exceeded maximum execution time' in data:
		cur.errored = True
		cur.error = 'time'
	elif 'SymexecFailed' in data or 'Symexec failed' in data or 'argument evaluation failed' in data:
		cur.errored = True
		cur.error = 'choked'
	else:
		cur.errored = False

	if cur.errored:
		cur.found = False
		cur.verified = False
	else:
		if 'Reached call to' in data and not 'argument evaluation failed' in data:
			cur.found = True
		else:
			cur.found = False

		if 'Verification successful' in data:
			cur.verified = True
			cur.ver_outcome = 'ok'
		elif 'Verification failed' in data:
			cur.verified = True
			cur.ver_outcome = 'fail'
		elif 'Verification errored' in data:
			cur.verified = True
			cur.ver_outcome = 'error'
		else:
			cur.verified = False

	cur.funcname = funcname

	# libxml2 quirk
	if funcname.endswith('__internal_alias'):
		funcname = funcname.replace('__internal_alias', '')

	if funcname in funcs:
		cur = merge(funcs[funcname], cur)

	if cur.errored:
		assert cur.error
	if cur.verified:
		assert cur.ver_outcome

	funcs[funcname] = cur


total    = 0 # total funcs analyzed
found    = 0 # funcs for which symex found a result
notfound = 0 # funcs for which symex did not find a result

verified = 0 # funcs that also got verified on the found result
ver_ok   = 0 # funcs that also passed verification on the found result
ver_fail = 0 # funcs that did not pass verification on the found result
ver_err  = 0 # verification errored

errored    = 0 # funcs for which symex errored/failed/crashed/whatever
err_mem    = 0 # ran out of memory
err_time   = 0 # ran out of time
err_choked = 0 # angr/claripy choked

tot_time       = 0 # total time spent doing everything
time_avg       = 0 # average time spent on a func regardless of outcome
found_time     = 0 # total time spent on funcs that returned a found result
found_time_max = 0 # max time spent on a func that returned a found result
found_time_avg = 0 # avg time spent on funcs that returned a found result

tot_mem        = 0 # total mem used
mem_avg        = 0 # avg mem used
found_mem      = 0 # total mem used on funcs that returned a found result
found_mem_avg  = 0 # avg mem used on funcs that returned a found result


for funcname, res in funcs.items():
	total += 1
	tot_time += res.time
	tot_mem += res.mem

	if res.found:
		found += 1
		found_mem += res.mem
		found_time += res.time
		found_time_max = max(found_time_max, res.time)
	else:
		notfound += 1

	if res.errored:
		errored += 1
		if res.error == 'time':
			err_time += 1
		elif res.error == 'mem':
			err_mem += 1
		elif res.error == 'choked':
			err_choked += 1
		else:
			assert False

	if res.verified:
		verified += 1
		if res.ver_outcome == 'ok':
			ver_ok += 1
		elif res.ver_outcome == 'fail':
			ver_fail += 1
		elif res.ver_outcome == 'error':
			ver_err += 1
		else:
			assert False


assert found + notfound == total
assert found == verified
assert ver_ok + ver_fail + ver_err == verified
assert err_mem + err_time + err_choked == errored

noterrored = notfound - errored

mem_avg        = tot_mem / total
time_avg       = tot_time / total
found_time_avg = found_time / found
found_mem_avg  = found_mem / found


print(f'''\
Total functions tested {total}
  Solution found       {found} ({found / total:.2%})
    Verified           {verified}''')

if verified:
	print(f'''\
      Ver OK           {ver_ok} ({ver_ok / verified:.2%})
      Ver failed       {ver_fail} ({ver_fail / verified:.2%})
      Ver errored      {ver_err} ({ver_err / verified:.2%})''')

print(f'''\
  Solution not found   {notfound} ({notfound / total:.2%})''')

if notfound:
	print(f'''\
    Not errored        {noterrored} ({noterrored / notfound:.2%})
    Errored            {errored} ({errored / notfound:.2%})''')

if errored:
	print(f'''\
      Out of time      {err_time} ({err_time / errored:.2%})
      Out of memory    {err_mem} ({err_mem / errored:.2%})
      Symex error      {err_choked} ({err_choked / errored:.2%})''')

print(f'''
Total time             {tot_time:.2f} seconds
Average time           {time_avg:.2f} seconds
Average memory         {mem_avg:.2f} MiB

Found total time       {found_time:.2f} seconds
Found max time         {found_time_max:.2f} seconds
Found avg time         {found_time_avg:.2f} seconds
Found avg memory       {found_mem_avg:.0f} MiB''')
