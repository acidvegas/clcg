#!/usr/bin/env python3
# clcg - Linear Congruential Generator for IP Sharding - Developed by acidvegas in C (https://github.com/acidvegas/clcg)
# tests/test.py

'''
Correctness tests for the clcg binary, checked against Python's ipaddress module as an
independent reference. Run from the repository root after `make`: python3 tests/test.py
'''

import ipaddress
import os
import signal
import subprocess
import sys
import tempfile
import time


ROOT  = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
BIN   = os.path.join(ROOT, 'clcg')
FAILS = 0


def run(*args):
	'''Run clcg and return (exit code, stdout lines, stderr)'''

	p = subprocess.run([BIN, *map(str, args)], capture_output=True, text=True)

	return p.returncode, p.stdout.splitlines(), p.stderr


def run_in(text, *args):
	'''Run clcg with text on stdin and return (exit code, stdout lines, stderr)'''

	p = subprocess.run([BIN, *map(str, args)], input=text, capture_output=True, text=True)

	return p.returncode, p.stdout.splitlines(), p.stderr


def check(cond, msg):
	'''Record a failure without stopping the run'''

	global FAILS

	if not cond:
		FAILS += 1
		print(f'FAIL: {msg}')


def expected(cidr, excludes=()):
	'''Every address in cidr minus excludes of the same family, via ipaddress'''

	net = ipaddress.ip_network(cidr)
	ex  = [ipaddress.ip_network(e, strict=False) for e in excludes]
	ex  = [e for e in ex if e.version == net.version]

	return {str(a) for a in net if not any(a in e for e in ex)}


def test_coverage():
	'''Every shard layout covers the range exactly once, with and without excludes'''

	cases = [
		('10.0.0.1/32', []), ('10.0.0.0/31', []), ('10.0.0.0/30', ['10.0.0.1']),
		('10.0.0.0/24', []), ('10.0.0.0/24', ['10.0.0.0/26', '10.0.0.200', '10.0.0.128/30']),
		('10.0.0.0/22', ['10.0.1.0/24', '10.0.2.7', '10.0.3.250/31']), ('10.0.0.0/24', ['10.0.0.0/25', '10.0.0.128/26']),
		('10.0.0.0/20', ['10.0.0.0/8']), ('0.0.0.0/20', ['private']),
		('255.255.255.0/24', ['255.255.255.255', '255.255.255.0/29']), ('255.255.255.0/24', ['255.255.255.192/26']),
		('2001:db8::/120', ['2001:db8::10/124', '10.0.0.0/8']), ('2001:db8::/116', []),
	]

	n = 0

	for cidr, excl in cases:
		# Of the private ranges only 0.0.0.0/8 overlaps 0.0.0.0/20
		want = expected(cidr, ['0.0.0.0/8'] if excl == ['private'] else excl)

		for seed in (0, 1, 2, 12345, 2**64 - 1):
			for shards in (1, 2, 3, 4, 7, 16, 300):
				union = []

				for s in range(1, shards + 1):
					args = [cidr, '--seed', seed, '--total-shards', shards, '--shard-num', s, '--no-state']

					if excl:
						args += ['--exclude', ','.join(excl)]

					code, out, _ = run(*args)
					check(code == 0, f'{args} exited {code}')
					union += out

				check(len(union) == len(set(union)), f'{cidr} {excl} seed {seed} shards {shards}: duplicates')
				check(set(union) == want, f'{cidr} {excl} seed {seed} shards {shards}: coverage mismatch')
				n += 1

	print(f'coverage: {n} layouts')


def test_full_ipv4_prefixes():
	'''Every prefix length from /32 to /16 is covered exactly once'''

	for prefix in range(32, 15, -1):
		cidr = f'10.0.0.0/{prefix}'
		code, out, _ = run(cidr, '--seed', 99, '--no-state')
		check(code == 0 and len(out) == len(set(out)) == 2 ** (32 - prefix) and set(out) == expected(cidr), f'{cidr} coverage')

	print('prefixes: /32 through /16')


def test_resume_is_suffix():
	'''Resuming at any step yields exactly the tail of the full run'''

	for cidr, excl, shards in (('10.0.0.0/26', '10.0.0.5,10.0.0.32/29', 1), ('10.0.0.0/24', '', 3), ('2001:db8::/122', '', 2)):
		for shard in range(1, shards + 1):
			base = [cidr, '--seed', 777, '--total-shards', shards, '--shard-num', shard, '--no-state'] + (['--exclude', excl] if excl else [])
			full = run(*base)[1]
			prev = None

			for step in range(0, 2 ** 8 + 2):
				tail = run(*base, '--state', step)[1]
				check(full[len(full) - len(tail):] == tail if tail else True, f'{cidr} shard {shard} resume {step} is not a suffix')

				if prev is not None:
					check(len(tail) <= len(prev), f'{cidr} resume {step} grew')

				prev = tail

			check(prev == [], f'{cidr} shard {shard}: resuming past the end still output IPs')

	print('resume: every step is an exact suffix')


def test_state_file_and_broken_pipe():
	'''A run cut off by a closed pipe resumes from its state file, losing only what was in flight'''

	with tempfile.TemporaryDirectory() as d:
		path = os.path.join(d, 'sub', 'run.state')
		cidr = '10.0.0.0/16'
		full = run(cidr, '--seed', 5, '--no-state')[1]

		p    = subprocess.Popen([BIN, cidr, '--seed', '5', '--state-file', path, '--state-interval', '1000'], stdout=subprocess.PIPE, text=True)
		head = [p.stdout.readline().strip() for _ in range(20000)]
		p.stdout.close()
		p.wait()

		check(p.returncode == 0, f'broken pipe exited {p.returncode}')
		check(head == full[:20000], 'output before the pipe closed was not the start of the full run')

		with open(path) as f:
			line = f.read()

		check(line.startswith('clcg seed=5 cidr=10.0.0.0/16 shard=1 total=1 '), f'bad state line: {line!r}')

		code, rest, _ = run(cidr, '--state', path)
		check(code == 0, 'resume from state file failed')
		check(full[len(full) - len(rest):] == rest, 'resumed output is not a suffix of the full run')
		# A writer cannot know how much the reader consumed, so whatever sat unread in the
		# pipe when the reader closed is lost. That must be exactly the block right after
		# the last IP read, and no larger than the pipe buffer plus the reader's buffer.
		lost = len(full) - len(rest) - len(head)
		gap  = full[len(head):len(head) + max(lost, 0)]

		check(lost >= 0 and set(head) | set(gap) | set(rest) == set(full), 'IPs lost outside the in-flight block')
		check(sum(len(ip) + 1 for ip in gap) <= 65536 + 8192, f'{lost} IPs lost, more than a pipe buffer')

		with open(path) as f:
			check(f.read().endswith(f'step={2**16}\n'), 'finished run did not record the final step')

		# Resuming writes back to the same file, and a finished run outputs nothing
		check(run(cidr, '--state', path)[1] == [], 'resuming a finished run produced output')

	print('state: broken pipe, resume, write-back')


def test_skip():
	'''--skip N resumes exactly after the first N IPs, so a reader that counts the lines it
	finished loses nothing and repeats nothing even after dying with data still in the pipe'''

	for cidr, excl, shards in (('10.0.0.0/24', '10.0.0.0/28,10.0.0.77', 2), ('2001:db8::/120', '', 1)):
		for shard in range(1, shards + 1):
			base = [cidr, '--seed', 31, '--total-shards', shards, '--shard-num', shard, '--no-state'] + (['--exclude', excl] if excl else [])
			full = run(*base)[1]

			for n in range(0, len(full) + 3):
				check(run(*base, '--skip', n)[1] == full[n:], f'{cidr} shard {shard} --skip {n}')

	with tempfile.TemporaryDirectory() as d:
		path = os.path.join(d, 'run.state')
		cidr = '10.0.0.0/16'
		full = run(cidr, '--seed', 6, '--no-state')[1]

		# The reader handles 20000 lines and dies with more sitting unread in the pipe
		p    = subprocess.Popen([BIN, cidr, '--seed', '6', '--state-file', path], stdout=subprocess.PIPE, text=True)
		head = [p.stdout.readline().strip() for _ in range(20000)]
		p.stdout.close()
		p.wait()

		code, rest, _ = run(cidr, '--state', path, '--skip', len(head))
		check(code == 0, f'resume with --skip exited {code}')
		check(head + rest == full, 'reader count + --skip did not give exactly the full run')

		with open(path) as f:
			check(f.read().endswith(f'step={2**16}\n'), 'state file not advanced by the --skip resume')

		# A --skip that reaches the end still records it, so the state file is not left behind
		stale = os.path.join(d, 'stale.state')

		with open(stale, 'w') as f:
			f.write('clcg seed=2 cidr=10.0.0.0/24 shard=1 total=1 excludes=cbf29ce484222325 step=50\n')

		check(run('10.0.0.0/24', '--state', stale, '--skip', 1000) == (0, [], ''), '--skip past the end did not finish cleanly')

		with open(stale) as f:
			check(f.read().endswith('step=256\n'), '--skip past the end left the state file behind')

	check(run('10.0.0.0/24', '--seed', 1, '--state', 5, '--skip', 3)[0] == 2, '--skip with a raw --state step accepted')
	check(run('10.0.0.0/24', '--seed', 1, '--skip', 'x')[0] == 2, 'non-numeric --skip accepted')

	print('skip: exact resume from a reader\'s line count')


def test_sigint():
	'''SIGINT records the delivered position and exits 130, and resume completes the range'''

	with tempfile.TemporaryDirectory() as d:
		path = os.path.join(d, 'run.state')
		out  = os.path.join(d, 'out.txt')
		cidr = '10.0.0.0/8'

		with open(out, 'w') as f:
			p = subprocess.Popen([BIN, cidr, '--seed', '9', '--state-file', path, '--state-interval', '100000'], stdout=f)
			time.sleep(0.05)
			p.send_signal(signal.SIGINT)
			p.wait()

		check(p.returncode == 130, f'SIGINT exited {p.returncode}')

		with open(out) as f:
			first = f.read().splitlines()

		check(0 < len(first) < 2**24, f'interrupt landed at {len(first)} lines, test needs a mid-run interrupt')

		code, rest, _ = run(cidr, '--state', path)
		both = first + rest

		check(code == 0, 'resume after SIGINT failed')
		check(len(set(both)) == 2**24, f'coverage after SIGINT + resume: {len(set(both))} of {2**24}')
		check(len(both) - 2**24 < 70000, f'resume repeated {len(both) - 2**24} IPs')

	print('sigint: exit 130, resume completes the range')


def test_stalled_reader():
	'''A signal still stops the run while it is blocked writing to a reader that stopped reading'''

	for sig in (signal.SIGINT, signal.SIGTERM):
		r, w = os.pipe()
		p    = subprocess.Popen([BIN, '10.0.0.0/8', '--seed', '1', '--no-state'], stdout=w, stderr=subprocess.DEVNULL)
		os.close(w)
		time.sleep(0.3)
		p.send_signal(sig)

		try:
			p.wait(timeout=2)
			check(p.returncode == 130, f'stalled reader + {sig.name} exited {p.returncode}')
		except subprocess.TimeoutExpired:
			p.kill()
			check(False, f'stalled reader + {sig.name}: still blocked')

		os.close(r)

	print('stalled reader: signals still stop the run')


def test_excludes():
	'''Exclude parsing: keyword, files, comments, mixed families, invalid entries'''

	with tempfile.TemporaryDirectory() as d:
		f = os.path.join(d, 'ex.txt')

		with open(f, 'w') as fh:
			fh.write('# comment\n\n   # indented comment\n10.0.0.0/25\n  10.0.0.200  \n::1\n# ' + 'x' * 5000 + '\n')

		out = run('10.0.0.0/24', '--seed', 1, '--no-state', '--exclude', f'{f},10.0.0.130')[1]
		check(set(out) == expected('10.0.0.0/24', ['10.0.0.0/25', '10.0.0.200', '10.0.0.130']), 'exclude file + list')

		# Excludes from the other family are ignored rather than colliding as integers
		check(len(run('10.0.0.0/24', '--seed', 1, '--no-state', '--exclude', '::/96')[1]) == 256, 'v6 exclude hit a v4 target')
		check(len(run('::/120', '--seed', 1, '--no-state', '--exclude', 'private')[1]) == 256, 'private hit a v6 target')

		# Everything excluded: no output, clean exit
		code, out, _ = run('10.0.0.0/24', '--seed', 1, '--no-state', '--exclude', '10.0.0.0/8')
		check(code == 0 and out == [], 'fully excluded range')

		for bad in ('nope', '10.0.0.0/33', '1.2.3', 'privat'):
			check(run('10.0.0.0/24', '--no-state', '--exclude', bad)[0] == 2, f'bad exclude {bad!r} accepted')

	print('excludes: keyword, files, families, errors')


def test_errors():
	'''Bad arguments exit 2 and I/O errors exit 1, with nothing on stdout'''

	for args in (['10.0.0.1/24'], ['nope'], ['10.0.0.0/24', '--shard-num', 3, '--total-shards', 2], ['10.0.0.0/24', '--total-shards', 0],
	             ['10.0.0.0/24', '--seed', -1], ['10.0.0.0/24', '--state', 5], ['10.0.0.0/24', '--state', 'missing.state'],
	             ['10.0.0.0/24', '--state-interval', 0], ['::/0'], []):
		code, out, _ = run(*args, '--no-state')
		check(code == 2 and out == [], f'{args} exited {code}')

	code, out, _ = run('-h')
	check(code == 0 and out == [], f'-h exited {code}')

	with tempfile.TemporaryDirectory() as d:
		path = os.path.join(d, 'r.state')
		run('10.0.0.0/24', '--seed', 3, '--state-file', path)

		for args, why in (([ '--seed', 4], 'seed'), (['--total-shards', 2], 'shard'), (['--exclude', '10.0.0.1'], 'excludes')):
			check(run('10.0.0.0/24', '--state', path, *args)[0] == 2, f'state mismatch on {why} accepted')

		check(run('10.0.0.0/25', '--state', path)[0] == 2, 'state mismatch on cidr accepted')

		with open(path, 'w') as f:
			f.write('garbage\n')

		check(run('10.0.0.0/24', '--state', path)[0] == 2, 'garbage state file accepted')

		unreadable = os.path.join(d, 'ex.txt')

		with open(unreadable, 'w') as f:
			f.write('10.0.0.1\n')

		os.chmod(unreadable, 0)
		check(run('10.0.0.0/24', '--no-state', '--exclude', unreadable)[0] == 1, 'unreadable exclude file did not exit 1')
		check(run('10.0.0.0/24', '--seed', 1, '--state-file', '/proc/clcg.state')[0] == 1, 'unwritable state file did not exit 1')

	with open('/dev/full', 'w') as full:
		code = subprocess.run([BIN, '10.0.0.0/24', '--seed', '1', '--no-state'], stdout=full, stderr=subprocess.DEVNULL).returncode
		check(code == 1, f'stdout write error exited {code}')

	print('errors: exit codes')


def example(name, *args):
	'''Run a program from examples/ and return (exit code, stdout lines)'''

	p = subprocess.run([os.path.join(ROOT, 'examples', name), *map(str, args)], capture_output=True, text=True)

	return p.returncode, p.stdout.splitlines()


def test_examples():
	'''The library examples give the same IPs as the command, and resume and threads lose nothing'''

	for cidr, seed in (('1.0.0.0/24', 5), ('10.0.0.0/16', 77), ('2001:db8::/120', 3)):
		full = run(cidr, '--seed', seed, '--no-state')[1]
		check(example('basic', cidr, seed) == (0, full), f'examples/basic {cidr} differs from clcg')
		check(example('batch', cidr, seed) == (0, full), f'examples/batch {cidr} differs from clcg')

	with tempfile.TemporaryDirectory() as d:
		full = run('1.0.0.0/24', '--seed', 8, '--no-state')[1]

		# Crash after a few IPs at a time, restart from the saved step, and every IP still
		# comes out exactly once in the original order
		for crash in (1, 37, 100):
			state, out = os.path.join(d, f'{crash}.state'), []

			while True:
				code, lines = example('resume', '1.0.0.0/24', 8, state, crash)
				out += lines

				if code != 3:
					break

			check(code == 0 and out == full, f'examples/resume crashing every {crash} IPs lost or repeated IPs')

	for threads in (1, 3, 8):
		code, lines = example('threads', '1.0.0.0/20', 4, threads)
		total = sum(int(ipaddress.ip_address(a)) for a in ipaddress.ip_network('1.0.0.0/20'))
		check(code == 0 and lines[-1] == f'total: 4096 IPs, address sum {total}', f'examples/threads with {threads} threads: {lines[-1:]}')

	# The ping example sends real packets, so it is only pointed at loopback. Without root
	# it must refuse cleanly; with root every loopback address answers.
	code, lines = example('ping', '127.0.0.0/30')
	check((code == 1 and lines == []) if os.geteuid() else (code == 0 and sorted(lines) == ['127.0.0.0', '127.0.0.1', '127.0.0.2', '127.0.0.3']), f'examples/ping exited {code}')

	print('examples: basic, batch, resume, threads, ping')


def test_ports():
	'''--ports pairs every IP with every port exactly once across shards, resumes and skips
	exactly, and folds the ports and rounds into the state checks'''

	def pair(ip, port):
		return f'[{ip}]:{port}' if ':' in ip else f'{ip}:{port}'

	cases = [
		('10.0.0.1/32', [], '80', [80]), ('10.0.0.0/30', ['10.0.0.1'], '0,65535', [0, 65535]),
		('10.0.0.0/24', ['10.0.0.0/26', '10.0.0.200'], '22,80-82,81,443', [22, 80, 81, 82, 443]),
		('255.255.255.0/28', ['255.255.255.15'], '1-100', list(range(1, 101))), ('2001:db8::/122', ['2001:db8::10/126'], '53,443', [53, 443]),
	]

	n = 0

	for cidr, excl, ports, plist in cases:
		want = {pair(ip, p) for ip in expected(cidr, excl) for p in plist}

		for seed in (0, 12345, 2**64 - 1):
			for rounds in (1, 4, 13):
				for shards in (1, 3, 16):
					union = []

					for s in range(1, shards + 1):
						args = [cidr, '-p', ports, '--rounds', rounds, '--seed', seed, '--total-shards', shards, '--shard-num', s, '--no-state']

						if excl:
							args += ['--exclude', ','.join(excl)]

						code, out, _ = run(*args)
						check(code == 0, f'{args} exited {code}')
						union += out

					check(len(union) == len(set(union)), f'{cidr} {ports} seed {seed} rounds {rounds} shards {shards}: duplicates')
					check(set(union) == want, f'{cidr} {ports} seed {seed} rounds {rounds} shards {shards}: coverage mismatch')
					n += 1

	# The port list order and duplicates do not change the output, the rounds and seed do
	base = run('10.0.0.0/24', '--ports', '80,22,22', '--seed', 1, '--no-state')[1]
	check(base == run('10.0.0.0/24', '--ports', '22,80', '--seed', 1, '--no-state')[1], 'port order changed the output')
	check(base != run('10.0.0.0/24', '--ports', '22,80', '--rounds', 5, '--seed', 1, '--no-state')[1], '--rounds did not change the output')
	check(base != run('10.0.0.0/24', '--ports', '22,80', '--seed', 2, '--no-state')[1], '--seed did not change the output')

	# Resume and skip
	for cidr in ('10.0.0.0/27', '2001:db8::/124'):
		args = [cidr, '-p', '1-3', '--seed', 9, '--total-shards', 2, '--shard-num', 2, '--no-state']
		full = run(*args)[1]

		for step in range(0, 2 ** 7 + 2):
			tail = run(*args, '--state', step)[1]
			check(full[len(full) - len(tail):] == tail, f'{cidr} ports resume {step} is not a suffix')

		for k in range(0, len(full) + 2):
			check(run(*args, '--skip', k)[1] == full[k:], f'{cidr} ports --skip {k}')

	with tempfile.TemporaryDirectory() as d:
		path = os.path.join(d, 'p.state')
		run('10.0.0.0/24', '-p', '80,443', '--seed', 3, '--state-file', path)

		check(run('10.0.0.0/24', '-p', '443,80', '--state', path)[0] == 0, 'state rejected the same ports in another order')

		for args, why in (([], 'no ports'), (['-p', '80'], 'ports'), (['-p', '80,443', '--rounds', 5], 'rounds')):
			check(run('10.0.0.0/24', '--state', path, *args)[0] == 2, f'state mismatch on {why} accepted')

	# Without --ports the state file and its fingerprint are unchanged
	with tempfile.TemporaryDirectory() as d:
		path = os.path.join(d, 'n.state')
		run('10.0.0.0/24', '--seed', 3, '--state-file', path)

		with open(path) as f:
			check('excludes=cbf29ce484222325 ' in f.read(), 'fingerprint without ports changed')

	for args in (['-p', ''], ['-p', ','], ['-p', '65536'], ['-p', '5-3'], ['-p', '-80'], ['-p', '80-'], ['-p', '8a'], ['-p', '1-2-3'],
	             ['-p', '80', '--rounds', 0], ['-p', '80', '--rounds', 65], ['--rounds', 4], ['-p']):
		code, out, _ = run('10.0.0.0/24', *args, '--no-state')
		check(code == 2 and out == [], f'{args} exited {code}')

	# 2^127 pairs is the limit
	check(run('::/1', '-p', '80', '--no-state', '--seed', 1, '--state', 2**127 - 5)[0] == 0, '::/1 with 1 port refused')
	check(run('::/1', '-p', '80,81', '--no-state')[0] == 2, '::/1 with 2 ports accepted')

	print(f'ports: {n} layouts, resume, skip, state checks, errors')


def expected_list(targets, excludes=()):
	'''Every address in a list of targets minus excludes of the same family, via ipaddress'''

	ex   = [ipaddress.ip_network(e, strict=False) for e in excludes]
	want = set()

	for t in targets:
		net   = ipaddress.ip_network(t)
		want |= {str(a) for a in net if not any(a.version == e.version and a in e for e in ex)}

	return want


def test_targets():
	'''A target list of IPs, CIDRs and files, IPv4 and IPv6 mixed, covers each address once
	across shards, resumes and skips exactly, and is checked on resume like the excludes'''

	with tempfile.TemporaryDirectory() as d:
		tfile = os.path.join(d, 'targets.txt')

		with open(tfile, 'w') as f:
			f.write('# targets\n10.9.0.0/29\n\n2001:db8:1::/126\n  10.9.0.8  \n')

		file_nets = ['10.9.0.0/29', '2001:db8:1::/126', '10.9.0.8']

		cases = [
			(['10.0.0.0/30', '10.0.0.8/30'], []),
			(['10.0.0.0/24', '10.0.0.0/25', '10.0.0.7', '10.0.1.0/24'], ['10.0.0.128/26']),
			(['10.0.0.1', '10.0.0.3', '10.0.0.255', '10.0.2.0'], []),
			(['255.255.255.254/31', '0.0.0.0/30'], ['0.0.0.1']),
			(['10.0.0.0/26', '2001:db8::/122', '192.168.0.0/30'], ['10.0.0.5', '2001:db8::10/124', '192.168.0.0/31']),
			(['2001:db8::/124', '2001:db8::100/124', '::1'], ['2001:db8::4/126']),
			(['10.0.0.0/28', 'FILE'], ['10.9.0.2']),
		]

		n = 0

		for targets, excl in cases:
			want = expected_list([t for t in targets if t != 'FILE'] + (file_nets if 'FILE' in targets else []), excl)
			arg  = ','.join(tfile if t == 'FILE' else t for t in targets)

			for seed in (0, 99, 2**64 - 1):
				for shards in (1, 2, 5, 32):
					union = []

					for s in range(1, shards + 1):
						args = [arg, '--seed', seed, '--total-shards', shards, '--shard-num', s, '--no-state'] + (['--exclude', ','.join(excl)] if excl else [])
						code, out, err = run(*args)
						check(code == 0, f'{args} exited {code}: {err}')
						union += out

					check(len(union) == len(set(union)), f'{arg} {excl} seed {seed} shards {shards}: duplicates')
					check(set(union) == want, f'{arg} {excl} seed {seed} shards {shards}: coverage mismatch')
					n += 1

		# The same addresses give the same order however the list is written
		ref = run('10.0.0.0/23', '--seed', 4, '--no-state')[1]
		check(ref == run('10.0.1.0/24,10.0.0.0/24,10.0.0.0/25', '--seed', 4, '--no-state')[1], 'list order or overlap changed the output')

		# Resume and skip over a mixed list
		args = ['10.0.0.0/27,2001:db8::/123,10.1.0.0/30', '--seed', 5, '--exclude', '10.0.0.3,2001:db8::8/125', '--total-shards', 2, '--shard-num', 2, '--no-state']
		full = run(*args)[1]

		for step in range(0, 2 ** 6 + 2):
			tail = run(*args, '--state', step)[1]
			check(full[len(full) - len(tail):] == tail, f'mixed list resume {step} is not a suffix')

		for k in range(0, len(full) + 2):
			check(run(*args, '--skip', k)[1] == full[k:], f'mixed list --skip {k}')

		# A state file is refused once the target file changes, and accepted while it does not
		path = os.path.join(d, 't.state')
		run(tfile, '--seed', 3, '--state-file', path)
		check(run(tfile, '--state', path)[0] == 0, 'unchanged target file refused on resume')

		with open(tfile, 'a') as f:
			f.write('10.9.1.0/30\n')

		check(run(tfile, '--state', path)[0] == 2, 'changed target file accepted on resume')

		with open(tfile, 'w') as f:
			f.write('10.9.0.0/29\n10.9.0.0/30\n')

		path2 = os.path.join(d, 't2.state')
		run(tfile, '--seed', 3, '--state-file', path2)

		with open(tfile, 'w') as f:
			f.write('10.9.0.0/28\n')

		check(run(tfile, '--state', path2)[0] == 2, 'grown target file accepted on resume')

		# Errors
		bad = os.path.join(d, 'bad.txt')

		with open(bad, 'w') as f:
			f.write('10.0.0.0/24\nnope\n')

		for arg in ('10.0.0.0/8,10.0.0.1/24', 'nope,10.0.0.0/8', ',', '', 'private', '::/0', '::/1,8000::/2', bad):
			code, out, _ = run(arg, '--no-state')
			check(code == 2 and out == [], f'target {arg!r} exited {code}')

		unreadable = os.path.join(d, 'unreadable.txt')

		with open(unreadable, 'w') as f:
			f.write('10.0.0.1\n')

		os.chmod(unreadable, 0)
		check(run(f'10.0.0.0/30,{unreadable}', '--no-state')[0] == 1, 'unreadable target file did not exit 1')

	# 2^127 exactly is allowed, overlaps included
	check(run('::/1,::/2', '--seed', 1, '--no-state', '--state', 2**127 - 3)[0] == 0, '::/1 with an overlap refused')

	# A span over all of IPv6
	code, out, _ = run('::,ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', '--seed', 1, '--no-state')
	check(code == 0 and sorted(out) == ['::', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'], f'full IPv6 span: {code} {out}')
	check(run('::,ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', '--exclude', '::/0', '--seed', 1, '--no-state')[:2] == (0, []), 'full IPv6 span fully excluded')
	check(run('::,ffff::/16', '--exclude', 'ffff::/17', '--seed', 1, '--no-state', '--state', 2**127 - 3)[0] == 0, 'span with an exclusion at the top of IPv6')

	# Overlapping exclusions that both end at the top of IPv6 merge instead of counting twice
	top  = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff'
	want = expected(f'{top}:ff00/120', [f'{top}:ffc0/122'])
	code, out, _ = run(f'{top}:ff00/120', '--exclude', f'{top}:ffc0/122,{top}:ffe0/123', '--seed', 1, '--no-state')
	check(code == 0 and len(out) == len(set(out)) and set(out) == want, f'nested exclusions at the top of IPv6: {len(out)} of {len(want)}')

	# A state line holds up to 4000 characters of targets and no whitespace
	long = ','.join(f'10.{i // 256}.{i % 256}.0/30' for i in range(400))
	check(len(long) > 4000 and run(long, '--seed', 1, '--state-file', os.devnull)[0] == 2, 'over-long target list accepted with a state file')
	check(run(long, '--seed', 1, '--no-state')[0] == 0, 'over-long target list refused without a state file')
	check(run('10.0.0.0/30, 10.0.1.0/30', '--seed', 1, '--state-file', os.devnull)[0] == 2, 'whitespace target list accepted with a state file')
	check(len(run('10.0.0.0/30, 10.0.1.0/30', '--seed', 1, '--no-state')[1]) == 8, 'whitespace target list without a state file')

	print(f'targets: {n} layouts, files, mixed families, resume, skip, state checks, errors')


def span(lo, hi):
	'''Every address from lo to hi inclusive, via ipaddress'''

	return {str(a) for net in ipaddress.summarize_address_range(ipaddress.ip_address(lo), ipaddress.ip_address(hi)) for a in net}


def test_ranges_and_stdin():
	'''IP-IP ranges work in targets, excludes and files, and "-" reads targets from stdin once,
	with resume refusing a different list on stdin'''

	n = 0

	cases = [
		('10.0.0.250-10.0.1.3', [], span('10.0.0.250', '10.0.1.3')),
		('10.0.0.5-10.0.0.5,10.0.0.0/30', [], span('10.0.0.5', '10.0.0.5') | span('10.0.0.0', '10.0.0.3')),
		('255.255.255.200-255.255.255.255,0.0.0.0-0.0.0.9', ['255.255.255.250-255.255.255.252'], (span('255.255.255.200', '255.255.255.255') | span('0.0.0.0', '0.0.0.9')) - span('255.255.255.250', '255.255.255.252')),
		('2001:db8::fff0-2001:db8::1:f,10.1.0.0-10.1.0.20', ['2001:db8::1:0-2001:db8::1:3', '10.1.0.0/30'], (span('2001:db8::fff0', '2001:db8::1:f') | span('10.1.0.0', '10.1.0.20')) - span('2001:db8::1:0', '2001:db8::1:3') - span('10.1.0.0', '10.1.0.3')),
	]

	for arg, excl, want in cases:
		for shards in (1, 3, 8):
			union = []

			for sh in range(1, shards + 1):
				union += run(arg, '--seed', 6, '--total-shards', shards, '--shard-num', sh, '--no-state', *(['--exclude', ','.join(excl)] if excl else []))[1]

			check(len(union) == len(set(union)) and set(union) == want, f'{arg} {excl} shards {shards}: coverage mismatch')
			n += 1

	check(run('10.0.0.0-10.0.1.255', '--seed', 2, '--no-state')[1] == run('10.0.0.0/23', '--seed', 2, '--no-state')[1], 'range and CIDR of the same addresses differ')

	for arg in ('10.0.0.9-10.0.0.1', '10.0.0.1-::1', '10.0.0.1-', '10.0.0.1-10.0.0.3/24', '10.0.0.1--10.0.0.3', '10.0.0.1-10.0.0.2-10.0.0.3', 'a-b'):
		code, out, _ = run(arg, '--no-state')
		check(code == 2 and out == [], f'target {arg!r} exited {code}')

	check(run('10.0.0.0/24', '--exclude', '10.0.0.9-10.0.0.1', '--no-state')[0] == 2, 'reversed exclude range accepted')

	# stdin, alone, in a list, after --, with comments, ranges and both families
	text = '# piped\n10.0.0.0/30\n\n  2001:db8::1-2001:db8::2  \n10.0.0.2\n'
	want = span('10.0.0.0', '10.0.0.3') | {'2001:db8::1', '2001:db8::2'}

	for args in (['-'], ['192.168.0.1,-'], ['--seed', 1, '--no-state', '--', '-,192.168.0.1']):
		code, out, err = run_in(text, *args) if '--' in args else run_in(text, *args, '--seed', 1, '--no-state')
		extra = set() if args == ['-'] else {'192.168.0.1'}
		check(code == 0 and len(out) == len(set(out)) and set(out) == want | extra, f'stdin {args}: {code} {err}')

	code, out, _ = run_in(text, '-', '-p', '80,U:53', '--seed', 1, '--no-state')
	check(code == 0 and len(out) == 12 and len(set(out)) == 12, f'stdin with ports: {code} {len(out)}')

	for bad, why in (('', 'empty stdin'), ('10.0.0.0/30\nnope\n', 'bad line'), ('10.0.0.1/24\n', 'host bits')):
		check(run_in(bad, '-', '--no-state')[0] == 2, f'{why} on stdin accepted')

	check(run_in('10.0.0.0/30\n', '10.0.0.0/24', '--exclude', '-', '--no-state')[0] == 2, '- accepted as an exclude')

	# Resume needs the same list on stdin again, even for a single CIDR
	with tempfile.TemporaryDirectory() as d:
		path = os.path.join(d, 's.state')
		full = run_in('10.0.0.0/24\n', '-', '--seed', 4, '--no-state')[1]
		run_in('10.0.0.0/24\n', '-', '--seed', 4, '--state-file', path)

		# Rewind the finished state file to step 100 to resume partway
		with open(path) as f:
			line = f.read()

		with open(path, 'w') as f:
			f.write(line[:line.index(' step=')] + ' step=100\n')

		code, tail, _ = run_in('10.0.0.0/24\n', '-', '--state', path)
		check(code == 0 and tail and full[len(full) - len(tail):] == tail, 'stdin resume is not a suffix')
		check(run_in('10.0.1.0/24\n', '-', '--state', path)[0] == 2, 'different single CIDR on stdin accepted on resume')
		check(run_in('10.0.0.0/24\n10.0.1.7\n', '-', '--state', path)[0] == 2, 'different list on stdin accepted on resume')
		check(run_in('10.0.0.0/25\n10.0.0.128/25\n', '-', '--state', path)[0] == 0, 'same addresses written differently on stdin refused on resume')

	print(f'ranges and stdin: {n} layouts, errors, resume')


def test_protocols():
	'''T:, U: and S: tag each port item, untagged is TCP, and every protocol of a port is its
	own pair'''

	cidr = '10.0.0.0/29,2001:db8::/126'
	ips  = expected_list(['10.0.0.0/29', '2001:db8::/126'])

	def line(ip, port, proto):
		return (f'[{ip}]' if ':' in ip else ip) + f':{port}' + ('' if proto == 'tcp' else f'/{proto}')

	for ports, plist in (('U:53,161', [(53, 'udp'), (161, 'tcp')]), ('t:80,u:80,s:80,80', [(80, 'tcp'), (80, 'udp'), (80, 'sctp')]),
	                     ('S:1-3,U:65535,0', [(1, 'sctp'), (2, 'sctp'), (3, 'sctp'), (65535, 'udp'), (0, 'tcp')])):
		want = {line(ip, p, proto) for ip in ips for p, proto in plist}

		for shards in (1, 3):
			union = []

			for s in range(1, shards + 1):
				union += run(cidr, '-p', ports, '--seed', 8, '--total-shards', shards, '--shard-num', s, '--no-state')[1]

			check(len(union) == len(set(union)) and set(union) == want, f'-p {ports} shards {shards}: coverage mismatch')

	check(run(cidr, '-p', 'U:53,80', '--seed', 1, '--no-state')[1] == run(cidr, '-p', '80,U:53,80', '--seed', 1, '--no-state')[1], 'port order changed the output')
	check(run(cidr, '-p', 'U:53', '--seed', 1, '--no-state')[1] != run(cidr, '-p', '53', '--seed', 1, '--no-state')[1], 'U:53 and 53 gave the same output')

	with tempfile.TemporaryDirectory() as d:
		path = os.path.join(d, 'p.state')
		run(cidr, '-p', 'U:53', '--seed', 3, '--state-file', path)
		check(run(cidr, '-p', '53', '--state', path)[0] == 2, 'state accepted a different protocol')
		check(run(cidr, '-p', 'u:53', '--state', path)[0] == 0, 'state refused the same protocol')

	for ports in ('X:80', 'U:', 'U:-5', 'UDP:53', 'U:53-', ':80', 'U:53:1', '1:80', 'U:70000'):
		code, out, _ = run(cidr, '-p', ports, '--no-state')
		check(code == 2 and out == [], f'-p {ports} exited {code}')

	print('protocols: tags, coverage, state checks, errors')


def test_random_seed():
	'''Without --seed a random seed is chosen and printed to stderr only'''

	code, out, err = run('10.0.0.0/28', '--no-state')
	check(code == 0 and len(out) == 16 and err.startswith('Using random seed: '), 'random seed notice')

	# Different seeds give different orders
	orders = {tuple(run('10.0.0.0/24', '--seed', s, '--no-state')[1]) for s in range(20)}
	check(len(orders) == 20, f'only {len(orders)} distinct orders from 20 seeds')

	print('seed: random notice, distinct orders')


if __name__ == '__main__':
	if not os.path.isfile(BIN):
		sys.exit('build first: make')

	for test in (test_coverage, test_full_ipv4_prefixes, test_resume_is_suffix, test_state_file_and_broken_pipe, test_skip, test_sigint, test_stalled_reader, test_excludes, test_errors, test_examples, test_ports, test_targets, test_ranges_and_stdin, test_protocols, test_random_seed):
		test()

	print('FAILED' if FAILS else 'OK', f'({FAILS} failures)' if FAILS else '')
	sys.exit(1 if FAILS else 0)
