# clcg

Stream every IP address in a list of CIDRs exactly once, in a pseudo-random order, with sharding, exclusions and resume. Use it as a command that writes IPs to stdout, or as a C library that hands them to your program directly. It is the C successor to [pylcg](https://github.com/acidvegas/pylcg) and runs 70 to 90 times faster. With `--ports` it streams every IP:port pair instead, TCP, UDP or SCTP, shuffled by a Feistel network.

## Building

```
make                  # clcg, libclcg.a, libclcg.so.1
make static           # clcg-static, one file that runs on any Linux machine
make test             # library tests, plus CLI tests checked against Python's ipaddress module
make fullcheck        # every address of 0.0.0.0/0 checked in a 512MB bitmap, takes minutes
sh tests/sanitize.sh  # all tests under AddressSanitizer and UndefinedBehaviorSanitizer
make install          # clcg, clcg.h, libclcg.a and libclcg.so.1 under /usr/local
```

Linux only, no dependencies. Built and tested with gcc 13 and clang 18, which produce identical output. The gcc build measured 16.7 cycles per IP against 21.5 for clang, so use gcc *(`make CC=gcc` if your `cc` is clang)*.

## Usage

```
clcg TARGETS [options]
```

| Argument           | Default    | Description                                                                                                   |
|--------------------|------------|---------------------------------------------------------------------------------------------------------------|
| `TARGETS`          | *required* | Comma-separated IPs, CIDRs, IP-IP ranges and files *(one entry per line)*, IPv4 and IPv6 mixed, `-` for stdin |
| `--shard-num N`    | 1          | Shard number *(1-based)*                                                                                      |
| `--total-shards N` | 1          | Total number of shards                                                                                        |
| `--seed N`         | random     | Seed from 0 to 2^64-1 *(a random seed is printed to stderr)*                                                  |
| `--state FILE`     | none       | Resume from a state file                                                                                      |
| `--state STEP`     | none       | Resume from a raw step number *(requires `--seed`)*                                                           |
| `--skip N`         | none       | Skip the first N IPs of the shard *(see below)*                                                               |
| `--state-file F`   | `~/.clcg/` | Where to write the state file                                                                                 |
| `--state-interval` | 100000     | Write the state file every N steps                                                                            |
| `--no-state`       | off        | Do not write a state file                                                                                     |
| `--exclude LIST`   | none       | Comma-separated IPs, CIDRs, IP-IP ranges, files *(one entry per line)*, or `private`                          |
| `-p, --ports LIST` | none       | Pair every IP with these ports, e.g. `22,80,1024-3000,U:53,S:38412` *(0 to 65535)*                            |
| `--rounds N`       | 4          | Feistel rounds that shuffle the pairs *(1 to 64, needs `--ports`)*                                            |

Only IP addresses are written to stdout, or `IP:port` and `[IPv6]:port` lines with `--ports`. UDP and SCTP lines end in `/udp` and `/sctp`, so `1.2.3.4:53/udp`, while TCP lines have no suffix. Errors go to stderr as one line, except an unknown option, which also prints the usage.

| Exit code | Meaning                                                                |
|-----------|------------------------------------------------------------------------|
| 0         | Finished, or the reader closed the pipe                                |
| 1         | I/O error on the state file, a target or exclude file, stdin or stdout |
| 2         | Bad arguments, targets, exclude list, ports or state file              |
| 130       | Interrupted by SIGINT or SIGTERM                                       |

### Examples

```
# Whole range, random seed
clcg 192.168.0.0/16

# Reproducible order
clcg 192.168.0.0/16 --seed 12345

# Machine 2 of 4. Every machine must use the same seed.
clcg 0.0.0.0/0 --seed 12345 --total-shards 4 --shard-num 2

# Skip private & reserved ranges plus a blocklist file
clcg 0.0.0.0/0 --exclude private,blocklist.txt

# Several ranges and a file of targets, IPv4 and IPv6, shuffled together
clcg 10.0.0.0/8,192.168.1.0/24,2001:db8::/120,targets.txt

# A dash range, and targets piped in from another tool
clcg 10.0.0.100-10.0.0.200
some-tool | clcg - -p 443

# Every IP:port pair for ports 22, 80 and 8000 to 8100
clcg 10.0.0.0/16 -p 22,80,8000-8100

# TCP 80 and 443, UDP 53 and 161, SCTP 38412
clcg 10.0.0.0/16 -p 80,443,U:53,U:161,S:38412

# More Feistel rounds for a stronger shuffle
clcg 0.0.0.0/0 -p 443 --rounds 8 --exclude private

# Resume. Progress keeps going to the same file.
clcg 0.0.0.0/0 --state ~/.clcg/clcg_12345_0.0.0.0_0_1_1_cbf29ce484222325.state

# Resume right after the 48,213,770th IP, because that is how many the scanner finished
clcg 0.0.0.0/0 --state ~/.clcg/clcg_12345_0.0.0.0_0_1_1_cbf29ce484222325.state --skip 48213770
```

Target and exclude files take one IP, CIDR or `IP-IP` range per line *(both ends included)*. Blank lines and `#` comments are ignored. `-` as a target reads the same format from stdin, once. Since a list starting with `-` looks like an option, write `-` alone, later in the list *(`10.0.0.0/8,-`)*, or after `--`. Targets may overlap, and an address covered twice still comes out once. Exclusions only apply to their own family, so one blocklist can hold both IPv4 and IPv6. A target CIDR must not have host bits set *(`10.0.0.1/24` is refused)*, while an exclude CIDR may.

Each item of `--ports` is a port or a range, tagged `T:`, `U:` or `S:` for TCP, UDP or SCTP. An untagged item is TCP, and a tag only applies to its own item, so `U:53,161` is UDP 53 and TCP 161.

## How it works

1. The targets minus their exclusions are numbered `0 .. N-1`, IPv4 first, then IPv6. A sorted table of exclusions maps an index back to its address *(see target lists below)*.
2. A linear congruential generator `x = a*x + c mod 2^k` walks every value below `2^k`, the smallest power of 2 at or above `N`, exactly once. `a = 1664525` and any odd `c` satisfy the Hull-Dobell theorem for every power of 2. `c` is derived from the seed with splitmix64, so each seed walks its own cycle instead of entering one shared cycle at a different point.
3. Each value passes through a mixer: three xorshifts and two odd multiplies, modulo `2^k`. Every one of those steps is reversible, so the output is still an exact permutation. A bare power-of-2 LCG has a strong pattern in its low bits: the last bit alternates every step, so IPs go even, odd, even, odd, and with 2 shards one shard gets only even IPs. After mixing, the next IP has the same parity about half the time and each shard gets 50% even IPs.
4. Values at or above `N` are skipped. That is never more than half of the steps, and zero for a plain CIDR.
5. Shard `i` of `T` takes steps `i+1, i+1+T, i+1+2T ...`, which together cover the cycle once with no gaps or overlaps. Jumps compose in `O(log n)`, so resuming at any step is instant.

### Target lists

Each family's targets are merged and sorted, then treated as one span from the lowest target to the highest, with the gaps between targets added to the exclusions. That turns a list of any length into the single range and exclusion table step 1 already handles, so a list costs the same per IP as the same addresses written as one CIDR minus exclusions. 5,000 scattered /20s measured 52.8 cycles per IP as a target file and 56.0 as `0.0.0.0/4` minus their complement, against about 16 for a plain CIDR. The IPv4 span takes indexes `0 .. N4-1` and the IPv6 span the rest. Overlaps and order do not matter: `10.0.0.0/24,10.0.1.0/24` gives exactly the same output as `10.0.0.0/23`.

### Ports

With `--ports` the targets are every valid IP times every port, so pair `t` is IP index `t mod N` on port slot `t / N`. Ports are deduplicated and sorted by protocol then number, so `80,22` and `22,80,22` give the same order. TCP 53 and UDP 53 are two different slots. The LCG is replaced by a Feistel network:

1. The domain is the smallest power of 2 at or above the pair count, split into a high and a low half that can differ by one bit, so any size works without a `mod` in every round. Values at or above the pair count are skipped, never more than half of the steps.
2. Each round XORs one half with a keyed function of the other and swaps them. That is reversible no matter what the function is, so the output is an exact permutation. The function is a splitmix64 finalizer *(two multiplies, three XORs)* with one key per round derived from the seed.
3. Shard `i` of `T` feeds in `i-1, i-1+T, i-1+2T ...` directly, so resuming at any step costs nothing.

Avalanche tests *(flip one input bit, count changed output bits)* show 2 rounds are visibly biased and 4 have no measurable bias, which is why 4 is the default. More rounds cost speed without a measurable gain, but are there if you want a stronger shuffle. A function with one multiply was 25% faster per round but needed 6 to 8 rounds for the same result on small ranges, so it lost overall. masscan's BlackRock does the same job with 14 rounds of S-box lookups and modulo, but its code is AGPL, so this one is written from scratch.

### State and resume

The state file is one line:

```
clcg seed=12345 cidr=0.0.0.0/0 shard=1 total=4 excludes=cbf29ce484222325 step=1830000000
```

`excludes` is a digest of the effective exclusions. For a target list it also covers each family's span, and with `--ports` the ports, protocols and rounds, so editing a target file is caught on resume too. Resuming checks the seed, targets, shard layout and digest against the command line, and refuses to start if any of them differ. A single CIDR without ports digests exactly as before, so older state files still resume.

The targets are stored as given, so a state file holds at most 4,000 characters of them and no whitespace. Put a longer list in a file, or use `--no-state`. A run reading targets from stdin resumes only when the same addresses are piped in again.

The output buffer is always written to stdout before a step is recorded, so a resumed run never skips IPs that were not delivered. After a hard kill it repeats at most one interval. SIGINT and SIGTERM flush the output and record the exact position before exiting. If the reader has stopped reading and the pipe is full, a signal still ends the run, and the state file keeps its last checkpoint. The file is overwritten in place and never truncated first, so it is never left empty.

One limit applies to every program writing to a pipe: once data is written into the pipe, the writer cannot know whether the reader consumed it. If the reader exits early, the IPs sitting unread in the pipe *(at most 64KB, about 5,000 IPs)* are lost to a run resumed from the state file alone.

### Resuming with zero loss

There are two ways to make sure no IP is ever missed, and both need the reader to say how far it got:

- **`--skip N`**: the reader counts the lines it has fully handled, across every run of the shard, and passes that count back. Since the order is fixed by the seed, line N is always the same IP, so the resumed run starts exactly after it. The count is taken from the start of the shard, so it stays correct even when the state file is ahead of the reader. Skipping costs about 8 cycles per step, roughly 11 seconds for a whole /0 shard. Pass `--state` too to keep the seed, shard and exclude checks.
- **The library**: the program pulls IPs itself and saves `clcg_step()` after handling each one, so nothing is ever in flight.

## Library

`clcg.h` is the whole API. Link with `-lclcg` *(shared, `libclcg.so.1`)* or `libclcg.a` *(static)*. The `.1` is the ABI version, so a program built against it will not load a future incompatible version.

```c
#include <stdio.h>
#include "clcg.h"

int main(void) {
	struct clcg_config cfg = { .cidr = "8.0.0.0/6", .seed = 12345, .has_seed = 1, .exclude = "private" };
	char err[256], text[46];
	struct clcg_ip ip;

	clcg *g = clcg_new(&cfg, err, sizeof(err));

	if (!g) {
		fprintf(stderr, "%s\n", err);
		return 1;
	}

	while (clcg_next(g, &ip)) {
		clcg_format(&ip, text);  /* or use ip.addr directly, in network byte order */
		puts(text);

		/* Save clcg_step(g) once this IP is fully handled. Passing it back as
		 * cfg.step later resumes right after it. */
	}

	clcg_free(g);
	return 0;
}
```

| Function           | Purpose                                                                                         |
|--------------------|-------------------------------------------------------------------------------------------------|
| `clcg_new`         | Create a generator from a config. NULL and a message on error.                                  |
| `clcg_new_ports`   | Same, pairing every IP with a port list, with a number of Feistel rounds                        |
| `clcg_next`        | Next IP as raw bytes. 0 once the shard is finished.                                             |
| `clcg_next_port`   | Next IP, port and protocol *(`CLCG_TCP`, `CLCG_UDP` or `CLCG_SCTP`)*. Both are 0 without ports. |
| `clcg_next_batch`  | Many raw IPs per call, over twice as fast as one at a time                                      |
| `clcg_fill`        | Fill a buffer with newline-terminated text, the fastest way to produce text                     |
| `clcg_skip`        | Skip N IPs without producing them                                                               |
| `clcg_format`      | Raw IP to text                                                                                  |
| `clcg_step`        | Current position, for `cfg.step` on resume                                                      |
| `clcg_steps`       | Total steps in this shard                                                                       |
| `clcg_count`       | IPs *(or IP:port pairs)* in the whole range after exclusions                                    |
| `clcg_seed`        | Seed in use, including a randomly chosen one                                                    |
| `clcg_fingerprint` | Digest of the effective exclusions, target spans and ports                                      |
| `clcg_free`        | Free a generator                                                                                |

The config takes the same target, shard, seed and exclude syntax as the command, with the target list in `cfg.cidr`. For a port generator, `clcg_fill` writes `IP:port` lines, while `clcg_next` and `clcg_next_batch` return the IPs without their ports. Generators share nothing, so each thread can run its own.

### Examples

Complete programs in `examples/`, built with `make examples`. `make test` runs every one except `ping` and checks its output.

| Program   | Shows                                                                               |
|-----------|-------------------------------------------------------------------------------------|
| `basic`   | Pulling IPs one at a time with `clcg_next` and printing them                        |
| `batch`   | Pulling 1024 raw IPs per call with `clcg_next_batch`, the fast way to get addresses |
| `resume`  | Saving `clcg_step()` after each IP is handled, so a crash and restart loses nothing |
| `threads` | One generator per thread, each on its own shard, covering one range together        |
| `ping`    | A ping sweep: one ICMP echo per IP in random order, printing the ones that reply    |

```
examples/basic 1.0.0.0/24 12345
examples/threads 1.0.0.0/16 12345 8
sudo examples/ping 1.0.0.0/24 500   # 500 packets per second
```

`ping` sends real packets, so only point it at networks you are allowed to probe. It needs root, or `sudo setcap cap_net_raw+ep examples/ping` once. The tests only run it against loopback.

## Performance

Measured on a Ryzen 5 PRO 2400GE, one core, `-O2`:

| Workload                         | Cycles per IP |
|----------------------------------|---------------|
| No exclusions                    | ~17           |
| `--exclude private` on 0.0.0.0/4 | ~31           |
| 5,000 exclude ranges             | ~38           |
| 100,000 exclude ranges           | ~190          |
| Library `clcg_next`, raw bytes   | ~26           |
| Library `clcg_next_batch`, 1024  | ~11           |

That is roughly 150M IPs per second to `/dev/null` at full clock. Through a pipe the pipe itself is the limit, about 125M IPs per second on this machine. pylcg does about 1.7M per second.

With `--ports`, 1.0.0.0/8 on 16 ports to `/dev/null`:

| Rounds | Pairs per second |
|--------|------------------|
| 1      | 77M              |
| 2      | 47M              |
| 4      | 36M              |
| 8      | 24M              |
| 14     | 12M              |

About 15% of the time at 4 rounds is the division that splits a pair into IP and port.

Each design choice was measured. The formatting, output and 128-bit rows come from the programs in `bench/` *(`make bench`)*. The BlackRock row used a port of masscan's code that is not included, since masscan is AGPL. The rest compared builds of clcg itself by CPU cycles per IP:

| Choice                                         | Result                              | Decision                     |
|------------------------------------------------|-------------------------------------|------------------------------|
| LCG, LCG + mixer, masscan's BlackRock cipher   | 1.37, 1.90, 255 ns per index        | LCG + mixer                  |
| `snprintf` vs precomputed octet table          | 289 vs 3.8 ns per IP                | Octet table                  |
| `printf`, `fwrite` per line, 64KB `write()`    | 190, 24 to 29, 3.9 ns per IP        | 64KB buffer + `write()`      |
| Fortified `memcpy` *(Ubuntu default)*          | 18.5 vs 3.9 ns per IP               | `__builtin_memcpy`           |
| Pipe size 64KB, 256KB, 1MB                     | All about 125M IPs per second       | Default pipe                 |
| 64-bit vs 128-bit arithmetic for IPv4          | 2.1 vs 10.0 ns per index            | 64-bit path for IPv4         |
| Branching vs branchless binary search, 5,000   | 4.7 vs 0.2 mispredicts per IP       | Replaced by the bucket table |
| Binary search vs bucket table, 5,000 / 100,000 | 114 vs 49, 443 vs 259 cycles per IP | Bucket table                 |
| Split vs interleaved 32-bit slots, 100,000     | 293 vs 211 cycles per IP            | Interleaved 32-bit           |
| State interval 1K, 10K, 100K, 1M               | 58, 24.5, 20.7, 20.9 cycles per IP  | 100,000                      |
| `-O2`, `-O3`, `-march=native`                  | Within noise                        | `-O2`                        |

## Limits

- At most 2^127 addresses in total, so `::/0` is refused and `::/1` is the largest single CIDR. With `--ports`, IPs times ports may not exceed 2^127 either. Large IPv6 ranges are accepted but can never finish.
- IPv6 uses `inet_ntop` and 128-bit math, so it is much slower than IPv4.
- The output order is not cryptographically secure. Anyone who knows the seed can compute it.

---

###### Mirrors: [SuperNETs](https://git.supernets.org/acidvegas/) • [GitHub](https://github.com/acidvegas/) • [GitLab](https://gitlab.com/acidvegas/) • [Codeberg](https://codeberg.org/acidvegas/)
