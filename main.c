/*
 * clcg - Linear Congruential Generator for IP Sharding - Developed by acidvegas in C (https://github.com/acidvegas/clcg)
 * main.c
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "clcg.h"

typedef clcg_u128 u128;

/* Measured fastest for both /dev/null and pipes (see bench/) */
#define OUT_BUF (1 << 16)

#define STATE_MARKER "clcg"

#define VERSION "1.1.0"

static volatile sig_atomic_t stop_flag;

static char   out_buf[OUT_BUF];
static size_t out_len;

static int  state_fd = -1;
static char state_path[4096];

/* Everything a state line records besides the step */
static struct {
	const char *cidr, *fingerprint;
	uint64_t    seed, shard, total;
} run;


static void die(int code, const char *fmt, ...) __attribute__((format(printf, 2, 3), noreturn));

static void die(int code, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	fputs("clcg: ", stderr);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
	exit(code);
}

static void interrupted(void) {
	fputs("clcg: interrupted\n", stderr);
	exit(130);
}

static int parse_u128(const char *s, u128 *out) {
	u128 v = 0;

	if (!*s)
		return 0;

	for (; *s; s++) {
		if (*s < '0' || *s > '9')
			return 0;

		u128 next = v * 10 + (unsigned)(*s - '0');

		if ((next - (unsigned)(*s - '0')) / 10 != v)
			return 0;

		v = next;
	}

	*out = v;
	return 1;
}

static int parse_u64(const char *s, uint64_t *out) {
	u128 v;

	if (!parse_u128(s, &v) || v > UINT64_MAX)
		return 0;

	*out = (uint64_t)v;
	return 1;
}

static char *u128_str(u128 v, char *buf) {
	char tmp[40];
	int n = 0;

	do { tmp[n++] = '0' + (int)(v % 10); v /= 10; } while (v);

	for (int i = 0; i < n; i++)
		buf[i] = tmp[n - 1 - i];

	buf[n] = 0;
	return buf;
}

static int is_file(const char *path) {
	struct stat st;
	return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}


/* ---------------------------------------------------------------- output & state */

/* Push the buffer out of the process. A closed pipe ends the run quietly without
 * recording the undelivered IPs, so a resume picks up from the last recorded step. */
static void flush_out(void) {
	size_t off = 0;

	while (off < out_len) {
		ssize_t n = write(1, out_buf + off, out_len - off);

		if (n < 0) {
			/* A signal while blocked on a full pipe stops the run here. The position on
			 * disk is the last checkpoint, which never includes this buffer. */
			if (errno == EINTR) {
				if (stop_flag)
					interrupted();

				continue;
			}

			if (errno == EPIPE)
				exit(0);

			die(1, "%s: stdout", strerror(errno));
		}

		off += (size_t)n;

		/* A signal during a write that blocked partway returns a short count instead of
		 * EINTR, so check again before blocking on the rest */
		if (stop_flag && off < out_len)
			interrupted();
	}

	out_len = 0;
}

/* The longest target list a state line holds. Longer lists belong in a file. */
#define TARGETS_MAX 4000

static void state_write(u128 step) {
	char line[TARGETS_MAX + 256], num[40];
	int n;

	if (state_fd < 0)
		return;

	n = snprintf(line, sizeof(line), STATE_MARKER " seed=%llu cidr=%s shard=%llu total=%llu excludes=%s step=%s\n",
	             (unsigned long long)run.seed, run.cidr, (unsigned long long)run.shard, (unsigned long long)run.total,
	             run.fingerprint, u128_str(step, num));

	/* Overwrite in place rather than truncating first, so the file never sits empty */
	if (pwrite(state_fd, line, (size_t)n, 0) != n || ftruncate(state_fd, n) < 0)
		die(1, "%s: %s", strerror(errno), state_path);
}

static void mkdirs(const char *path) {
	char buf[4096];
	char *slash;

	snprintf(buf, sizeof(buf), "%s", path);
	slash = strrchr(buf, '/');

	if (!slash || slash == buf)
		return;

	*slash = 0;

	for (char *p = buf + 1; *p; p++) {
		if (*p == '/') {
			*p = 0;
			mkdir(buf, 0755);
			*p = '/';
		}
	}

	if (mkdir(buf, 0755) < 0 && errno != EEXIST)
		die(1, "%s: %s", strerror(errno), buf);
}

static void state_open(const char *path) {
	if (path) {
		snprintf(state_path, sizeof(state_path), "%s", path);
	} else {
		const char *home = getenv("HOME");
		char cidr[128];

		snprintf(cidr, sizeof(cidr), "%s", run.cidr);

		for (char *p = cidr; *p; p++)
			if (*p == '/' || *p == ':')
				*p = '_';

		snprintf(state_path, sizeof(state_path), "%s/.clcg/" STATE_MARKER "_%llu_%s_%llu_%llu_%s.state", home ? home : ".",
		         (unsigned long long)run.seed, cidr, (unsigned long long)run.shard, (unsigned long long)run.total, run.fingerprint);
	}

	mkdirs(state_path);

	/* No O_TRUNC, so a resumed file keeps its position until the first write replaces it */
	state_fd = open(state_path, O_RDWR | O_CREAT, 0644);

	if (state_fd < 0)
		die(1, "%s: %s", strerror(errno), state_path);
}

struct loaded { uint64_t seed, shard, total; u128 step; char cidr[TARGETS_MAX + 1], excludes[17]; };

static void state_load(const char *path, struct loaded *st) {
	FILE *f = fopen(path, "r");
	char line[TARGETS_MAX + 256], *save = NULL, *tok;
	int have = 0;

	if (!f)
		die(1, "%s: %s", strerror(errno), path);

	if (!fgets(line, sizeof(line), f))
		line[0] = 0;

	fclose(f);

	tok = strtok_r(line, " \n", &save);

	if (!tok || strcmp(tok, STATE_MARKER))
		die(2, "%s is not a clcg state file", path);

	while ((tok = strtok_r(NULL, " \n", &save))) {
		char *eq = strchr(tok, '=');

		if (!eq)
			continue;

		*eq++ = 0;

		if (!strcmp(tok, "seed") && parse_u64(eq, &st->seed))
			have |= 1;
		else if (!strcmp(tok, "cidr") && strlen(eq) < sizeof(st->cidr))
			strcpy(st->cidr, eq), have |= 2;
		else if (!strcmp(tok, "shard") && parse_u64(eq, &st->shard))
			have |= 4;
		else if (!strcmp(tok, "total") && parse_u64(eq, &st->total))
			have |= 8;
		else if (!strcmp(tok, "excludes") && strlen(eq) == 16)
			strcpy(st->excludes, eq), have |= 16;
		else if (!strcmp(tok, "step") && parse_u128(eq, &st->step))
			have |= 32;
	}

	if (have != 63)
		die(2, "%s is missing or has an invalid field", path);
}

static void on_signal(int sig) {
	(void)sig;
	stop_flag = 1;
}


/* ---------------------------------------------------------------- main */

static void usage(void) {
	fputs("usage: clcg TARGETS [options]\n"
	      "\n"
	      "Stream every IP in TARGETS exactly once, in a pseudo-random order. TARGETS is a\n"
	      "comma-separated list of IPs, CIDRs, IP-IP ranges and files, IPv4 and IPv6 alike,\n"
	      "with - reading targets from stdin.\n"
	      "\n"
	      "  --shard-num N        Shard number (1-based, default: 1)\n"
	      "  --total-shards N     Total number of shards (default: 1)\n"
	      "  --seed N             Random seed (default: random, printed to stderr)\n"
	      "  --state FILE|STEP    Resume from a state file, or from a raw step number (needs --seed)\n"
	      "  --skip N             Skip the first N IPs of the shard, e.g. the count a reader finished\n"
	      "  --state-file FILE    Where to write the state file (default: ~/.clcg/)\n"
	      "  --state-interval N   Write the state file every N steps (default: 100000)\n"
	      "  --no-state           Do not write a state file at all\n"
	      "  --exclude LIST       Comma-separated IPs, CIDRs, IP-IP ranges, files, or \"private\"\n"
	      "  -p, --ports LIST     Pair every IP with these ports, e.g. 22,80,1024-3000,U:53,S:38412\n"
	      "                       (0-65535, T: U: S: for TCP, UDP, SCTP, TCP when untagged)\n"
	      "  --rounds N           Feistel rounds that shuffle the pairs (default: 4, max: 64)\n"
	      "  -h, --help           Show this help\n"
	      "  --version            Show the version\n", stderr);
}

int main(int argc, char **argv) {
	static const struct option opts[] = {
		{ "shard-num",      required_argument, 0, 1 },
		{ "total-shards",   required_argument, 0, 2 },
		{ "seed",           required_argument, 0, 3 },
		{ "state",          required_argument, 0, 4 },
		{ "state-file",     required_argument, 0, 5 },
		{ "state-interval", required_argument, 0, 6 },
		{ "no-state",       no_argument,       0, 7 },
		{ "exclude",        required_argument, 0, 8 },
		{ "skip",           required_argument, 0, 9 },
		{ "ports",          required_argument, 0, 'p' },
		{ "rounds",         required_argument, 0, 10 },
		{ "help",           no_argument,       0, 'h' },
		{ "version",        no_argument,       0, 11 },
		{ 0, 0, 0, 0 },
	};

	struct clcg_config cfg = { .shard = 1, .total = 1 };
	uint64_t interval = 100000;
	int no_state = 0, have_skip = 0, opt;
	const char *state_arg = NULL, *state_file = NULL, *ports = NULL;
	uint64_t rounds = 0;
	u128 skip = 0;

	while ((opt = getopt_long(argc, argv, "hp:", opts, NULL)) != -1) {
		switch (opt) {
			case 1: if (!parse_u64(optarg, &cfg.shard) || !cfg.shard) die(2, "--shard-num must be at least 1"); break;
			case 2: if (!parse_u64(optarg, &cfg.total) || !cfg.total) die(2, "--total-shards must be at least 1"); break;
			case 3: if (!parse_u64(optarg, &cfg.seed)) die(2, "--seed must be a number from 0 to %llu", (unsigned long long)UINT64_MAX); cfg.has_seed = 1; break;
			case 4: state_arg = optarg; break;
			case 5: state_file = optarg; break;
			case 6: if (!parse_u64(optarg, &interval) || !interval) die(2, "--state-interval must be at least 1"); break;
			case 7: no_state = 1; break;
			case 8: cfg.exclude = optarg; break;
			case 9: if (!parse_u128(optarg, &skip)) die(2, "--skip must be a number"); have_skip = 1; break;
			case 'p': ports = optarg; break;
			case 10: if (!parse_u64(optarg, &rounds) || !rounds || rounds > CLCG_ROUNDS_MAX) die(2, "--rounds must be from 1 to %d", CLCG_ROUNDS_MAX); break;
			case 'h': usage(); return 0;
			case 11: puts("clcg " VERSION); return 0;
			default: usage(); return 2;
		}
	}

	if (optind != argc - 1) {
		usage();
		return 2;
	}

	if (rounds && !ports)
		die(2, "--rounds only applies with --ports");

	if (cfg.shard > cfg.total)
		die(2, "--shard-num %llu is greater than --total-shards %llu", (unsigned long long)cfg.shard, (unsigned long long)cfg.total);

	cfg.cidr = argv[optind];

	/* Resume */
	const char *expected = NULL;
	struct loaded st;

	if (state_arg) {
		if (is_file(state_arg)) {
			state_load(state_arg, &st);

			if (cfg.has_seed && cfg.seed != st.seed)
				die(2, "--seed %llu does not match the seed in %s (%llu)", (unsigned long long)cfg.seed, state_arg, (unsigned long long)st.seed);

			if (strcmp(cfg.cidr, st.cidr))
				die(2, "CIDR %s does not match the CIDR in %s (%s)", cfg.cidr, state_arg, st.cidr);

			if (cfg.shard != st.shard || cfg.total != st.total)
				die(2, "Shard %llu/%llu does not match the shard in %s (%llu/%llu)", (unsigned long long)cfg.shard, (unsigned long long)cfg.total, state_arg, (unsigned long long)st.shard, (unsigned long long)st.total);

			cfg.seed     = st.seed;
			cfg.has_seed = 1;
			cfg.step     = st.step;
			expected     = st.excludes;

			/* Keep advancing the file being resumed from unless told to write elsewhere */
			if (!state_file)
				state_file = state_arg;
		} else {
			if (have_skip)
				die(2, "--skip counts from the start of the shard, so it cannot be combined with a raw --state step");

			if (!parse_u128(state_arg, &cfg.step))
				die(2, "--state: '%s' is neither an existing state file nor a step number", state_arg);

			if (!cfg.has_seed)
				die(2, "When resuming from a raw step number, you must provide the --seed that was used originally");
		}
	}

	/* --skip counts IPs from the start of the shard, so it replaces any saved step */
	if (have_skip)
		cfg.step = 0;

	char err[512];
	clcg *g = ports ? clcg_new_ports(&cfg, ports, (unsigned)rounds, err, sizeof(err)) : clcg_new(&cfg, err, sizeof(err));

	if (!g)
		die(errno == EINVAL ? 2 : 1, "%s", err);

	if (expected && strcmp(clcg_fingerprint(g), expected))
		die(2, "--exclude, --ports or --rounds does not match the ones used when %s was written", state_arg);

	if (!cfg.has_seed)
		fprintf(stderr, "Using random seed: %llu\n", (unsigned long long)clcg_seed(g));

	run.cidr        = cfg.cidr;
	run.seed        = clcg_seed(g);
	run.shard       = cfg.shard;
	run.total       = cfg.total;
	run.fingerprint = clcg_fingerprint(g);

	if (have_skip)
		clcg_skip(g, skip);

	/* Nothing left to do. A --skip that reached the end still records it below, so the
	 * state file does not stay behind what the reader already finished. */
	if (clcg_step(g) >= clcg_steps(g) && !have_skip)
		return 0;

	/* Write the starting position straight away so the file is valid from the start */
	if (!no_state) {
		if (strlen(cfg.cidr) > TARGETS_MAX || strpbrk(cfg.cidr, " \t\r\n"))
			die(2, "A state file cannot hold a target list over %d characters or with whitespace, so use a file of targets or --no-state", TARGETS_MAX);

		state_open(state_file);
		state_write(clcg_step(g));
	}

	if (clcg_step(g) >= clcg_steps(g))
		return 0;

	/* No SA_RESTART, so a signal interrupts a write blocked on a stalled reader */
	struct sigaction sa_stop = { .sa_handler = on_signal };

	signal(SIGPIPE, SIG_IGN);
	sigaction(SIGINT, &sa_stop, NULL);
	sigaction(SIGTERM, &sa_stop, NULL);

	/* Each fill stops when the buffer is full or at the next checkpoint. The buffer is
	 * written before every state write, so the recorded step can never describe IPs
	 * that have not left the process. */
	u128 countdown = interval;

	while (clcg_step(g) < clcg_steps(g)) {
		u128 before = clcg_step(g);

		out_len = clcg_fill(g, out_buf, sizeof(out_buf), countdown);
		flush_out();

		countdown -= clcg_step(g) - before;

		if (!countdown) {
			countdown = interval;
			state_write(clcg_step(g));
		}

		if (stop_flag) {
			state_write(clcg_step(g));
			interrupted();
		}
	}

	state_write(clcg_step(g));
	clcg_free(g);

	if (state_fd >= 0)
		close(state_fd);

	return 0;
}
