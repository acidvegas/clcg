// clcg - Developed by acidvegas in C (https://github.com/acidvegas)
// bench/bench.c

/* clcg design benchmarks - each mode isolates one design choice */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#define LCG_A 1664525ULL

static double now(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* ---- index generators ---- */

static inline uint64_t mix(uint64_t x, unsigned s, uint64_t mask) {
	x ^= x >> s; x = (x * 0x9E3779B97F4A7C15ULL) & mask;
	x ^= x >> s; x = (x * 0xBF58476D1CE4E5B9ULL) & mask;
	x ^= x >> s;
	return x;
}

static void bench_gen(const char *mode, unsigned k) {
	uint64_t m = 1ULL << k, mask = m - 1, x = 12345 & mask, c = 0x5bd1e995ULL | 1, sum = 0;
	unsigned s = (k + 1) / 2;
	double t = now();

	if (!strcmp(mode, "lcg")) {
		for (uint64_t i = 0; i < m; i++) { x = (LCG_A * x + c) & mask; sum += x; }
	} else if (!strcmp(mode, "lcgmix")) {
		for (uint64_t i = 0; i < m; i++) { x = (LCG_A * x + c) & mask; sum += mix(x, s, mask); }
	}

	t = now() - t;
	fprintf(stderr, "gen %-10s 2^%u: %7.3fs  %6.2f ns/idx  %7.1f M/s  (sum %llu)\n", mode, k, t, t * 1e9 / m, m / t / 1e6, (unsigned long long)sum);
}

/* ---- formatting ---- */

static char oct_dot[256][4], oct_nl[256][4];
static unsigned char oct_len[256];

static void init_tables(void) {
	for (int i = 0; i < 256; i++) {
		int n = sprintf(oct_dot[i], "%d", i);
		memcpy(oct_nl[i], oct_dot[i], 4);
		oct_dot[i][n] = '.'; oct_nl[i][n] = '\n';
		oct_len[i] = n + 1;
	}
}

static inline char *fmt_table(char *p, uint32_t v) {
	__builtin_memcpy(p, oct_dot[v >> 24], 4);        p += oct_len[v >> 24];
	__builtin_memcpy(p, oct_dot[v >> 16 & 255], 4);  p += oct_len[v >> 16 & 255];
	__builtin_memcpy(p, oct_dot[v >> 8 & 255], 4);   p += oct_len[v >> 8 & 255];
	__builtin_memcpy(p, oct_nl[v & 255], 4);         p += oct_len[v & 255];
	return p;
}

static void bench_fmt(const char *mode, unsigned k) {
	static char buf[1 << 16];
	uint64_t m = 1ULL << k, total = 0;
	double t = now();
	char *p = buf;
	int use_snprintf = !strcmp(mode, "snprintf");

	for (uint64_t i = 0; i < m; i++) {
		uint32_t v = (uint32_t)(i * 2654435761u);
		if (p > buf + sizeof(buf) - 16) { total += p - buf; p = buf; }
		if (use_snprintf)
			p += snprintf(p, 16, "%u.%u.%u.%u\n", v >> 24, v >> 16 & 255, v >> 8 & 255, v & 255);
		else
			p = fmt_table(p, v);
	}

	total += p - buf;
	t = now() - t;
	fprintf(stderr, "fmt %-10s 2^%u: %7.3fs  %6.2f ns/ip  (%llu bytes)\n", mode, k, t, t * 1e9 / m, (unsigned long long)total);
}

/* ---- output ---- */

static void bench_out(const char *mode, unsigned k, size_t bufsize) {
	uint64_t m = 1ULL << k, mask = m - 1, x = 12345 & mask, c = 0x5bd1e995ULL | 1;
	unsigned s = (k + 1) / 2;
	double t = now();

	if (!strcmp(mode, "printf")) {
		for (uint64_t i = 0; i < m; i++) {
			x = (LCG_A * x + c) & mask;
			uint32_t v = (uint32_t)mix(x, s, mask);
			printf("%u.%u.%u.%u\n", v >> 24, v >> 16 & 255, v >> 8 & 255, v & 255);
		}
		fflush(stdout);
	} else if (!strcmp(mode, "fwrite")) {
		char line[16];
		setvbuf(stdout, NULL, _IOFBF, bufsize);
		for (uint64_t i = 0; i < m; i++) {
			x = (LCG_A * x + c) & mask;
			char *e = fmt_table(line, (uint32_t)mix(x, s, mask));
			fwrite(line, 1, e - line, stdout);
		}
		fflush(stdout);
	} else if (!strcmp(mode, "write")) {
		if (getenv("PIPESZ")) fcntl(1, F_SETPIPE_SZ, atoi(getenv("PIPESZ")));
		char *buf = malloc(bufsize), *p = buf, *lim = buf + bufsize - 16;
		for (uint64_t i = 0; i < m; i++) {
			x = (LCG_A * x + c) & mask;
			p = fmt_table(p, (uint32_t)mix(x, s, mask));
			if (p > lim) { if (write(1, buf, p - buf) < 0) exit(1); p = buf; }
		}
		if (write(1, buf, p - buf) < 0) exit(1);
		free(buf);
	}

	t = now() - t;
	fprintf(stderr, "out %-10s buf %7zu 2^%u: %7.3fs  %6.2f ns/ip  %7.1f M/s\n", mode, bufsize, k, t, t * 1e9 / m, m / t / 1e6);
}

int main(int argc, char **argv) {
	if (argc < 4) { fprintf(stderr, "usage: bench gen|fmt|out MODE BITS [BUFSIZE]\n"); return 2; }
	init_tables();
	unsigned k = atoi(argv[3]);
	if (!strcmp(argv[1], "gen")) bench_gen(argv[2], k);
	else if (!strcmp(argv[1], "fmt")) bench_fmt(argv[2], k);
	else bench_out(argv[2], k, argc > 4 ? strtoull(argv[4], NULL, 10) : 65536);
	return 0;
}
