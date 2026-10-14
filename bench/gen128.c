/* Cost of running the IPv4 generator on 128-bit integers instead of 64-bit */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
typedef unsigned __int128 u128;
static double now(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec + ts.tv_nsec / 1e9; }
static inline u128 mix(u128 x, unsigned s, u128 mask) {
	x ^= x >> s; x = (x * 0x9E3779B97F4A7C15ULL) & mask;
	x ^= x >> s; x = (x * 0xBF58476D1CE4E5B9ULL) & mask;
	x ^= x >> s; return x;
}
int main(int argc, char **argv) {
	if (argc != 2) { fprintf(stderr, "usage: gen128 BITS\n"); return 2; }
	unsigned k = atoi(argv[1]); u128 m = (u128)1 << k, mask = m - 1, x = 12345, c = 0x5bd1e995ULL | 1, sum = 0;
	double t = now();
	for (uint64_t i = 0; i < (uint64_t)m; i++) { x = (1664525 * x + c) & mask; sum += mix(x, (k + 1) / 2, mask); }
	t = now() - t;
	fprintf(stderr, "gen lcgmix128 2^%u: %.3fs  %.2f ns/idx (sum %llu)\n", k, t, t * 1e9 / (double)m, (unsigned long long)sum);
}
