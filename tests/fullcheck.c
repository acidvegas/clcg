/*
 * clcg - Linear Congruential Generator for IP Sharding - Developed by acidvegas in C (https://github.com/acidvegas/clcg)
 * tests/fullcheck.c
 *
 * Exhaustive check of the entire IPv4 space: every shard of 0.0.0.0/0 is generated and
 * each address is marked in a 512MB bitmap, so a single duplicate or missing address is
 * caught. Slow (minutes), so it is not part of `make test`. Run: make fullcheck
 *
 * usage: fullcheck TOTAL_SHARDS SEED [EXCLUDE]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "clcg.h"

int main(int argc, char **argv) {
	if (argc < 3) {
		fprintf(stderr, "usage: fullcheck TOTAL_SHARDS SEED [EXCLUDE]\n");
		return 2;
	}

	uint64_t total = strtoull(argv[1], NULL, 10), seed = strtoull(argv[2], NULL, 10);
	const char *exclude = argc > 3 ? argv[3] : NULL;
	uint64_t *bits = calloc((1ULL << 32) / 64, sizeof(uint64_t));
	struct clcg_ip ips[1024];
	unsigned long long seen = 0, dups = 0;
	char err[256];

	if (!bits) {
		fprintf(stderr, "need 512MB\n");
		return 1;
	}

	for (uint64_t shard = 1; shard <= total; shard++) {
		struct clcg_config cfg = { .cidr = "0.0.0.0/0", .shard = shard, .total = total, .seed = seed, .has_seed = 1, .exclude = exclude };
		clcg *g = clcg_new(&cfg, err, sizeof(err));
		size_t got;

		if (!g) {
			fprintf(stderr, "%s\n", err);
			return 1;
		}

		while ((got = clcg_next_batch(g, ips, 1024)) > 0) {
			for (size_t i = 0; i < got; i++) {
				uint32_t v = (uint32_t)ips[i].addr[0] << 24 | ips[i].addr[1] << 16 | ips[i].addr[2] << 8 | ips[i].addr[3];
				uint64_t m = 1ULL << (v & 63);

				dups += (bits[v >> 6] & m) != 0;
				bits[v >> 6] |= m;
				seen++;
			}
		}

		fprintf(stderr, "shard %llu/%llu done, %llu IPs so far\n", (unsigned long long)shard, (unsigned long long)total, seen);
		clcg_free(g);
	}

	/* No excluded address may appear. With the counts matching, that also means every
	 * valid address did. Checked for the "private" keyword, whose ranges are listed here. */
	static const char *private[] = { "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	                                 "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
	                                 "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32" };
	unsigned long long leaked = 0;

	for (size_t r = 0; exclude && !strcmp(exclude, "private") && r < sizeof(private) / sizeof(*private); r++) {
		unsigned a, b, c, d, len;
		sscanf(private[r], "%u.%u.%u.%u/%u", &a, &b, &c, &d, &len);
		uint64_t lo = (uint64_t)a << 24 | b << 16 | c << 8 | d, hi = lo + (1ULL << (32 - len)) - 1;

		for (uint64_t v = lo; v <= hi; v++)
			leaked += (bits[v >> 6] >> (v & 63)) & 1;
	}

	struct clcg_config cfg = { .cidr = "0.0.0.0/0", .seed = seed, .has_seed = 1, .exclude = exclude };
	clcg *g = clcg_new(&cfg, err, sizeof(err));
	unsigned long long expected = (unsigned long long)clcg_count(g), set = 0;

	for (uint64_t i = 0; i < (1ULL << 32) / 64; i++)
		set += (unsigned long long)__builtin_popcountll(bits[i]);

	clcg_free(g);

	int ok = !dups && !leaked && seen == expected && set == expected;

	printf("generated %llu, distinct %llu, duplicates %llu, excluded leaked %llu, expected %llu: %s\n", seen, set, dups, leaked, expected, ok ? "OK" : "FAIL");

	return !ok;
}
