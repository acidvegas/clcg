/*
 * clcg - Linear Congruential Generator for IP Sharding - Developed by acidvegas in C (https://github.com/acidvegas/clcg)
 * examples/batch.c
 *
 * The fast way to get raw addresses: 1024 per call, over twice as fast as one at a time.
 * A scanner would copy ip.addr straight into a packet. This one prints them so the
 * output can be checked against the clcg command.
 *
 * usage: batch CIDR SEED
 */

#include <stdio.h>
#include <stdlib.h>

#include "clcg.h"

int main(int argc, char **argv) {
	if (argc != 3) {
		fprintf(stderr, "usage: batch CIDR SEED\n");
		return 2;
	}

	struct clcg_config cfg = { .cidr = argv[1], .seed = strtoull(argv[2], NULL, 10), .has_seed = 1 };
	static struct clcg_ip ips[1024];
	char err[256], text[46];
	size_t got;

	clcg *g = clcg_new(&cfg, err, sizeof(err));

	if (!g) {
		fprintf(stderr, "%s\n", err);
		return 1;
	}

	/* Fewer than 1024 only at the end of the shard, 0 once it is finished */
	while ((got = clcg_next_batch(g, ips, 1024)) > 0) {
		for (size_t i = 0; i < got; i++) {
			clcg_format(&ips[i], text);
			puts(text);
		}
	}

	clcg_free(g);
	return 0;
}
