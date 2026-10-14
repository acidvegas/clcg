/*
 * clcg - Linear Congruential Generator for IP Sharding - Developed by acidvegas in C (https://github.com/acidvegas/clcg)
 * examples/basic.c
 *
 * The simplest use: pull IPs one at a time and print them.
 *
 * usage: basic CIDR SEED
 */

#include <stdio.h>
#include <stdlib.h>

#include "clcg.h"

int main(int argc, char **argv) {
	if (argc != 3) {
		fprintf(stderr, "usage: basic CIDR SEED\n");
		return 2;
	}

	struct clcg_config cfg = { .cidr = argv[1], .seed = strtoull(argv[2], NULL, 10), .has_seed = 1 };
	char err[256], text[46];
	struct clcg_ip ip;

	clcg *g = clcg_new(&cfg, err, sizeof(err));

	if (!g) {
		fprintf(stderr, "%s\n", err);
		return 1;
	}

	/* ip.addr holds the address in network byte order, clcg_format turns it into text */
	while (clcg_next(g, &ip)) {
		clcg_format(&ip, text);
		puts(text);
	}

	clcg_free(g);
	return 0;
}
