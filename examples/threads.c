/*
 * clcg - Linear Congruential Generator for IP Sharding - Developed by acidvegas in C (https://github.com/acidvegas/clcg)
 * examples/threads.c
 *
 * Split one range across threads. Each thread gets its own generator on its own shard
 * with the same seed, so together they cover the range exactly once with no locking.
 * The same layout works across machines with the clcg command's --shard-num.
 *
 * usage: threads CIDR SEED THREADS
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include "clcg.h"

struct job {
	struct clcg_config cfg;
	unsigned long long count, sum;
	int                ok;
};

static void *work(void *arg) {
	struct job *job = arg;
	struct clcg_ip ips[1024];
	char err[256];
	size_t got;

	clcg *g = clcg_new(&job->cfg, err, sizeof(err));

	if (!g) {
		fprintf(stderr, "shard %llu: %s\n", (unsigned long long)job->cfg.shard, err);
		return NULL;
	}

	/* A real scanner would send to each address here. This counts them and sums the
	 * IPv4 addresses, a quick check that the shards together covered the range. */
	while ((got = clcg_next_batch(g, ips, 1024)) > 0) {
		for (size_t i = 0; i < got; i++) {
			job->count++;
			job->sum += (unsigned long long)ips[i].addr[0] << 24 | ips[i].addr[1] << 16 | ips[i].addr[2] << 8 | ips[i].addr[3];
		}
	}

	clcg_free(g);
	job->ok = 1;
	return NULL;
}

int main(int argc, char **argv) {
	if (argc != 4) {
		fprintf(stderr, "usage: threads CIDR SEED THREADS\n");
		return 2;
	}

	uint64_t seed = strtoull(argv[2], NULL, 10), n = strtoull(argv[3], NULL, 10);

	if (!n) {
		fprintf(stderr, "THREADS must be at least 1\n");
		return 2;
	}

	struct job *jobs = calloc(n, sizeof(*jobs));
	pthread_t *tids  = calloc(n, sizeof(*tids));

	for (uint64_t i = 0; i < n; i++) {
		jobs[i].cfg = (struct clcg_config){ .cidr = argv[1], .seed = seed, .has_seed = 1, .shard = i + 1, .total = n };
		pthread_create(&tids[i], NULL, work, &jobs[i]);
	}

	unsigned long long count = 0, sum = 0;
	int ok = 1;

	for (uint64_t i = 0; i < n; i++) {
		pthread_join(tids[i], NULL);
		printf("shard %llu: %llu IPs\n", (unsigned long long)i + 1, jobs[i].count);
		count += jobs[i].count;
		sum   += jobs[i].sum;
		ok    &= jobs[i].ok;
	}

	printf("total: %llu IPs, address sum %llu\n", count, sum);
	free(jobs);
	free(tids);
	return !ok;
}
