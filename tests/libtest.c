/*
 * clcg - Linear Congruential Generator for IP Sharding - Developed by acidvegas in C (https://github.com/acidvegas/clcg)
 * tests/libtest.c
 *
 * Library API tests. The CLI tests in test.py check the output itself against Python's
 * ipaddress module; these check that every way of driving the library agrees with it.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "clcg.h"

static int fails;

#define CHECK(cond, ...) do { if (!(cond)) { fails++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); putchar('\n'); } } while (0)

/* Every IP of a config via clcg_next, as one newline-joined string */
static char *all_next(const struct clcg_config *cfg, size_t *count) {
	char err[256], line[64];
	clcg *g = clcg_new(cfg, err, sizeof(err));
	size_t cap = 1 << 20, len = 0;
	char *out = malloc(cap);
	struct clcg_ip ip;

	*count = 0;

	while (clcg_next(g, &ip)) {
		size_t n = clcg_format(&ip, line);

		if (len + n + 2 > cap)
			out = realloc(out, cap *= 2);

		memcpy(out + len, line, n);
		len += n;
		out[len++] = '\n';
		(*count)++;
	}

	out[len] = 0;
	CHECK(clcg_step(g) == clcg_steps(g), "clcg_next stopped before the last step");
	clcg_free(g);
	return out;
}

/* Every IP via clcg_fill with a given buffer size and step limit */
static char *all_fill(const struct clcg_config *cfg, size_t bufsize, clcg_u128 max_steps) {
	char err[256], *buf = malloc(bufsize);
	clcg *g = clcg_new(cfg, err, sizeof(err));
	size_t cap = 1 << 20, len = 0;
	char *out = malloc(cap);

	while (clcg_step(g) < clcg_steps(g)) {
		clcg_u128 before = clcg_step(g);
		size_t n = clcg_fill(g, buf, bufsize, max_steps);

		CHECK(clcg_step(g) - before <= max_steps, "fill took more steps than allowed");
		CHECK(clcg_step(g) > before, "fill made no progress");

		if (len + n + 1 > cap)
			out = realloc(out, cap = (cap + n) * 2);

		memcpy(out + len, buf, n);
		len += n;
	}

	out[len] = 0;
	CHECK(clcg_fill(g, buf, bufsize, max_steps) == 0, "fill after the end returned data");
	clcg_free(g);
	free(buf);
	return out;
}

static void test_next_matches_fill(void) {
	const char *cidrs[]    = { "10.0.0.0/22", "10.0.0.7/32", "2001:db8::/118", "255.255.255.0/24", "10.0.0.0/24,10.0.2.0/25,10.0.1.7", "10.0.0.0/25,2001:db8::/121,192.168.0.0/30", "10.0.0.200-10.0.1.10,2001:db8::fff0-2001:db8::1:f" };
	const char *excludes[] = { NULL, "10.0.1.0/24,10.0.2.9", NULL, "255.255.255.255,255.255.255.0/30", "10.0.0.0/28,10.0.2.64/26", "10.0.0.5,2001:db8::10/124", "10.0.0.255-10.0.1.1,2001:db8::1:0" };

	for (int c = 0; c < 7; c++) {
		for (uint64_t total = 1; total <= 3; total++) {
			for (uint64_t shard = 1; shard <= total; shard++) {
				struct clcg_config cfg = { .cidr = cidrs[c], .shard = shard, .total = total, .seed = 42, .has_seed = 1, .exclude = excludes[c] };
				size_t count;
				char *ref = all_next(&cfg, &count);

				/* clcg_next_batch, in batch sizes that do and do not divide the count */
				size_t batches[] = { 1, 3, 64, 5000 };

				for (int bi = 0; bi < 4; bi++) {
					char err[256], line[64];
					clcg *g = clcg_new(&cfg, err, sizeof(err));
					struct clcg_ip *ips = malloc(batches[bi] * sizeof(*ips));
					size_t cap = strlen(ref) + 64, len = 0, got;
					char *out = malloc(cap);

					while ((got = clcg_next_batch(g, ips, batches[bi])) > 0) {
						for (size_t i = 0; i < got; i++) {
							size_t n = clcg_format(&ips[i], line);
							CHECK(len + n + 1 < cap, "batch produced too much");
							if (len + n + 1 >= cap) break;
							memcpy(out + len, line, n);
							len += n;
							out[len++] = '\n';
						}
					}

					out[len] = 0;
					CHECK(!strcmp(ref, out), "%s %llu/%llu: batch %zu differs from next", cidrs[c], (unsigned long long)shard, (unsigned long long)total, batches[bi]);
					CHECK(clcg_step(g) == clcg_steps(g), "batch stopped before the last step");
					free(ips);
					free(out);
					clcg_free(g);
				}

				size_t sizes[] = { 64, 100, 4096, 1 << 16 };
				clcg_u128 limits[] = { 1, 7, 1000, (clcg_u128)-1 };

				for (int s = 0; s < 4; s++) {
					for (int l = 0; l < 4; l++) {
						char *got = all_fill(&cfg, sizes[s], limits[l]);
						CHECK(!strcmp(ref, got), "%s %llu/%llu: fill(buf %zu) differs from next", cidrs[c], (unsigned long long)shard, (unsigned long long)total, sizes[s]);
						free(got);
					}
				}

				free(ref);
			}
		}
	}

	printf("next matches next_batch and fill across batch sizes, buffer sizes and step limits\n");
}

static void resume_and_skip(struct clcg_config cfg) {
	char err[256], a[64], b[64];
	struct clcg_ip ip, ip2;
	size_t count;
	char *full = all_next(&cfg, &count);

	for (size_t taken = 0; taken <= count; taken++) {
		/* Resume from the step after `taken` IPs: the next IP must be number `taken` */
		clcg *g = clcg_new(&cfg, err, sizeof(err));

		for (size_t i = 0; i < taken; i++)
			clcg_next(g, &ip);

		struct clcg_config r = cfg;
		r.step = clcg_step(g);
		clcg *h = clcg_new(&r, err, sizeof(err));

		/* The same via skip */
		clcg *s = clcg_new(&cfg, err, sizeof(err));
		CHECK(clcg_skip(s, taken) == taken, "skip %zu skipped fewer", taken);

		int more_g = clcg_next(g, &ip), more_h = clcg_next(h, &ip2);
		CHECK(more_g == more_h, "resume at %zu: one stream ended early", taken);

		if (more_g && more_h) {
			clcg_format(&ip, a);
			clcg_format(&ip2, b);
			CHECK(!strcmp(a, b), "resume at %zu: %s vs %s", taken, a, b);

			CHECK(clcg_next(s, &ip2), "skip %zu ended early", taken);
			clcg_format(&ip2, b);
			CHECK(!strcmp(a, b), "skip %zu: %s vs %s", taken, a, b);
		}

		clcg_free(g);
		clcg_free(h);
		clcg_free(s);
	}

	clcg *g = clcg_new(&cfg, err, sizeof(err));
	CHECK(clcg_skip(g, count + 50) == count, "skip past the end did not return the IP count");
	CHECK(!clcg_next(g, &ip), "IPs left after skipping past the end");
	clcg_free(g);

	free(full);
}

static void test_resume_and_skip(void) {
	resume_and_skip((struct clcg_config){ .cidr = "10.0.0.0/24", .total = 2, .shard = 2, .seed = 7, .has_seed = 1, .exclude = "10.0.0.0/28" });
	resume_and_skip((struct clcg_config){ .cidr = "10.0.0.0/26,2001:db8::/122,10.0.1.0/28", .total = 2, .shard = 1, .seed = 8, .has_seed = 1, .exclude = "10.0.0.8/29,2001:db8::3" });

	printf("resume and skip land on the right IP at every position\n");
}

static void test_shards_partition(void) {
	char err[256];
	struct clcg_ip ip;
	static unsigned char seen[4096];

	for (uint64_t total = 1; total <= 9; total++) {
		memset(seen, 0, sizeof(seen));
		size_t n = 0;

		for (uint64_t shard = 1; shard <= total; shard++) {
			struct clcg_config cfg = { .cidr = "10.0.0.0/20", .shard = shard, .total = total, .seed = 3, .has_seed = 1 };
			clcg *g = clcg_new(&cfg, err, sizeof(err));

			while (clcg_next(g, &ip)) {
				unsigned idx = (unsigned)(ip.addr[2] & 15) << 8 | ip.addr[3];
				CHECK(!seen[idx], "shards %llu: duplicate", (unsigned long long)total);
				seen[idx] = 1;
				n++;
			}

			clcg_free(g);
		}

		CHECK(n == 4096, "shards %llu: covered %zu of 4096", (unsigned long long)total, n);
	}

	printf("shards partition the range exactly\n");
}

static void test_errors_and_getters(void) {
	char err[256];
	struct clcg_config cfg = { .cidr = "10.0.0.1/24" };

	CHECK(!clcg_new(&cfg, err, sizeof(err)) && errno == EINVAL && strstr(err, "Invalid target"), "host bits accepted: %s", err);

	cfg.cidr = "::/0";
	CHECK(!clcg_new(&cfg, err, sizeof(err)) && errno == EINVAL, "::/0 accepted");

	cfg.cidr    = "10.0.0.0/24";
	cfg.exclude = "nope";
	CHECK(!clcg_new(&cfg, err, sizeof(err)) && errno == EINVAL && strstr(err, "nope"), "bad exclude accepted: %s", err);

	cfg.exclude = "private,10.0.0.0/33";
	CHECK(!clcg_new(&cfg, err, sizeof(err)) && errno == EINVAL, "bad prefix accepted");

	cfg.exclude = NULL;
	cfg.shard   = 3;
	cfg.total   = 2;
	CHECK(!clcg_new(&cfg, err, sizeof(err)) && errno == EINVAL, "shard > total accepted");

	/* Random seeds differ, and the chosen seed is reported */
	struct clcg_config r = { .cidr = "10.0.0.0/24" };
	clcg *a = clcg_new(&r, err, sizeof(err)), *b = clcg_new(&r, err, sizeof(err));
	CHECK(a && b && clcg_seed(a) != clcg_seed(b), "two random seeds were equal");
	CHECK(clcg_count(a) == 256 && clcg_steps(a) == 256 && strlen(clcg_fingerprint(a)) == 16, "getters");
	clcg_free(a);
	clcg_free(b);

	/* A config resumed past the end is simply finished */
	struct clcg_config end = { .cidr = "10.0.0.0/24", .seed = 1, .has_seed = 1, .step = 999 };
	clcg *g = clcg_new(&end, err, sizeof(err));
	struct clcg_ip ip;
	CHECK(g && !clcg_next(g, &ip) && clcg_step(g) == clcg_steps(g), "resume past the end produced IPs");
	clcg_free(g);

	/* Formatting */
	struct clcg_ip v4 = { .family = 4, .addr = { 192, 168, 0, 255 } }, v6 = { .family = 6, .addr = { 0x20, 0x01, 0x0d, 0xb8, [15] = 1 } };
	char buf[64];
	CHECK(clcg_format(&v4, buf) == 13 && !strcmp(buf, "192.168.0.255"), "format v4: %s", buf);
	CHECK(clcg_format(&v6, buf) == 11 && !strcmp(buf, "2001:db8::1"), "format v6: %s", buf);

	/* "-" reads stdin once for both families */
	FILE *tmp = tmpfile();
	fputs("# list\n10.0.0.0/30\n2001:db8::1-2001:db8::3\n", tmp);
	rewind(tmp);

	int saved = dup(0);
	dup2(fileno(tmp), 0);

	struct clcg_config piped = { .cidr = "192.168.0.1,-", .seed = 1, .has_seed = 1 };
	clcg *p = clcg_new(&piped, err, sizeof(err));
	CHECK(p && clcg_count(p) == 8, "stdin targets: %s", p ? "wrong count" : err);
	clcg_free(p);

	dup2(saved, 0);
	close(saved);
	fclose(tmp);

	printf("errors, getters and formatting\n");
}

/* Up to limit steps of a port generator as IP:port text, via clcg_next_port or clcg_fill */
static char *ports_text(const struct clcg_config *cfg, const char *ports, unsigned rounds, int fill, clcg_u128 limit) {
	char err[256], line[100], buf[100];
	clcg *g = clcg_new_ports(cfg, ports, rounds, err, sizeof(err));
	size_t cap = 1 << 20, len = 0;
	char *out = malloc(cap);
	struct clcg_ip ip;
	uint16_t port;
	int proto;

	CHECK(g, "clcg_new_ports: %s", err);

	if (limit > clcg_steps(g))
		limit = clcg_steps(g);

	while (clcg_step(g) < limit) {
		size_t n;

		if (fill) {
			n = clcg_fill(g, buf, sizeof(buf), limit - clcg_step(g));
			memcpy(line, buf, n);
		} else {
			if (!clcg_next_port(g, &ip, &port, &proto))
				break;

			char text[46];
			const char *suffix = proto == CLCG_UDP ? "/udp" : proto == CLCG_SCTP ? "/sctp" : "";

			CHECK(proto == CLCG_TCP || proto == CLCG_UDP || proto == CLCG_SCTP, "bad protocol %d", proto);
			clcg_format(&ip, text);
			n = (size_t)snprintf(line, sizeof(line), ip.family == 6 ? "[%s]:%u%s\n" : "%s:%u%s\n", text, port, suffix);
		}

		if (len + n + 1 > cap)
			out = realloc(out, cap *= 2);

		memcpy(out + len, line, n);
		len += n;
	}

	out[len] = 0;
	clcg_free(g);
	return out;
}

static void test_ports(void) {
	struct clcg_config cfgs[] = {
		{ .cidr = "10.0.0.0/22", .exclude = "10.0.1.0/24,10.0.3.3", .seed = 4, .has_seed = 1, .shard = 2, .total = 3 },
		{ .cidr = "2001:db8::/118", .seed = 5, .has_seed = 1 },
		{ .cidr = "2001:db8::/63", .seed = 6, .has_seed = 1, .shard = 5, .total = 9 }, /* 2^65 pairs, the 128-bit Feistel */
		{ .cidr = "10.0.0.0/26,2001:db8::/122,10.9.0.0/30", .exclude = "10.0.0.7,2001:db8::/126", .seed = 7, .has_seed = 1, .shard = 2, .total = 2 },
	};

	for (size_t c = 0; c < sizeof(cfgs) / sizeof(*cfgs); c++) {
		char *a = ports_text(&cfgs[c], "1,7-9,U:7,S:65535,u:0", 6, 0, 20000), *b = ports_text(&cfgs[c], "u:0,9,S:65535,1,7-8,U:7", 6, 1, 20000);

		CHECK(*a && !strcmp(a, b), "%s: next_port and fill differ", cfgs[c].cidr);
		free(a);
		free(b);
	}

	/* clcg_next and clcg_next_batch give the same IPs without the port */
	char err[256];
	clcg *g = clcg_new_ports(&cfgs[0], "1,7-9", 6, err, sizeof(err)), *h = clcg_new_ports(&cfgs[0], "1,7-9", 6, err, sizeof(err));
	struct clcg_ip ip, batch[7];
	uint16_t port;
	int proto;
	size_t got;

	CHECK(clcg_count(g) == (1024 - 256 - 1) * 4, "count is not IPs times ports");

	while ((got = clcg_next_batch(g, batch, 7)))
		for (size_t i = 0; i < got; i++)
			CHECK(clcg_next_port(h, &ip, &port, NULL) && !memcmp(&ip, &batch[i], sizeof(ip)), "batch differs from next_port");

	CHECK(!clcg_next_port(h, &ip, &port, NULL), "next_port outlived batch");
	clcg_free(g);
	clcg_free(h);

	/* Without ports clcg_next_port matches clcg_next and reports port 0 */
	g = clcg_new(&cfgs[1], err, sizeof(err));
	h = clcg_new(&cfgs[1], err, sizeof(err));

	while (clcg_next(g, &batch[0]))
		CHECK(clcg_next_port(h, &ip, &port, &proto) && port == 0 && proto == 0 && !memcmp(&ip, &batch[0], sizeof(ip)), "next_port without ports differs");

	clcg_free(g);
	clcg_free(h);

	CHECK(!clcg_new_ports(&cfgs[0], "80,x", 0, err, sizeof(err)) && errno == EINVAL && strstr(err, "x"), "bad port accepted: %s", err);
	CHECK(!clcg_new_ports(&cfgs[0], "", 0, err, sizeof(err)) && errno == EINVAL, "empty port list accepted");
	CHECK(!clcg_new_ports(&cfgs[0], "X:80", 0, err, sizeof(err)) && errno == EINVAL && strstr(err, "X:80"), "bad protocol accepted: %s", err);
	CHECK(!clcg_new_ports(&cfgs[0], "U:", 0, err, sizeof(err)) && errno == EINVAL, "tag without a port accepted");

	/* Each protocol of the same port is its own pair, and untagged ports are TCP */
	struct clcg_config one = cfgs[0];
	one.shard = one.total = 1;
	g = clcg_new_ports(&one, "80,T:80,U:80,S:80", 0, err, sizeof(err));
	CHECK(g && clcg_count(g) == (1024 - 256 - 1) * 3, "protocols did not make 3 pairs per IP");

	int seen[3] = { 0 };

	while (clcg_next_port(g, &ip, &port, &proto))
		seen[proto == CLCG_TCP ? 0 : proto == CLCG_UDP ? 1 : 2] += port == 80;

	CHECK(seen[0] == 767 && seen[1] == 767 && seen[2] == 767, "protocol split %d/%d/%d", seen[0], seen[1], seen[2]);
	clcg_free(g);
	CHECK(!clcg_new_ports(&cfgs[0], "80", CLCG_ROUNDS_MAX + 1, err, sizeof(err)) && errno == EINVAL, "too many rounds accepted");

	struct clcg_config big = { .cidr = "::/1", .seed = 1, .has_seed = 1 };
	CHECK(!clcg_new_ports(&big, "1-2", 0, err, sizeof(err)) && errno == EINVAL, "2^128 pairs accepted");

	printf("ports: next_port, fill, batch, 128-bit domain, errors\n");
}

int main(void) {
	test_next_matches_fill();
	test_resume_and_skip();
	test_shards_partition();
	test_errors_and_getters();
	test_ports();

	printf(fails ? "FAILED (%d)\n" : "OK\n", fails);
	return fails != 0;
}
