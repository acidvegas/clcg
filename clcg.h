/*
 * clcg - Linear Congruential Generator for IP Sharding - Developed by acidvegas in C (https://github.com/acidvegas/clcg)
 * clcg.h
 */

#ifndef CLCG_H
#define CLCG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Steps and counts reach 2^127 for IPv6, so they need 128 bits. Targets without __int128
 * (32-bit CPUs) or built with -DCLCG_NO_IPV6 are IPv4 only, where 64 bits always fit. */
#if !defined(CLCG_NO_IPV6) && !defined(__SIZEOF_INT128__)
#define CLCG_NO_IPV6
#endif

#ifdef CLCG_NO_IPV6
typedef uint64_t clcg_u128;
#else
typedef unsigned __int128 clcg_u128;
#endif

typedef struct clcg clcg;

/* Most Feistel rounds clcg_new_ports() accepts */
#define CLCG_ROUNDS_MAX 64

/* Port protocols, as IANA protocol numbers */
#define CLCG_TCP  6
#define CLCG_UDP  17
#define CLCG_SCTP 132

struct clcg_config {
	const char *cidr;    /* Comma-separated target IPs, CIDRs, IP-IP ranges and files, IPv4 and IPv6
	                      * alike, with "-" reading stdin once. Required. */
	uint64_t    shard;   /* Shard number, 1-based (0 means 1) */
	uint64_t    total;   /* Total number of shards (0 means 1) */
	uint64_t    seed;    /* Seed, used when has_seed is set */
	int         has_seed; /* 0 picks a random seed, readable afterwards with clcg_seed() */
	const char *exclude; /* Comma-separated IPs, CIDRs, files, or "private" (NULL for none) */
	clcg_u128   step;    /* Step to resume from, as returned by clcg_step() (0 for the start) */
};

struct clcg_ip {
	int     family;      /* 4 or 6 */
	uint8_t addr[16];    /* Network byte order. IPv4 uses the first 4 bytes. */
};

/* Create a generator. Returns NULL on failure with a message in err, and errno set to
 * EINVAL for bad input or to the error from reading an exclude file. */
clcg *clcg_new(const struct clcg_config *cfg, char *err, size_t errlen);

/* Like clcg_new, but every IP is paired with every port in ports, a comma-separated list of
 * ports and ranges such as "22,80,1024-3000,U:53,S:38412" (each tagged T:, U: or S: for TCP,
 * UDP or SCTP, TCP when untagged), and the pairs are shuffled with a Feistel network of the
 * given rounds (0 means 4). clcg_count() and every step then count
 * pairs. Read them with clcg_next_port() or clcg_fill(), as clcg_next() and
 * clcg_next_batch() drop the port. */
clcg *clcg_new_ports(const struct clcg_config *cfg, const char *ports, unsigned rounds, char *err, size_t errlen);

void clcg_free(clcg *g);

/* Next IP of the shard. Returns 1, or 0 once the shard is finished. */
int clcg_next(clcg *g, struct clcg_ip *ip);

/* Next IP, port and protocol (CLCG_TCP, CLCG_UDP or CLCG_SCTP) of the shard. Returns 1, or 0
 * once the shard is finished. port and proto can be NULL, and are set to 0 by a generator
 * made without ports. */
int clcg_next_port(clcg *g, struct clcg_ip *ip, uint16_t *port, int *proto);

/* Up to n next IPs into ips, the fast way to get raw addresses. Returns how many, fewer
 * than n only at the end of the shard. clcg_step() then points right after the last one. */
size_t clcg_next_batch(clcg *g, struct clcg_ip *ips, size_t n);

/* Fill buf with newline-terminated IPs, or IP:port and [IPv6]:port with ports (UDP and SCTP
 * ports end in /udp and /sctp), stopping when the next line might not fit, after max_steps
 * steps, or at the end of the shard. Returns the bytes written, which can be 0 when the
 * steps taken held no IP, so loop until clcg_step() reaches clcg_steps() rather than until
 * it returns 0. The fastest way to produce text. */
size_t clcg_fill(clcg *g, char *buf, size_t cap, clcg_u128 max_steps);

/* Skip the next n IPs without producing them. Returns how many were skipped, fewer than
 * n only when the shard ends first. */
clcg_u128 clcg_skip(clcg *g, clcg_u128 n);

/* Write ip as text with a terminating NUL. Returns its length. buf needs 46 bytes. */
size_t clcg_format(const struct clcg_ip *ip, char *buf);

/* Current position. Passing it back as clcg_config.step resumes right after the last
 * IP returned, so save it only once that IP has been fully handled. */
clcg_u128 clcg_step(const clcg *g);

clcg_u128   clcg_steps(const clcg *g);       /* Steps in this shard; clcg_step() reaches it when done */
clcg_u128   clcg_count(const clcg *g);       /* IPs (or IP:port pairs) after exclusions, across all shards */
uint64_t    clcg_seed(const clcg *g);        /* Seed in use, including a randomly chosen one */
const char *clcg_fingerprint(const clcg *g); /* 16 hex digits identifying the effective exclusions, ports and rounds */

#ifdef __cplusplus
}
#endif

#endif
