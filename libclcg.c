/*
 * clcg - Linear Congruential Generator for IP Sharding - Developed by acidvegas in C (https://github.com/acidvegas/clcg)
 * libclcg.c
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "clcg.h"

/* newlib (ESP-IDF and other embedded targets) only has getline as __getline */
#if defined(__NEWLIB__) && !defined(getline)
#define getline __getline
#endif

typedef clcg_u128 u128;

/* Multiplier with a-1 divisible by 4. With any odd increment this satisfies Hull-Dobell
 * for every power-of-2 modulus, so the generator visits each state exactly once. */
#define LCG_A 1664525

/* Odd multipliers for the output mixer. Any odd value keeps it a bijection. */
#define MIX_M1 0x9E3779B97F4A7C15ULL
#define MIX_M2 0xBF58476D1CE4E5B9ULL

static const char *PRIVATE_RANGES[] = {
	"0.0.0.0/8",          /* Current network */
	"10.0.0.0/8",         /* Private network (Class A) */
	"100.64.0.0/10",      /* Carrier-grade NAT */
	"127.0.0.0/8",        /* Loopback */
	"169.254.0.0/16",     /* Link-local */
	"172.16.0.0/12",      /* Private network (Class B) */
	"192.0.0.0/24",       /* IETF Protocol Assignments */
	"192.0.2.0/24",       /* TEST-NET-1 */
	"192.88.99.0/24",     /* IPv6 to IPv4 relay */
	"192.168.0.0/16",     /* Private network (Class C) */
	"198.18.0.0/15",      /* Network benchmark tests */
	"198.51.100.0/24",    /* TEST-NET-2 */
	"203.0.113.0/24",     /* TEST-NET-3 */
	"224.0.0.0/4",        /* Multicast */
	"240.0.0.0/4",        /* Reserved for future use */
	"255.255.255.255/32", /* Broadcast */
};

struct range { u128 lo, hi; };

struct ranges { struct range *v; size_t n, cap; };

/* Offset and base side by side in 32 bits, so an IPv4 lookup touches one cache line
 * instead of two. Every value fits except the base after an exclusion that ends at
 * 255.255.255.255, and that slot's offset equals the valid count so no index selects it. */
struct slot { uint32_t off, base; };

/* ":65535/sctp\n" and its length, so a port is one fixed 16-byte copy */
struct ptxt { char s[15]; unsigned char n; };

/* Port protocols in tag order (T:, U:, S:), as IANA protocol numbers and line suffixes */
static const uint8_t     PROTO_NUM[3]  = { CLCG_TCP, CLCG_UDP, CLCG_SCTP };
static const char *const PROTO_NAME[3] = { "", "/udp", "/sctp" };

/* Each family's targets as one span from the lowest target to the highest, with the gaps
 * between targets added to the exclusions */
struct span { int has; struct range hull; struct ranges ex; u128 n; u128 *offsets, *bases; };

struct clcg {
	int      family;            /* 4 or 6 when every IP is one family, 0 when mixed */
	unsigned shift;             /* Mixer shift, (k + 1) / 2 for modulus 2^k */
	u128     mask;              /* Modulus - 1 */
	u128     cur, sa, sc;       /* LCG state and the one-shard-stride step */
	u128     step, steps;       /* Position in the shard and its length */
	u128     valid, n4;         /* IPs left after exclusions, of which the first n4 indexes are IPv4 */
	uint64_t seed;
	char     fingerprint[17];

	/* IPv4: slot 0 is a sentinel for "before every exclusion" and slot nex4 + 1 one that
	 * no index reaches, so a lookup needs no bounds checks */
	struct slot *slots;
	uint32_t    *bucket;
	unsigned     bshift;
	size_t       nex4;
	uint64_t     start4;

	/* IPv6: offsets[i] = valid IPs before exclusion i, bases[i] = first IP after it */
	u128  start6;
	u128 *offsets, *bases;
	size_t nex6;

	/* Ports: pair t is IP index t % valid with port t / valid, and a Feistel network over
	 * 2^(fhi + flo) shuffles the pairs instead of the LCG. cur is then the next input and
	 * sc the shard stride. */
	size_t       nports;
	uint16_t    *ports;
	uint8_t     *protos;        /* IANA protocol number of each port */
	struct ptxt *ptxt;
	u128         targets;       /* valid * nports */
	unsigned     rounds, fhi, flo;
	uint64_t     keys[CLCG_ROUNDS_MAX];
};

/* Precomputed "255." and "255\n" so each octet is one fixed 4-byte copy */
static char          oct_dot[256][4], oct_nl[256][4];
static unsigned char oct_len[256];


/* ---------------------------------------------------------------- helpers */

static clcg *fail(clcg *g, int code, char *err, size_t errlen, const char *fmt, ...) __attribute__((format(printf, 5, 6)));

static clcg *fail(clcg *g, int code, char *err, size_t errlen, const char *fmt, ...) {
	if (err && errlen) {
		va_list ap;
		va_start(ap, fmt);
		vsnprintf(err, errlen, fmt, ap);
		va_end(ap);
	}

	clcg_free(g);
	errno = code;
	return NULL;
}

static uint64_t splitmix64(uint64_t *state) {
	uint64_t z = (*state += 0x9E3779B97F4A7C15ULL);
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
	z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
	return z ^ (z >> 31);
}

static int parse_prefix(const char *s, unsigned *out) {
	unsigned v = 0;

	if (!*s)
		return 0;

	for (; *s; s++) {
		if (*s < '0' || *s > '9' || v > 128)
			return 0;

		v = v * 10 + (unsigned)(*s - '0');
	}

	*out = v;
	return 1;
}

/* Parse "IP" or "IP/prefix". strict rejects set host bits, as a target CIDR should. */
static int parse_cidr(const char *text, int strict, int *family, struct range *out) {
	char buf[128];
	unsigned char raw[16];
	char *slash;
	unsigned bits, prefix;
	u128 addr = 0;

	if (strlen(text) >= sizeof(buf))
		return 0;

	strcpy(buf, text);
	slash = strchr(buf, '/');

	if (slash)
		*slash = 0;

	if (inet_pton(AF_INET, buf, raw) == 1) {
		*family = 4;
		bits    = 32;
#ifndef CLCG_NO_IPV6
	} else if (inet_pton(AF_INET6, buf, raw) == 1) {
		*family = 6;
		bits    = 128;
#endif
	} else {
		return 0;
	}

	for (unsigned i = 0; i < bits / 8; i++)
		addr = addr << 8 | raw[i];

	prefix = bits;

	if (slash && (!parse_prefix(slash + 1, &prefix) || prefix > bits))
		return 0;

	u128 host = prefix == bits ? 0 : (prefix == 0 ? ~(u128)0 : (((u128)1 << (bits - prefix)) - 1));

	if (bits == 32)
		host &= 0xFFFFFFFF;

	if (strict && (addr & host))
		return 0;

	out->lo = addr & ~host;
	out->hi = out->lo | host;
	return 1;
}

/* Parse "IP-IP", both ends included and of one family */
static int parse_dash(const char *text, int *family, struct range *out) {
	char buf[128], *dash;
	struct range a, b;
	int fa, fb;

	if (strlen(text) >= sizeof(buf) || strchr(text, '/'))
		return 0;

	strcpy(buf, text);

	if (!(dash = strchr(buf, '-')))
		return 0;

	*dash = 0;

	if (!parse_cidr(buf, 1, &fa, &a) || !parse_cidr(dash + 1, 1, &fb, &b) || fa != fb || a.lo > b.lo)
		return 0;

	*family = fa;
	out->lo = a.lo;
	out->hi = b.lo;
	return 1;
}

static int ranges_add(struct ranges *r, struct range x) {
	if (r->n == r->cap) {
		size_t cap = r->cap ? r->cap * 2 : 64;
		struct range *v = realloc(r->v, cap * sizeof(*v));

		if (!v)
			return 0;

		r->v   = v;
		r->cap = cap;
	}

	r->v[r->n++] = x;
	return 1;
}

static int range_cmp(const void *a, const void *b) {
	const struct range *x = a, *y = b;
	return x->lo < y->lo ? -1 : x->lo > y->lo;
}

static void trim(char **s) {
	char *e;

	while (**s == ' ' || **s == '\t' || **s == '\r' || **s == '\n')
		(*s)++;

	e = *s + strlen(*s);

	while (e > *s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n'))
		*--e = 0;
}

/* Add one entry: an IP, a CIDR, an IP-IP range, or for an exclude list the keyword
 * "private". Target CIDRs reject set host bits. Entries of the other family are skipped, since v4 and v6 would otherwise
 * collide as plain integers. Returns 1, 0 for an invalid entry, or -1 when out of memory. */
static int add_entry(struct ranges *r, const char *item, int family, int target) {
	struct range x;
	int fam;

	if (!target && !strcasecmp(item, "private")) {
		for (size_t i = 0; i < sizeof(PRIVATE_RANGES) / sizeof(*PRIVATE_RANGES); i++)
			if (add_entry(r, PRIVATE_RANGES[i], family, 0) < 0)
				return -1;

		return 1;
	}

	if (strchr(item, '-') ? !parse_dash(item, &fam, &x) : !parse_cidr(item, target, &fam, &x))
		return 0;

	if (fam == family && !ranges_add(r, x))
		return -1;

	return 1;
}

static int is_file(const char *path) {
	struct stat st;
	return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* Whether a list has a "-" entry, meaning stdin */
static int has_stdin(const char *list) {
	char *copy = strdup(list), *save = NULL;
	int found = 0;

	for (char *tok = copy ? strtok_r(copy, ",", &save) : NULL; tok && !found; tok = strtok_r(NULL, ",", &save)) {
		trim(&tok);
		found = !strcmp(tok, "-");
	}

	free(copy);
	return found;
}

/* All of stdin, read once since a pipe cannot be read twice. Returns 0 or an errno. */
static int read_stdin(char **out, size_t *len) {
	size_t cap = 1 << 16, n;

	*len = 0;

	if (!(*out = malloc(cap)))
		return ENOMEM;

	while ((n = fread(*out + *len, 1, cap - *len, stdin)) > 0) {
		*len += n;

		if (*len == cap) {
			char *grown = realloc(*out, cap *= 2);

			if (!grown)
				return ENOMEM;

			*out = grown;
		}
	}

	return ferror(stdin) ? (errno ? errno : EIO) : 0;
}

/* A target or exclude list is comma-separated, and each entry can be an IP, a CIDR, an IP-IP
 * range, a file of entries one per line, for targets "-" for the text read from stdin (in,
 * inlen), or for excludes the keyword "private". Returns 0 or an errno with err filled. */
static int parse_list(struct ranges *r, const char *arg, int family, int target, const char *in, size_t inlen, char *err, size_t errlen) {
	char *copy = strdup(arg), *save = NULL;
	int rc = 0;

	if (!copy)
		return ENOMEM;

	for (char *tok = strtok_r(copy, ",", &save); tok && !rc; tok = strtok_r(NULL, ",", &save)) {
		int from_stdin;

		trim(&tok);

		if (!*tok)
			continue;

		from_stdin = target && in && !strcmp(tok, "-");

		if (!from_stdin && ((!target && !strcasecmp(tok, "private")) || !is_file(tok))) {
			int added = add_entry(r, tok, family, target);

			if (added < 0)
				rc = ENOMEM;
			else if (!added && target)
				snprintf(err, errlen, "Invalid target: %s (not an IP, a CIDR, an IP-IP range, or an existing file)", tok), rc = EINVAL;
			else if (!added)
				snprintf(err, errlen, "exclude '%s' is not an IP, a CIDR, an IP-IP range, the keyword \"private\", or an existing file", tok), rc = EINVAL;

			continue;
		}

		/* Empty stdin has nothing to read, and fmemopen refuses a zero size */
		if (from_stdin && !inlen)
			continue;

		FILE *f = from_stdin ? fmemopen((char *)in, inlen, "r") : fopen(tok, "r");
		char *line = NULL;
		size_t linecap = 0;

		if (from_stdin)
			tok = "stdin";

		if (!f) {
			snprintf(err, errlen, "%s: %s", strerror(errno), tok);
			rc = errno;
			continue;
		}

		/* getline reads whole lines of any length, so a long comment is never split into
		 * a second piece that no longer starts with # */
		while (!rc && getline(&line, &linecap, f) >= 0) {
			char *s = line;
			trim(&s);

			if (!*s || *s == '#')
				continue;

			int added = add_entry(r, s, family, target);

			if (added < 0)
				rc = ENOMEM;
			else if (!added)
				snprintf(err, errlen, "Invalid IP, CIDR or range in %s: %s", tok, s), rc = EINVAL;
		}

		free(line);
		fclose(f);
	}

	if (rc == ENOMEM)
		snprintf(err, errlen, "out of memory");

	free(copy);
	return rc;
}

static int parse_port(const char *s, unsigned *out) {
	unsigned v = 0;

	if (!*s || strlen(s) > 5)
		return 0;

	for (; *s; s++) {
		if (*s < '0' || *s > '9')
			return 0;

		v = v * 10 + (unsigned)(*s - '0');
	}

	*out = v;
	return v <= 65535;
}

/* A port list is comma-separated ports and lo-hi ranges, each optionally tagged T:, U: or S:
 * for TCP, UDP or SCTP, with TCP when untagged. Duplicates and overlaps collapse, and the
 * ports are kept sorted by protocol then number, so the order they were given in does not
 * change the output. Returns 0 or an errno with err filled. */
static int parse_ports(clcg *g, const char *arg, char *err, size_t errlen) {
	/* 24KB, on the heap so small embedded stacks can hold the caller */
	uint64_t *seen = calloc(3 * 65536 / 64, sizeof(*seen));
	char *copy = strdup(arg), *save = NULL;

	if (!copy || !seen) {
		free(copy);
		free(seen);
		return snprintf(err, errlen, "out of memory"), ENOMEM;
	}

	for (char *tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		char *num, *dash;
		unsigned lo, hi, proto = 0;

		trim(&tok);

		if (!*tok)
			continue;

		num = tok;

		if (tok[0] && tok[1] == ':') {
			const char *tags = "TUS", *t = strchr(tags, tok[0] & ~0x20);

			if (!t) {
				snprintf(err, errlen, "Invalid port protocol (use T:, U: or S:): %s", tok);
				free(copy);
				free(seen);
				return EINVAL;
			}

			proto = (unsigned)(t - tags);
			num   = tok + 2;
		}

		if ((dash = strchr(num, '-')))
			*dash = 0;

		if (!parse_port(num, &lo) || !parse_port(dash ? dash + 1 : num, &hi) || lo > hi) {
			if (dash)
				*dash = '-';

			snprintf(err, errlen, "Invalid port or port range: %s", tok);
			free(copy);
			free(seen);
			return EINVAL;
		}

		for (unsigned p = lo; p <= hi; p++)
			seen[(proto * 65536 + p) / 64] |= 1ULL << (p % 64);
	}

	free(copy);

	for (size_t i = 0; i < 3 * 65536 / 64; i++)
		g->nports += (size_t)__builtin_popcountll(seen[i]);

	if (!g->nports)
		return free(seen), snprintf(err, errlen, "No ports given"), EINVAL;

	g->ports  = malloc(g->nports * sizeof(*g->ports));
	g->protos = malloc(g->nports * sizeof(*g->protos));
	g->ptxt   = malloc(g->nports * sizeof(*g->ptxt));

	if (!g->ports || !g->protos || !g->ptxt)
		return free(seen), snprintf(err, errlen, "out of memory"), ENOMEM;

	for (unsigned code = 0, n = 0; code < 3 * 65536; code++) {
		if (seen[code / 64] >> (code % 64) & 1) {
			char tmp[16];

			g->ports[n]  = (uint16_t)(code % 65536);
			g->protos[n] = PROTO_NUM[code / 65536];
			g->ptxt[n].n = (unsigned char)snprintf(tmp, sizeof(tmp), ":%u%s\n", code % 65536, PROTO_NAME[code / 65536]);
			memcpy(g->ptxt[n++].s, tmp, sizeof(g->ptxt->s));
		}
	}

	free(seen);
	return 0;
}

/* Clip to the target, sort and merge, so every remaining range is disjoint and inside it */
static void optimize(struct ranges *r, struct range target) {
	size_t n = 0;

	for (size_t i = 0; i < r->n; i++) {
		struct range x = r->v[i];

		if (x.hi < target.lo || x.lo > target.hi)
			continue;

		if (x.lo < target.lo) x.lo = target.lo;
		if (x.hi > target.hi) x.hi = target.hi;

		r->v[n++] = x;
	}

	r->n = n;

	if (!n)
		return;

	qsort(r->v, n, sizeof(*r->v), range_cmp);

	size_t out = 0;

	/* A range ending at the top of IPv6 contains everything sorted after it */
	for (size_t i = 1; i < n; i++) {
		if (r->v[out].hi == ~(u128)0 || r->v[i].lo <= r->v[out].hi + 1) {
			if (r->v[i].hi > r->v[out].hi)
				r->v[out].hi = r->v[i].hi;
		} else {
			r->v[++out] = r->v[i];
		}
	}

	r->n = out + 1;
}

static uint64_t fnv(uint64_t h, const void *data, size_t len) {
	const unsigned char *b = data;

	for (size_t i = 0; i < len; i++)
		h = (h ^ b[i]) * 0x100000001b3ULL;

	return h;
}

/* FNV-1a over the effective exclusions, so a resume against a different list is refused.
 * A target list (more than a single CIDR) also folds in each family's span, and ports fold
 * in the ports, protocols and rounds. A single CIDR without ports hashes as it always has. */
static void fingerprint(const struct span sp[2], int multi, const clcg *g, char out[17]) {
	uint64_t h = 0xcbf29ce484222325ULL;

	for (int f = 0; f < 2; f++) {
		if (multi && sp[f].has) {
			unsigned char fam = f ? 6 : 4;
			u128 hull[2] = { sp[f].hull.lo, sp[f].hull.hi };

			h = fnv(h, &fam, 1);
			h = fnv(h, hull, sizeof(hull));
		}

		for (size_t i = 0; i < sp[f].ex.n; i++) {
			u128 parts[2] = { sp[f].ex.v[i].lo, sp[f].ex.v[i].hi };
			h = fnv(h, parts, sizeof(parts));
		}
	}

	for (size_t i = 0; i < g->nports; i++) {
		unsigned char b[3] = { (unsigned char)(g->ports[i] & 255), (unsigned char)(g->ports[i] >> 8), g->protos[i] };
		h = fnv(h, b, g->protos[i] == CLCG_TCP ? 2 : 3);
	}

	if (g->nports) {
		unsigned char r = (unsigned char)g->rounds;
		h = fnv(h, &r, 1);
	}

	snprintf(out, 17, "%016llx", (unsigned long long)h);
}


/* ---------------------------------------------------------------- generator */

/* Compose n steps of x -> a*x + c into one (a, c), modulo the power of 2 behind mask */
static void jump_params(u128 n, u128 c, u128 mask, u128 *ra, u128 *rc) {
	u128 a = 1, b = 0, sa = LCG_A & mask, sc = c & mask;

	while (n) {
		if (n & 1) {
			a = (sa * a) & mask;
			b = (sa * b + sc) & mask;
		}

		sc = (sa * sc + sc) & mask;
		sa = (sa * sa) & mask;
		n >>= 1;
	}

	*ra = a;
	*rc = b;
}

/* A power-of-2 LCG's low bits cycle with short periods (the last bit alternates every
 * step). xorshift and odd multiplies are each invertible modulo 2^k, so this scrambles
 * that pattern away while keeping the output an exact permutation of [0, 2^k). */
static inline uint64_t mix64(uint64_t x, unsigned s, uint64_t mask) {
	x ^= x >> s; x = (x * MIX_M1) & mask;
	x ^= x >> s; x = (x * MIX_M2) & mask;
	x ^= x >> s;
	return x;
}

static inline u128 mix128(u128 x, unsigned s, u128 mask) {
	x ^= x >> s; x = (x * MIX_M1) & mask;
	x ^= x >> s; x = (x * MIX_M2) & mask;
	x ^= x >> s;
	return x;
}

/* Feistel round function: a keyed splitmix64 finalizer, of which each round uses the low bits */
static inline uint64_t feistel_f(uint64_t r, uint64_t key) {
	r = (r ^ key) * MIX_M1;
	r ^= r >> 32;
	r *= MIX_M2;
	return r ^ r >> 29;
}

/* A Feistel network permutes [0, 2^(hi + lo)) for any keys and round function, since each
 * round only XORs one half with a function of the other. The halves may differ by a bit, so
 * the domain is the smallest power of 2 covering the pairs, and they trade sizes each round. */
static inline uint64_t feistel64(uint64_t x, unsigned hi, unsigned lo, unsigned rounds, const uint64_t *keys) {
	uint64_t mhi = ((uint64_t)1 << hi) - 1, mlo = ((uint64_t)1 << lo) - 1;

	for (unsigned i = 0; i < rounds; i++) {
		uint64_t r = x & mlo, l = (x >> lo) ^ (feistel_f(r, keys[i]) & mhi), tm = mhi;
		unsigned t = hi;

		x   = r << hi | l;
		hi  = lo, lo = t;
		mhi = mlo, mlo = tm;
	}

	return x;
}

/* The same over a domain wider than 64 bits, where each half is at most 64 bits */
static u128 feistel128(u128 x, unsigned hi, unsigned lo, unsigned rounds, const uint64_t *keys) {
	uint64_t mhi = hi == 64 ? ~0ULL : ((uint64_t)1 << hi) - 1, mlo = ((uint64_t)1 << lo) - 1;

	for (unsigned i = 0; i < rounds; i++) {
		uint64_t r = (uint64_t)x & mlo, l = (uint64_t)(x >> lo) ^ (feistel_f(r, keys[i]) & mhi), tm = mhi;
		unsigned t = hi;

		x   = (u128)r << hi | l;
		hi  = lo, lo = t;
		mhi = mlo, mlo = tm;
	}

	return x;
}

static inline u128 permute(const clcg *g, u128 x) {
	if (g->fhi + g->flo <= 64)
		return feistel64((uint64_t)x, g->fhi, g->flo, g->rounds, g->keys);

	return feistel128(x, g->fhi, g->flo, g->rounds, g->keys);
}

/* Index among the valid IPs -> address, for IPv4. nex is fixed per generator, so the
 * branch is always predicted and a run without exclusions skips the lookup. */
static inline uint64_t addr_v4(const struct slot *slots, const uint32_t *bucket, unsigned bshift, size_t nex, uint64_t start, uint64_t index) {
	if (!nex)
		return start + index;

	/* Last slot whose offset <= index: the bucket gives the slot in effect at its start,
	 * and the scan rarely moves */
	size_t slot = bucket[index >> bshift];

	while (slots[slot + 1].off <= index)
		slot++;

	return (uint64_t)slots[slot].base + index - slots[slot].off;
}

static u128 addr_v6(const clcg *g, u128 index) {
	size_t lo = 0, hi = g->nex6;

	while (lo < hi) {
		size_t mid = (lo + hi) / 2;

		if (g->offsets[mid] <= index) lo = mid + 1;
		else hi = mid;
	}

	return lo ? g->bases[lo - 1] + index - g->offsets[lo - 1] : g->start6 + index;
}

/* Index among all valid IPs -> address, IPv4 indexes first */
static void ip_at(const clcg *g, u128 index, struct clcg_ip *ip) {
	memset(ip, 0, sizeof(*ip));

	if (index < g->n4) {
		uint64_t v = addr_v4(g->slots, g->bucket, g->bshift, g->nex4, g->start4, (uint64_t)index);

		ip->family = 4;

		for (int b = 3; b >= 0; b--, v >>= 8)
			ip->addr[b] = (uint8_t)v;
	} else {
		u128 v = addr_v6(g, index - g->n4);

		ip->family = 6;

		for (int b = 15; b >= 0; b--, v >>= 8)
			ip->addr[b] = (uint8_t)v;
	}
}

/* Runs when the library loads, so concurrent first calls to clcg_new() cannot race on it */
__attribute__((constructor)) static void init_tables(void) {
	for (int i = 0; i < 256; i++) {
		int n = snprintf(oct_dot[i], 4, "%d", i);
		memcpy(oct_nl[i], oct_dot[i], 4);
		oct_dot[i][n] = '.';
		oct_nl[i][n]  = '\n';
		oct_len[i]    = (unsigned char)(n + 1);
	}
}


/* ---------------------------------------------------------------- api */

clcg *clcg_new(const struct clcg_config *cfg, char *err, size_t errlen) {
	return clcg_new_ports(cfg, NULL, 0, err, errlen);
}

/* Build one family's span: merge its targets, add the gaps between them to that family's
 * exclusions, and number what is left. Returns 0 or an errno with err filled. */
static int build_span(struct span *sp, const struct clcg_config *cfg, int family, const char *in, size_t inlen, char *err, size_t errlen) {
	struct ranges t = { 0 };
	struct range all = { 0, family == 4 ? 0xFFFFFFFF : ~(u128)0 };
	int rc;

	if ((rc = parse_list(&t, cfg->cidr, family, 1, in, inlen, err, errlen)) || !t.n) {
		free(t.v);
		return rc;
	}

	optimize(&t, all);

	sp->has  = 1;
	sp->hull = (struct range){ t.v[0].lo, t.v[t.n - 1].hi };

	for (size_t i = 1; i < t.n && !rc; i++)
		if (!ranges_add(&sp->ex, (struct range){ t.v[i - 1].hi + 1, t.v[i].lo - 1 }))
			rc = ENOMEM;

	free(t.v);

	if (rc)
		return snprintf(err, errlen, "out of memory"), rc;

	if (cfg->exclude && (rc = parse_list(&sp->ex, cfg->exclude, family, 0, NULL, 0, err, errlen)))
		return rc;

	optimize(&sp->ex, sp->hull);

	sp->offsets = malloc((sp->ex.n + 1) * sizeof(u128));
	sp->bases   = malloc((sp->ex.n + 1) * sizeof(u128));

	if (!sp->offsets || !sp->bases)
		return snprintf(err, errlen, "out of memory"), ENOMEM;

	/* An exclusion ending at the top of IPv6 leaves nothing after it, and its offset equals
	 * the count so no index selects its base */
	u128 cursor = sp->hull.lo, before = 0;
	int end = 0;

	for (size_t i = 0; i < sp->ex.n; i++) {
		before          += sp->ex.v[i].lo - cursor;
		end              = sp->ex.v[i].hi == ~(u128)0;
		cursor           = sp->ex.v[i].hi + 1;
		sp->offsets[i]   = before;
		sp->bases[i]     = cursor;
	}

	/* Only a span over all of IPv6 with nothing excluded reaches 2^128, which does not fit */
	if (!end && cursor <= sp->hull.hi) {
		u128 tail = sp->hull.hi - cursor;

		if (tail == ~(u128)0 || before + tail + 1 < before)
			return snprintf(err, errlen, "%s is too large (over 2^127 addresses)", cfg->cidr), EINVAL;

		before += tail + 1;
	}

	sp->n = before;
	return 0;
}

static void spans_free(struct span sp[2]) {
	for (int f = 0; f < 2; f++) {
		free(sp[f].ex.v);
		free(sp[f].offsets);
		free(sp[f].bases);
	}
}

clcg *clcg_new_ports(const struct clcg_config *cfg, const char *ports, unsigned rounds, char *err, size_t errlen) {
	struct span sp[2] = { 0 };
	int rc;
	clcg *g;

	if (err && errlen)
		err[0] = 0;

	uint64_t shard = cfg->shard ? cfg->shard : 1, total = cfg->total ? cfg->total : 1;

	if (shard > total)
		return fail(NULL, EINVAL, err, errlen, "shard %llu is greater than the total of %llu", (unsigned long long)shard, (unsigned long long)total);

	if (!cfg->cidr)
		return fail(NULL, EINVAL, err, errlen, "Invalid target: (null)");

	if (!(g = calloc(1, sizeof(*g))))
		return fail(NULL, ENOMEM, err, errlen, "out of memory");

	g->rounds = rounds ? rounds : 4;

	if (g->rounds > CLCG_ROUNDS_MAX)
		return fail(g, EINVAL, err, errlen, "rounds must be from 1 to %d", CLCG_ROUNDS_MAX);

	if (ports && (rc = parse_ports(g, ports, err, errlen)))
		return fail(g, rc, NULL, 0, "%s", "");

	/* A "-" target reads stdin once, for both families */
	int piped = has_stdin(cfg->cidr);
	char *in = NULL;
	size_t inlen = 0;

	if (piped && (rc = read_stdin(&in, &inlen))) {
		free(in);
		return fail(g, rc, err, errlen, "%s: stdin", strerror(rc));
	}

	/* Targets and exclusions, IPv4 then IPv6. IPv4 takes the first n4 indexes. */
	for (int f = 0; f < 2; f++) {
		if ((rc = build_span(&sp[f], cfg, f ? 6 : 4, in, inlen, err, errlen))) {
			free(in);
			spans_free(sp);
			return fail(g, rc, NULL, 0, "%s", "");
		}
	}

	free(in);

	if (!sp[0].has && !sp[1].has) {
		spans_free(sp);
		return fail(g, EINVAL, err, errlen, "No targets given");
	}

#ifndef CLCG_NO_IPV6
	if (sp[1].n > ((u128)1 << 127) - sp[0].n) {
		spans_free(sp);
		return fail(g, EINVAL, err, errlen, "%s is too large (over 2^127 addresses)", cfg->cidr);
	}
#endif

	g->n4     = sp[0].n;
	g->valid  = sp[0].n + sp[1].n;
	g->family = sp[1].n ? (sp[0].n ? 0 : 6) : 4;
	g->start4 = (uint64_t)sp[0].hull.lo;
	g->nex4   = sp[0].ex.n;
	g->start6 = sp[1].hull.lo;
	g->nex6   = sp[1].ex.n;

	fingerprint(sp, strchr(cfg->cidr, ',') || is_file(cfg->cidr) || piped, g, g->fingerprint);

	if (g->n4) {
		size_t nex = g->nex4;
		unsigned k4 = 0;

		while (((u128)1 << k4) < g->n4)
			k4++;

		if (!(g->slots = malloc((nex + 2) * sizeof(*g->slots)))) {
			spans_free(sp);
			return fail(g, ENOMEM, err, errlen, "out of memory");
		}

		g->slots[0].off       = 0;
		g->slots[0].base      = (uint32_t)g->start4;
		g->slots[nex + 1].off = UINT32_MAX;

		for (size_t i = 0; i < nex; i++) {
			g->slots[i + 1].off  = (uint32_t)sp[0].offsets[i];
			g->slots[i + 1].base = (uint32_t)sp[0].bases[i];
		}

		/* Bucket table: the top bits of an index give the slot in effect at the start of
		 * its bucket. At least 256 buckets and 4 per exclusion measured best across few
		 * and many exclusions, and the 2^20 cap keeps the table at 4MB. */
		unsigned bbits = 0;

		while (bbits < k4 && bbits < 20 && (bbits < 8 || ((size_t)1 << bbits) < nex * 4))
			bbits++;

		g->bshift = k4 - bbits;

		if (!(g->bucket = malloc(((size_t)1 << bbits) * sizeof(uint32_t)))) {
			spans_free(sp);
			return fail(g, ENOMEM, err, errlen, "out of memory");
		}

		for (size_t b = 0, slot = 0; b < ((size_t)1 << bbits); b++) {
			while (g->slots[slot + 1].off <= ((uint64_t)b << g->bshift))
				slot++;

			g->bucket[b] = (uint32_t)slot;
		}
	}

	/* The IPv6 table moves into the generator */
	g->offsets     = sp[1].offsets;
	g->bases       = sp[1].bases;
	sp[1].offsets  = sp[1].bases = NULL;
	spans_free(sp);

	/* Seed */
	g->seed = cfg->seed;

	if (!cfg->has_seed && getrandom(&g->seed, sizeof(g->seed), 0) != sizeof(g->seed))
		return fail(g, errno, err, errlen, "getrandom: %s", strerror(errno));

	/* Generator: modulus 2^k >= valid, increment derived from the seed (any odd value
	 * keeps the full period), start at the seed */
	unsigned k = 0;

	while (k < 128 && ((u128)1 << k) < g->valid)
		k++;

	uint64_t sm   = g->seed;
	uint64_t c_hi = splitmix64(&sm);
	uint64_t c_lo = splitmix64(&sm);

	g->mask  = ((u128)1 << k) - 1;
	g->shift = (k + 1) / 2;

#ifdef CLCG_NO_IPV6
	/* k is at most 33 here, so the high half never reaches the mask */
	(void)c_hi;
	u128 c    = (c_lo | 1) & g->mask;
#else
	u128 c    = (((u128)c_hi << 64) | c_lo | 1) & g->mask;
#endif
	u128 m    = (u128)1 << k;
	u128 idx0 = shard - 1;

	/* Shard i owns steps i+1, i+1+T, i+1+2T ... which across all shards is exactly the
	 * full period, so there are no gaps and no overlaps */
	g->steps = g->valid && m > idx0 ? (m - idx0 + total - 1) / total : 0;
	g->step  = cfg->step < g->steps ? cfg->step : g->steps;

	u128 ja, jc;
	jump_params(idx0 + 1 + g->step * total, c, g->mask, &ja, &jc);
	g->cur = (ja * ((u128)g->seed & g->mask) + jc) & g->mask;
	jump_params(total, c, g->mask, &g->sa, &g->sc);

	/* Ports replace the LCG with a Feistel network over every IP:port pair. Its input is
	 * just the step's position in the domain, as the keys alone decide the order. */
	if (g->nports) {
		unsigned kd = 0;

#ifndef CLCG_NO_IPV6
		if (g->valid > ((u128)1 << 127) / g->nports)
			return fail(g, EINVAL, err, errlen, "%s with %zu ports is too large (over 2^127 IP:port pairs)", cfg->cidr, g->nports);
#endif

		g->targets = g->valid * g->nports;

		while (((u128)1 << kd) < g->targets)
			kd++;

		g->mask  = ((u128)1 << kd) - 1;
		g->fhi   = kd - kd / 2;
		g->flo   = kd / 2;
		m        = (u128)1 << kd;
		g->steps = g->targets && m > idx0 ? (m - idx0 + total - 1) / total : 0;
		g->step  = cfg->step < g->steps ? cfg->step : g->steps;
		g->cur   = idx0 + g->step * total;
		g->sc    = total;

		for (unsigned i = 0; i < g->rounds; i++)
			g->keys[i] = splitmix64(&sm);
	}

	return g;
}

void clcg_free(clcg *g) {
	if (!g)
		return;

	free(g->slots);
	free(g->bucket);
	free(g->offsets);
	free(g->bases);
	free(g->ports);
	free(g->protos);
	free(g->ptxt);
	free(g);
}

int clcg_next(clcg *g, struct clcg_ip *ip) {
	if (g->nports)
		return clcg_next_port(g, ip, NULL, NULL);

	if (g->family == 4) {
		uint64_t cur = (uint64_t)g->cur, sa = (uint64_t)g->sa, sc = (uint64_t)g->sc, mask = (uint64_t)g->mask, valid = (uint64_t)g->valid;

		while (g->step < g->steps) {
			uint64_t index = mix64(cur, g->shift, mask);

			cur = (sa * cur + sc) & mask;
			g->step++;

			if (index < valid) {
				uint32_t v = (uint32_t)addr_v4(g->slots, g->bucket, g->bshift, g->nex4, g->start4, index);

				g->cur     = cur;
				ip->family = 4;
				memset(ip->addr, 0, sizeof(ip->addr));
				ip->addr[0] = (uint8_t)(v >> 24);
				ip->addr[1] = (uint8_t)(v >> 16);
				ip->addr[2] = (uint8_t)(v >> 8);
				ip->addr[3] = (uint8_t)v;
				return 1;
			}
		}

		g->cur = cur;
		return 0;
	}

	while (g->step < g->steps) {
		u128 index = mix128(g->cur, g->shift, g->mask);

		g->cur = (g->sa * g->cur + g->sc) & g->mask;
		g->step++;

		/* Indices past the valid count are the slack up to the power of 2, no IP */
		if (index >= g->valid)
			continue;

		ip_at(g, index, ip);
		return 1;
	}

	return 0;
}

int clcg_next_port(clcg *g, struct clcg_ip *ip, uint16_t *port, int *proto) {
	if (!g->nports) {
		if (port)
			*port = 0;

		if (proto)
			*proto = 0;

		return clcg_next(g, ip);
	}

	while (g->step < g->steps) {
		u128 t = permute(g, g->cur);

		g->cur += g->sc;
		g->step++;

		/* Pairs past the target count are the slack up to the power of 2 */
		if (t >= g->targets)
			continue;

		u128 pi = t / g->valid;

		if (port)
			*port = g->ports[pi];

		if (proto)
			*proto = g->protos[pi];

		ip_at(g, t - pi * g->valid, ip);
		return 1;
	}

	return 0;
}

size_t clcg_next_batch(clcg *g, struct clcg_ip *ips, size_t n) {
	size_t got = 0;

	if (g->family != 4 || g->nports) {
		while (got < n && clcg_next(g, &ips[got]))
			got++;

		return got;
	}

	/* The clcg_next loop with the generator held in locals for the whole batch */
	const struct slot *slots = g->slots;
	const uint32_t *bucket   = g->bucket;
	uint64_t cur = (uint64_t)g->cur, sa = (uint64_t)g->sa, sc = (uint64_t)g->sc, mask = (uint64_t)g->mask;
	uint64_t valid = (uint64_t)g->valid, start = g->start4, step = (uint64_t)g->step, steps = (uint64_t)g->steps;
	unsigned shift = g->shift, bshift = g->bshift;
	size_t nex = g->nex4;

	while (got < n && step < steps) {
		uint64_t index = mix64(cur, shift, mask);

		cur = (sa * cur + sc) & mask;
		step++;

		if (index < valid) {
			uint32_t v = (uint32_t)addr_v4(slots, bucket, bshift, nex, start, index);
			struct clcg_ip *ip = &ips[got++];

			memset(ip, 0, sizeof(*ip));
			ip->family  = 4;
			ip->addr[0] = (uint8_t)(v >> 24);
			ip->addr[1] = (uint8_t)(v >> 16);
			ip->addr[2] = (uint8_t)(v >> 8);
			ip->addr[3] = (uint8_t)v;
		}
	}

	g->cur  = cur;
	g->step = step;
	return got;
}

size_t clcg_fill(clcg *g, char *buf, size_t cap, clcg_u128 max_steps) {
	u128 left = g->steps - g->step;
	char *p   = buf;

	if (max_steps < left)
		left = max_steps;

	if (g->nports) {
		/* The longest line is "[" + IPv6 + "]:65535/sctp\n" at 59 bytes. The port starts at
		 * most 47 bytes in, so its 16-byte copy stays within 64 bytes of the line start. */
		if (cap < 64)
			return 0;

		char *const lim = buf + cap - 64;
		const struct ptxt *ptxt = g->ptxt;

		if (g->family == 4) {
			/* IPv4 pairs stay under 2^48, so this is the 64-bit Feistel and 64-bit division */
			const struct slot *slots = g->slots;
			const uint32_t *bucket   = g->bucket;
			const uint64_t *keys     = g->keys;
			uint64_t cur = (uint64_t)g->cur, stride = (uint64_t)g->sc, valid = (uint64_t)g->valid, targets = (uint64_t)g->targets;
			uint64_t start = g->start4, n = (uint64_t)left, i;
			unsigned fhi = g->fhi, flo = g->flo, rounds = g->rounds, bshift = g->bshift;
			size_t nex = g->nex4;

			for (i = 0; i < n && p <= lim; i++) {
				uint64_t t = feistel64(cur, fhi, flo, rounds, keys);

				cur += stride;

				if (t < targets) {
					uint64_t pi = t / valid, v = addr_v4(slots, bucket, bshift, nex, start, t - pi * valid);

					__builtin_memcpy(p, oct_dot[v >> 24], 4);       p += oct_len[v >> 24];
					__builtin_memcpy(p, oct_dot[v >> 16 & 255], 4); p += oct_len[v >> 16 & 255];
					__builtin_memcpy(p, oct_dot[v >> 8 & 255], 4);  p += oct_len[v >> 8 & 255];
					__builtin_memcpy(p, oct_dot[v & 255], 4);       p += oct_len[v & 255] - 1;
					__builtin_memcpy(p, &ptxt[pi], 16);             p += ptxt[pi].n;
				}
			}

			g->cur   = cur;
			g->step += i;
		} else {
			for (u128 i = 0; i < left && p <= lim; i++) {
				u128 t = permute(g, g->cur);

				g->cur += g->sc;
				g->step++;

				if (t < g->targets) {
					struct clcg_ip ip;
					u128 pi = t / g->valid;

					ip_at(g, t - pi * g->valid, &ip);

					if (ip.family == 6) {
						*p++ = '[';
						p   += clcg_format(&ip, p);
						*p++ = ']';
					} else {
						p += clcg_format(&ip, p);
					}

					__builtin_memcpy(p, &ptxt[pi], 16);
					p += ptxt[pi].n;
				}
			}
		}
	} else if (g->family == 4) {
		/* IPv4 fits in 64 bits, which measured 5x faster than the 128-bit path */
		if (cap < 16)
			return 0;

		const struct slot *slots = g->slots;
		const uint32_t *bucket   = g->bucket;
		uint64_t cur = (uint64_t)g->cur, sa = (uint64_t)g->sa, sc = (uint64_t)g->sc, mask = (uint64_t)g->mask;
		uint64_t valid = (uint64_t)g->valid, start = g->start4, n = (uint64_t)left, i;
		unsigned shift = g->shift, bshift = g->bshift;
		size_t nex = g->nex4;
		char *const lim = buf + cap - 16;

		for (i = 0; i < n && p <= lim; i++) {
			uint64_t index = mix64(cur, shift, mask);

			cur = (sa * cur + sc) & mask;

			if (index < valid) {
				uint64_t v = addr_v4(slots, bucket, bshift, nex, start, index);

				__builtin_memcpy(p, oct_dot[v >> 24], 4);       p += oct_len[v >> 24];
				__builtin_memcpy(p, oct_dot[v >> 16 & 255], 4); p += oct_len[v >> 16 & 255];
				__builtin_memcpy(p, oct_dot[v >> 8 & 255], 4);  p += oct_len[v >> 8 & 255];
				__builtin_memcpy(p, oct_nl[v & 255], 4);        p += oct_len[v & 255];
			}
		}

		g->cur   = cur;
		g->step += i;
	} else {
		if (cap < INET6_ADDRSTRLEN + 1)
			return 0;

		char *const lim = buf + cap - (INET6_ADDRSTRLEN + 1);

		for (u128 i = 0; i < left && p <= lim; i++) {
			u128 index = mix128(g->cur, g->shift, g->mask);

			g->cur = (g->sa * g->cur + g->sc) & g->mask;
			g->step++;

			if (index < g->valid) {
				struct clcg_ip ip;

				ip_at(g, index, &ip);
				p += clcg_format(&ip, p);
				*p++ = '\n';
			}
		}
	}

	return (size_t)(p - buf);
}

clcg_u128 clcg_skip(clcg *g, clcg_u128 n) {
	u128 skipped = 0;

	/* Only whether each index is valid matters here, so nothing is mapped or formatted */
	if (g->nports) {
		while (skipped < n && g->step < g->steps) {
			skipped += permute(g, g->cur) < g->targets;
			g->cur  += g->sc;
			g->step++;
		}
	} else if (g->family == 4) {
		uint64_t cur = (uint64_t)g->cur, sa = (uint64_t)g->sa, sc = (uint64_t)g->sc, mask = (uint64_t)g->mask, valid = (uint64_t)g->valid;
		uint64_t step = (uint64_t)g->step, steps = (uint64_t)g->steps, want = n > valid ? valid : (uint64_t)n, done = 0;

		while (done < want && step < steps) {
			done += mix64(cur, g->shift, mask) < valid;
			cur   = (sa * cur + sc) & mask;
			step++;
		}

		g->cur   = cur;
		g->step  = step;
		skipped  = done;
	} else {
		while (skipped < n && g->step < g->steps) {
			skipped += mix128(g->cur, g->shift, g->mask) < g->valid;
			g->cur   = (g->sa * g->cur + g->sc) & g->mask;
			g->step++;
		}
	}

	return skipped;
}

size_t clcg_format(const struct clcg_ip *ip, char *buf) {
	if (!inet_ntop(ip->family == 4 ? AF_INET : AF_INET6, ip->addr, buf, 46)) {
		buf[0] = 0;
		return 0;
	}

	return strlen(buf);
}

clcg_u128 clcg_step(const clcg *g) { return g->step; }

clcg_u128 clcg_steps(const clcg *g) { return g->steps; }

clcg_u128 clcg_count(const clcg *g) { return g->nports ? g->targets : g->valid; }

uint64_t clcg_seed(const clcg *g) { return g->seed; }

const char *clcg_fingerprint(const clcg *g) { return g->fingerprint; }
