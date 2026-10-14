/*
 * clcg - Linear Congruential Generator for IP Sharding - Developed by acidvegas in C (https://github.com/acidvegas/clcg)
 * examples/ping.c
 *
 * A ping sweep: send one ICMP echo request to every IP in a range, in clcg's random order,
 * and print each address that replies. This sends real packets, so only point it at
 * networks you are allowed to probe.
 *
 * Needs a raw socket: run as root, or grant it once with
 *     sudo setcap cap_net_raw+ep examples/ping
 *
 * usage: ping CIDR [RATE]
 *        RATE is packets per second (default 1000)
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "clcg.h"

/* How long to keep listening for late replies after the last request */
#define WAIT_MS 2000

static uint16_t checksum(const void *data, size_t len) {
	const uint16_t *p = data;
	uint32_t sum = 0;

	for (; len > 1; len -= 2)
		sum += *p++;

	if (len)
		sum += *(const uint8_t *)p;

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += sum >> 16;
	return (uint16_t)~sum;
}

static double now(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Print every echo reply waiting on the socket that answers one of our requests */
static unsigned long long read_replies(int sock, uint16_t id, int timeout_ms) {
	struct pollfd pfd = { .fd = sock, .events = POLLIN };
	unsigned long long replies = 0;
	unsigned char buf[1500];

	while (poll(&pfd, 1, timeout_ms) > 0) {
		struct sockaddr_in from;
		socklen_t fromlen = sizeof(from);
		ssize_t n = recvfrom(sock, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&from, &fromlen);

		if (n <= 0)
			break;

		/* A raw socket hands over the IP header too, and sees every ICMP packet for this
		 * host, so skip past the header and keep only replies carrying our id */
		struct iphdr *iph = (struct iphdr *)buf;
		size_t hlen = (size_t)iph->ihl * 4;

		if ((size_t)n < hlen + sizeof(struct icmphdr))
			continue;

		struct icmphdr *icmp = (struct icmphdr *)(buf + hlen);

		if (icmp->type == ICMP_ECHOREPLY && icmp->un.echo.id == htons(id)) {
			char text[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &from.sin_addr, text, sizeof(text));
			puts(text);
			fflush(stdout);
			replies++;
		}

		timeout_ms = 0;
	}

	return replies;
}

int main(int argc, char **argv) {
	if (argc != 2 && argc != 3) {
		fprintf(stderr, "usage: ping CIDR [RATE]\n");
		return 2;
	}

	double rate = argc == 3 ? atof(argv[2]) : 1000;

	if (rate <= 0) {
		fprintf(stderr, "RATE must be above 0\n");
		return 2;
	}

	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	if (sock < 0) {
		fprintf(stderr, "raw socket: %s (run as root or setcap cap_net_raw+ep)\n", strerror(errno));
		return 1;
	}

	/* No seed given, so every sweep runs in a different order */
	struct clcg_config cfg = { .cidr = argv[1] };
	static struct clcg_ip ips[256];
	char err[256];

	clcg *g = clcg_new(&cfg, err, sizeof(err));

	if (!g) {
		fprintf(stderr, "%s\n", err);
		return 1;
	}

	uint16_t id = (uint16_t)getpid(), seq = 0;
	unsigned long long sent = 0, replies = 0;
	double next = now();
	size_t got;

	while ((got = clcg_next_batch(g, ips, 256)) > 0) {
		if (ips[0].family != 4) {
			fprintf(stderr, "this example only pings IPv4\n");
			clcg_free(g);
			close(sock);
			return 2;
		}

		for (size_t i = 0; i < got; i++) {
			struct icmphdr req = { .type = ICMP_ECHO };
			struct sockaddr_in to = { .sin_family = AF_INET };

			req.un.echo.id       = htons(id);
			req.un.echo.sequence = htons(seq++);
			req.checksum         = checksum(&req, sizeof(req));
			memcpy(&to.sin_addr, ips[i].addr, 4);

			/* Pace the requests, collecting replies while waiting for the next slot */
			double wait = next - now();

			if (wait > 0)
				replies += read_replies(sock, id, (int)(wait * 1000));

			next += 1 / rate;

			if (sendto(sock, &req, sizeof(req), 0, (struct sockaddr *)&to, sizeof(to)) < 0)
				fprintf(stderr, "send %s: %s\n", inet_ntoa(to.sin_addr), strerror(errno));
			else
				sent++;

			replies += read_replies(sock, id, 0);
		}
	}

	replies += read_replies(sock, id, WAIT_MS);
	fprintf(stderr, "seed %llu: sent %llu, replies %llu\n", (unsigned long long)clcg_seed(g), sent, replies);

	clcg_free(g);
	close(sock);
	return 0;
}
