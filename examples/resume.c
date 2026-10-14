/*
 * clcg - Linear Congruential Generator for IP Sharding - Developed by acidvegas in C (https://github.com/acidvegas/clcg)
 * examples/resume.c
 *
 * Resume with zero loss. After each IP is fully handled, its position is saved. Starting
 * again with the same state file picks up right after the last handled IP, so a crash
 * loses nothing. A crash between handling an IP and saving repeats only that one IP.
 *
 * Saving after every IP costs a system call each time. A real program can save every N
 * IPs instead and repeat at most N after a crash.
 *
 * usage: resume CIDR SEED STATEFILE [STOP_AFTER]
 *        STOP_AFTER exits after that many IPs, to simulate a crash
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "clcg.h"

/* Steps can exceed 64 bits for IPv6, so the position is stored as decimal text */
static clcg_u128 load_step(int fd) {
	char buf[64] = { 0 };
	clcg_u128 step = 0;

	if (pread(fd, buf, sizeof(buf) - 1, 0) <= 0)
		return 0;

	for (char *p = buf; *p >= '0' && *p <= '9'; p++)
		step = step * 10 + (unsigned)(*p - '0');

	return step;
}

static void save_step(int fd, clcg_u128 step) {
	char tmp[64], buf[64];
	int n = 0, len = 0;

	do { tmp[n++] = '0' + (int)(step % 10); step /= 10; } while (step);

	while (n)
		buf[len++] = tmp[--n];

	buf[len++] = '\n';

	if (pwrite(fd, buf, (size_t)len, 0) != len || ftruncate(fd, len) < 0) {
		perror("save");
		exit(1);
	}
}

int main(int argc, char **argv) {
	if (argc != 4 && argc != 5) {
		fprintf(stderr, "usage: resume CIDR SEED STATEFILE [STOP_AFTER]\n");
		return 2;
	}

	int fd = open(argv[3], O_RDWR | O_CREAT, 0644);

	if (fd < 0) {
		perror(argv[3]);
		return 1;
	}

	/* Same CIDR, seed and shard as before, starting from the saved position */
	struct clcg_config cfg = { .cidr = argv[1], .seed = strtoull(argv[2], NULL, 10), .has_seed = 1, .step = load_step(fd) };
	unsigned long long stop = argc == 5 ? strtoull(argv[4], NULL, 10) : 0, handled = 0;
	char err[256], text[46];
	struct clcg_ip ip;

	clcg *g = clcg_new(&cfg, err, sizeof(err));

	if (!g) {
		fprintf(stderr, "%s\n", err);
		return 1;
	}

	while (clcg_next(g, &ip)) {
		/* Handle the IP. Here that is printing it, flushed so it is really done. */
		clcg_format(&ip, text);
		puts(text);
		fflush(stdout);

		/* Only now is it safe to record that this IP is finished */
		save_step(fd, clcg_step(g));

		if (stop && ++handled == stop)
			break;
	}

	/* Stopping early exits 3, so a caller can tell the simulated crash from finishing */
	int code = stop && handled == stop ? 3 : 0;

	clcg_free(g);
	close(fd);
	return code;
}
