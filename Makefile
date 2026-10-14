CC     ?= cc
CFLAGS ?= -O2 -Wall -Wextra
PREFIX ?= /usr/local

# Shared library ABI version. Bump it when clcg.h changes incompatibly.
ABI = 1

all: clcg libclcg.a libclcg.so

libclcg.o: libclcg.c clcg.h
	$(CC) $(CFLAGS) -c -o $@ libclcg.c

libclcg.pic.o: libclcg.c clcg.h
	$(CC) $(CFLAGS) -fPIC -c -o $@ libclcg.c

libclcg.a: libclcg.o
	$(AR) rcs $@ $<

libclcg.so: libclcg.pic.o
	$(CC) -shared -Wl,-soname,libclcg.so.$(ABI) -o libclcg.so.$(ABI) $<
	ln -sf libclcg.so.$(ABI) $@

clcg: main.c clcg.h libclcg.a
	$(CC) $(CFLAGS) -o $@ main.c libclcg.a

# Fully static, so one file runs on any Linux machine whatever its libraries
static: clcg-static

clcg-static: main.c clcg.h libclcg.a
	$(CC) $(CFLAGS) -static -o $@ main.c libclcg.a

tests/libtest: tests/libtest.c clcg.h libclcg.a
	$(CC) $(CFLAGS) -I. -o $@ tests/libtest.c libclcg.a

EXAMPLES = examples/basic examples/batch examples/resume examples/threads examples/ping

examples: $(EXAMPLES)

examples/%: examples/%.c clcg.h libclcg.a
	$(CC) $(CFLAGS) -I. -pthread -o $@ $< libclcg.a

test: clcg tests/libtest examples
	tests/libtest
	python3 tests/test.py

# Every address of 0.0.0.0/0 across 3 shards, then with private excluded. Needs 512MB and minutes.
fullcheck: tests/fullcheck.c clcg.h libclcg.a
	$(CC) $(CFLAGS) -I. -o tests/fullcheck tests/fullcheck.c libclcg.a
	tests/fullcheck 3 12345
	tests/fullcheck 1 777 private

bench: bench/bench.c bench/gen128.c
	$(CC) $(CFLAGS) -o bench/bench bench/bench.c
	$(CC) $(CFLAGS) -o bench/gen128 bench/gen128.c

install: all
	install -Dm755 clcg $(DESTDIR)$(PREFIX)/bin/clcg
	install -Dm644 clcg.h $(DESTDIR)$(PREFIX)/include/clcg.h
	install -Dm644 libclcg.a $(DESTDIR)$(PREFIX)/lib/libclcg.a
	install -Dm755 libclcg.so.$(ABI) $(DESTDIR)$(PREFIX)/lib/libclcg.so.$(ABI)
	ln -sf libclcg.so.$(ABI) $(DESTDIR)$(PREFIX)/lib/libclcg.so

clean:
	rm -f clcg clcg-static libclcg.o libclcg.pic.o libclcg.a libclcg.so libclcg.so.* $(EXAMPLES) tests/libtest tests/fullcheck bench/bench bench/gen128

.PHONY: all static examples test fullcheck bench install clean
