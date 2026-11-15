/* SPDX-License-Identifier: GPL-2.0 */
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t u32;
#define __user
#define min(a, b) ((a) < (b) ? (a) : (b))
#define WARN_ONCE(condition, ...) ((void)(condition))
static unsigned int copy_calls;
static bool fail_copy;

static int vscnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
	int n = vsnprintf(buf, size, fmt, args);
	return n < 0 ? 0 : ((size_t)n >= size ? (int)size - 1 : n);
}

static unsigned long copy_to_user(void *to, const void *from, unsigned long n)
{
	copy_calls++;
	if (fail_copy) {
		if (n > 1)
			memcpy(to, from, 1);
		return n;
	}
	memcpy(to, from, n);
	return 0;
}

#include "subject.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%d: %s\n", __LINE__, #x); exit(1); } } while (0)
static void write_log(struct bpf_verifier_log *log, const char *fmt, ...)
{
	va_list args;
	if (!bpf_verifier_log_needed(log))
		return;
	va_start(args, fmt);
	bpf_verifier_vlog(log, fmt, args);
	va_end(args);
}

/* BTF multipart diagnostics check needed once, then call the writer directly. */
static void write_direct(struct bpf_verifier_log *log, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	bpf_verifier_vlog(log, fmt, args);
	va_end(args);
}

int main(int argc, char **argv)
{
	char output[2050], other[32], line[1201];
	struct bpf_verifier_log log = { .level = 1, .ubuf = output + 1, .len_total = 16 };
	struct bpf_verifier_log second = { .level = 1, .ubuf = other, .len_total = sizeof(other) };
	CHECK(argc == 2);
	memset(output, 0xa5, sizeof(output));
	if (!strcmp(argv[1], "append")) {
		write_log(&log, "id=%u", 17u);
		write_log(&log, ":%s", "ok");
		CHECK(log.len_used == 8 && !strcmp(log.ubuf, "id=17:ok"));
		CHECK(output[0] == (char)0xa5 && output[17] == (char)0xa5);
	} else if (!strcmp(argv[1], "full")) {
		log.len_total = 5;
		write_log(&log, "%s", "abcdefgh");
		CHECK(log.len_used == 4 && !strcmp(log.ubuf, "abcd"));
		CHECK(output[6] == (char)0xa5);
		write_direct(&log, "ignored");
		CHECK(copy_calls == 1 && bpf_verifier_log_full(&log));
	} else if (!strcmp(argv[1], "disabled")) {
		log.level = 0;
		write_direct(&log, "ignored");
		log.level = 1;
		log.ubuf = NULL;
		write_direct(&log, "ignored");
		CHECK(copy_calls == 0 && log.len_used == 0);
	} else if (!strcmp(argv[1], "fault")) {
		fail_copy = true;
		write_log(&log, "broken");
		CHECK(log.ubuf == NULL && log.len_used == 0);
		write_direct(&log, "ignored");
		CHECK(copy_calls == 1);
	} else if (!strcmp(argv[1], "long")) {
		memset(line, 'x', sizeof(line) - 1);
		line[sizeof(line) - 1] = 0;
		log.len_total = 2048;
		write_log(&log, "%s", line);
		CHECK(log.len_used == 1023 && output[1024] == 0);
		CHECK(output[1025] == (char)0xa5);
	} else if (!strcmp(argv[1], "independent")) {
		write_log(&log, "first");
		write_log(&second, "second");
		write_log(&log, "+one");
		CHECK(!strcmp(log.ubuf, "first+one") && !strcmp(other, "second"));
		CHECK(log.len_used == 9 && second.len_used == 6);
	} else {
		CHECK(0);
	}
	return 0;
}
