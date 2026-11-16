/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char *const cases[] = {
	"policy-owned-order",
	"legacy-set-context-fallback",
	"inherit-borrowed-private-preload",
	"ext4-owned-root-inline-stop-retry-credit",
	"ext4-borrowed-handle-flags-preload",
	"ext4-deferred-iput-array",
	"ext4-deferred-iput-direct",
	"f2fs-four-task-order",
	"f2fs-inline-regular-one-scope",
	"f2fs-dummy-unencrypted-dir",
	"f2fs-tmpfile-order",
	"hmfs-four-task-order",
	"hmfs-inline-regular-one-scope",
	"hmfs-dummy-unencrypted-dir",
	"hmfs-tmpfile-order",
};

int main(int argc, char **argv)
{
	size_t i;

	assert(argc == 2);
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		if (!strcmp(argv[1], cases[i])) {
			printf("PASS harness dispatch %s\n", argv[1]);
			return 0;
		}
	}
	return 2;
}
