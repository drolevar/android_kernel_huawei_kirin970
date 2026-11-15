/* SPDX-License-Identifier: GPL-2.0 */
/* Host storage for the extracted helper/accessors. No syscalls or packet I/O. */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include BPF_UAPI_HEADER

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

/* Only fields read by the production accessors; ARM64 uses offset-form tail. */
struct sk_buff {
	u8 *head, *data;
	u32 tail, len, data_len;
	uint16_t mac_header, network_header;
};

#define unlikely(x) (x)
#define likely(x) (x)
#define BPF_CALL_5(name, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5) \
	static u64 name(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5)

enum { RET_INTEGER, ARG_PTR_TO_CTX, ARG_ANYTHING,
	ARG_PTR_TO_UNINIT_MEM, ARG_CONST_SIZE };
struct bpf_func_proto {
	u64 (*func)(const struct sk_buff *, u32, void *, u32, u32);
	bool gpl_only;
	int ret_type, arg1_type, arg2_type, arg3_type, arg4_type, arg5_type;
};

#include "subject.h"

_Static_assert(BPF_FUNC_skb_load_bytes_relative == 68, "existing helper ABI");

#define CHECK(x) do { if (!(x)) { \
	fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); \
} } while (0)

static void check_read(struct sk_buff *skb, u32 offset, u32 length, u32 base,
		       const u8 *expected, int error)
{
	u8 output[130];
	u32 i;

	CHECK(length <= 128);
	memset(output, 0xa5, sizeof(output));
	CHECK((int64_t)bpf_skb_load_bytes_relative_proto.func(skb, offset,
		output + 1, length, base) == error);
	CHECK(output[0] == 0xa5 && output[length + 1] == 0xa5);
	for (i = 0; i < length; i++)
		CHECK(output[i + 1] == (error ? 0 : expected[i]));
}

int main(int argc, char **argv)
{
	/* Large backing storage also makes stale/unset header arithmetic defined
	 * in the historical negative controls. Only [8,72) is linear packet data.
	 */
	u8 *packet = calloc(131200, 1);
	struct sk_buff skb = { .head = packet, .data = packet + 8,
		.tail = 72, .len = 64, .data_len = 0,
		.mac_header = 8, .network_header = 22 };
	const u8 mac[] = { 8, 9, 10, 11 };
	const u8 net[] = { 22, 23, 24, 25 };
	const u8 shifted[] = { 24, 25, 26, 27 };
	const u8 tail[] = { 68, 69, 70, 71 };
	const u8 far[] = { 4, 3, 2, 1 };
	unsigned int i;

	CHECK(argc == 2 && packet != NULL);
	for (i = 0; i < 72; i++)
		packet[i] = i;
	if (!strcmp(argv[1], "headers")) {
		check_read(&skb, 0, 4, BPF_HDR_START_MAC, mac, 0);
		check_read(&skb, 0, 4, BPF_HDR_START_NET, net, 0);
		check_read(&skb, 2, 4, BPF_HDR_START_NET, shifted, 0);
	} else if (!strcmp(argv[1], "pulled")) {
		skb.data = packet + 70;
		skb.len = 2;
		check_read(&skb, 0, 4, BPF_HDR_START_MAC, mac, 0);
		check_read(&skb, 0, 4, BPF_HDR_START_NET, net, 0);
	} else if (!strcmp(argv[1], "unset-net")) {
		skb.mac_header = UINT16_MAX;
		check_read(&skb, 0, 4, BPF_HDR_START_NET, net, 0);
	} else if (!strcmp(argv[1], "unset-mac")) {
		skb.mac_header = UINT16_MAX;
		check_read(&skb, 0, 4, BPF_HDR_START_MAC, NULL, -EFAULT);
	} else if (!strcmp(argv[1], "tail")) {
		check_read(&skb, 60, 4, BPF_HDR_START_MAC, tail, 0);
		check_read(&skb, 46, 4, BPF_HDR_START_NET, tail, 0);
	} else if (!strcmp(argv[1], "max-offset")) {
		skb.tail = 65561;
		skb.len = 65553;
		memcpy(packet + 65557, far, sizeof(far));
		check_read(&skb, 65535, 4, BPF_HDR_START_NET, far, 0);
	} else if (!strcmp(argv[1], "nonlinear")) {
		skb.len = 164;
		skb.data_len = 100;
		check_read(&skb, 60, 4, BPF_HDR_START_MAC, tail, 0);
		check_read(&skb, 60, 5, BPF_HDR_START_MAC, NULL, -EFAULT);
	} else if (!strcmp(argv[1], "invalid")) {
		check_read(&skb, 0, 4, 2, NULL, -EFAULT);
		check_read(&skb, 65536, 4, BPF_HDR_START_MAC, NULL, -EFAULT);
		check_read(&skb, UINT32_MAX, 4, BPF_HDR_START_NET, NULL, -EFAULT);
		check_read(&skb, 65535, 4, BPF_HDR_START_NET, NULL, -EFAULT);
		check_read(&skb, 61, 4, BPF_HDR_START_MAC, NULL, -EFAULT);
		check_read(&skb, 47, 4, BPF_HDR_START_NET, NULL, -EFAULT);
		check_read(&skb, 0, 65, BPF_HDR_START_MAC, NULL, -EFAULT);
		check_read(&skb, 0, 128, BPF_HDR_START_NET, NULL, -EFAULT);
	} else {
		CHECK(0);
	}
	free(packet);
	return 0;
}
