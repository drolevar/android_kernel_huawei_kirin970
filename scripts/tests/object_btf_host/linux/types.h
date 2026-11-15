/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OBJECT_BTF_HOST_TYPES_H
#define OBJECT_BTF_HOST_TYPES_H
#include <stdint.h>
typedef uint8_t __u8;
typedef int8_t __s8;
typedef uint16_t __u16;
typedef int16_t __s16;
typedef uint32_t __u32;
typedef int32_t __s32;
typedef unsigned long long __u64;
typedef long long __s64;
typedef __u16 __be16, __le16, __sum16;
typedef __u32 __be32, __le32, __wsum;
typedef __u64 __be64, __le64;
#define __aligned_u64 __u64 __attribute__((aligned(8)))
#define __aligned_be64 __be64 __attribute__((aligned(8)))
#define __aligned_le64 __le64 __attribute__((aligned(8)))
#endif
