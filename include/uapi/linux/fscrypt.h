/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Modern fscrypt key-management user API for Huawei 4.14 kernel.
 *
 * Legacy FS_IOC_{SET,GET}_ENCRYPTION_POLICY and FS_IOC_GET_ENCRYPTION_PWSALT
 * definitions remain in <linux/fs.h>.
 */
#ifndef _UAPI_LINUX_FSCRYPT_H
#define _UAPI_LINUX_FSCRYPT_H

#include <linux/ioctl.h>
#include <linux/types.h>

#ifndef FSCRYPT_POLICY_V1
#define FSCRYPT_POLICY_V1			0
#endif
#ifndef FSCRYPT_KEY_DESCRIPTOR_SIZE
#define FSCRYPT_KEY_DESCRIPTOR_SIZE		8
#endif
#ifndef FSCRYPT_MAX_KEY_SIZE
#define FSCRYPT_MAX_KEY_SIZE			64
#endif
#ifndef FSCRYPT_POLICY_V2
#define FSCRYPT_POLICY_V2			2
#endif
#ifndef FSCRYPT_KEY_IDENTIFIER_SIZE
#define FSCRYPT_KEY_IDENTIFIER_SIZE		16
#endif

/*
 * v1 policy keys are specified by an arbitrary 8-byte key "descriptor".
 * v2 policy keys are specified by a 16-byte key "identifier".
 */
#define FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR	1
#define FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER	2

struct fscrypt_key_specifier {
	__u32 type;	/* one of FSCRYPT_KEY_SPEC_TYPE_* */
	__u32 __reserved;
	union {
		__u8 __reserved[32]; /* reserve some extra space */
		__u8 descriptor[FSCRYPT_KEY_DESCRIPTOR_SIZE];
		__u8 identifier[FSCRYPT_KEY_IDENTIFIER_SIZE];
	} u;
};

struct fscrypt_provisioning_key_payload {
	__u32 type;
	__u32 __reserved;
	__u8 raw[];
};

/* Struct passed to FS_IOC_ADD_ENCRYPTION_KEY */
struct fscrypt_add_key_arg {
	struct fscrypt_key_specifier key_spec;
	__u32 raw_size;
	__u32 key_id;
#define FSCRYPT_ADD_KEY_FLAG_HW_WRAPPED		0x00000001
	__u32 flags;
	__u32 __reserved[6];
#define __FSCRYPT_ADD_KEY_FLAG_HW_WRAPPED	0x00000001
	__u32 __flags;
	__u8 raw[];
};

/* Struct passed to FS_IOC_REMOVE_ENCRYPTION_KEY */
struct fscrypt_remove_key_arg {
	struct fscrypt_key_specifier key_spec;
#define FSCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY	0x00000001
#define FSCRYPT_KEY_REMOVAL_STATUS_FLAG_OTHER_USERS	0x00000002
	__u32 removal_status_flags;	/* output */
	__u32 __reserved[5];
};

/* Struct passed to FS_IOC_GET_ENCRYPTION_KEY_STATUS */
struct fscrypt_get_key_status_arg {
	/* input */
	struct fscrypt_key_specifier key_spec;
	__u32 __reserved[6];

	/* output */
#define FSCRYPT_KEY_STATUS_ABSENT		1
#define FSCRYPT_KEY_STATUS_PRESENT		2
#define FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED	3
	__u32 status;
#define FSCRYPT_KEY_STATUS_FLAG_ADDED_BY_SELF	0x00000001
	__u32 status_flags;
	__u32 user_count;
	__u32 __out_reserved[13];
};

#define FS_IOC_ADD_ENCRYPTION_KEY \
	_IOWR('f', 23, struct fscrypt_add_key_arg)
#define FS_IOC_REMOVE_ENCRYPTION_KEY \
	_IOWR('f', 24, struct fscrypt_remove_key_arg)
#define FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS \
	_IOWR('f', 25, struct fscrypt_remove_key_arg)
#define FS_IOC_GET_ENCRYPTION_KEY_STATUS \
	_IOWR('f', 26, struct fscrypt_get_key_status_arg)

#endif /* _UAPI_LINUX_FSCRYPT_H */
