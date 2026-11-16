/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _FSCRYPT_REGISTRY_H
#define _FSCRYPT_REGISTRY_H
#include <linux/fs.h>
#include "master_key.h"

/* Internal only: no ioctl or legacy-consumer activation in this dependency.
 * Caller keeps sb alive through each call and must not hold a master lease
 * while calling ADD. Returned core references require fscrypt_mk_put(); they
 * do not pin sb or executable module text. Future inode consumers retain their
 * inode/superblock and fscrypt module dependency through all core operations.
 *
 * Lookup returns a stable core even when its secret is removed. Only -ENOENT
 * denotes actual absence; all key-service errors retain their original errno.
 * No registry API invalidates or unlinks an entry before superblock teardown.
 */
struct fscrypt_master_key *fscrypt_registry_lookup(struct super_block *sb,
						 const u8 *descriptor);
int fscrypt_registry_add(struct super_block *sb, const u8 *descriptor,
			 const u8 *raw, size_t size);
int fscrypt_registry_init(void);
void fscrypt_registry_exit(void);
#endif
