/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FSCRYPT_REGISTRY_H
#define _LINUX_FSCRYPT_REGISTRY_H
#include <linux/fs.h>
#include <linux/key.h>
#include <linux/module.h>

/* VFS-owned teardown: no built-in call into a possibly modular fscrypt.
 * destroy_super() runs after all registry users have released their sb refs.
 * Key GC may be deferred; unregister_key_type() drains type callbacks before
 * fscrypt module exit returns. Never call this while the sb is still in use.
 */
static inline void fscrypt_registry_sb_free(struct super_block *sb)
{
#if IS_ENABLED(CONFIG_FS_ENCRYPTION)
	key_put(sb->s_fscrypt_keys);
	sb->s_fscrypt_keys = NULL;
	module_put(sb->s_fscrypt_keys_owner);
	sb->s_fscrypt_keys_owner = NULL;
#endif
}
#endif
