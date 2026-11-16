// SPDX-License-Identifier: GPL-2.0
/*
 * Filesystem-level fscrypt master key management ioctls and VFS reclaim.
 *
 * Copyright 2019 Google LLC
 *
 * Huawei adaptation: exposes upstream-compatible descriptor key-management
 * ioctls over the internal superblock keyring registry and reclaims clean
 * unreferenced inodes on key removal without adding an intrusive list_head
 * to fscrypt_mk_owner.
 */
#include <linux/bug.h>
#include <linux/capability.h>
#include <linux/dcache.h>
#include <linux/export.h>
#include <linux/fs.h>
#define __FS_HAS_ENCRYPTION 1
#include <linux/fscrypt.h>
#include <linux/fscrypt_common.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <uapi/linux/fscrypt.h>
#include "registry.h"

static int validate_key_spec(const struct fscrypt_key_specifier *spec)
{
	if (spec->__reserved)
		return -EINVAL;
	switch (spec->type) {
	case FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR:
		if (memchr_inv(spec->u.__reserved + FS_KEY_DESCRIPTOR_SIZE,
			       0, sizeof(spec->u.__reserved) -
			       FS_KEY_DESCRIPTOR_SIZE))
			return -EINVAL;
		return 0;
	case FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER:
		if (memchr_inv(spec->u.__reserved + FSCRYPT_KEY_IDENTIFIER_SIZE,
			       0, sizeof(spec->u.__reserved) -
			       FSCRYPT_KEY_IDENTIFIER_SIZE))
			return -EINVAL;
		return -EOPNOTSUPP;
	default:
		return -EINVAL;
	}
}

int fscrypt_ioctl_add_key(struct file *filp, void __user *_uarg)
{
	struct super_block *sb = file_inode(filp)->i_sb;
	struct fscrypt_add_key_arg __user *uarg = _uarg;
	struct fscrypt_add_key_arg arg;
	u8 raw[FSCRYPT_MK_RAW_SIZE];
	int spec_err;
	int err;

	BUILD_BUG_ON(sizeof(struct fscrypt_key_specifier) != 40);
	BUILD_BUG_ON(sizeof(struct fscrypt_add_key_arg) != 80);
	BUILD_BUG_ON(offsetof(struct fscrypt_add_key_arg, raw) != 80);

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;

	spec_err = validate_key_spec(&arg.key_spec);
	if (spec_err && spec_err != -EOPNOTSUPP)
		return spec_err;

	if (memchr_inv(arg.__reserved, 0, sizeof(arg.__reserved)))
		return -EINVAL;

	if (arg.key_id && arg.raw_size)
		return -EINVAL;

	if (spec_err == -EOPNOTSUPP || arg.flags || arg.__flags || arg.key_id)
		return -EOPNOTSUPP;

	if (arg.raw_size != FSCRYPT_MK_RAW_SIZE)
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	if (copy_from_user(raw, uarg->raw, sizeof(raw))) {
		memzero_explicit(raw, sizeof(raw));
		return -EFAULT;
	}

	err = fscrypt_registry_add(sb, arg.key_spec.u.descriptor,
				   raw, sizeof(raw));
	memzero_explicit(raw, sizeof(raw));
	return err;
}
EXPORT_SYMBOL_GPL(fscrypt_ioctl_add_key);

static void shrink_dcache_inode(struct inode *inode)
{
	struct dentry *dentry;

	if (S_ISDIR(inode->i_mode)) {
		dentry = d_find_any_alias(inode);
		if (dentry) {
			shrink_dcache_parent(dentry);
			dput(dentry);
		}
	}
	d_prune_aliases(inode);
}

static void evict_dentries_for_decrypted_inodes(struct super_block *sb,
						struct fscrypt_master_key *mk,
						u64 retired_gen)
{
	struct inode *inode;
	struct inode *toput_inode = NULL;
	const struct fscrypt_info *ci;

	/*
	 * Hold the current inode alive across lock release and dentry shrink
	 * so list_for_each_entry stays linked until next step puts toput_inode.
	 */
	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		spin_lock(&inode->i_lock);
		if (inode->i_state & (I_FREEING | I_WILL_FREE | I_NEW)) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		/*
		 * Pairs with cmpxchg(&inode->i_crypt_info, NULL, ci) release
		 * barrier when publishing ci_owner.
		 */
		ci = smp_load_acquire(&inode->i_crypt_info);
		if (!fscrypt_ci_is_managed(ci) ||
		    ci->ci_owner.key != mk ||
		    ci->ci_owner.generation > retired_gen) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		__iget(inode);
		spin_unlock(&inode->i_lock);
		spin_unlock(&sb->s_inode_list_lock);

		shrink_dcache_inode(inode);
		iput(toput_inode);
		toput_inode = inode;

		cond_resched();
		spin_lock(&sb->s_inode_list_lock);
	}
	spin_unlock(&sb->s_inode_list_lock);
	iput(toput_inode);
}

static bool has_retired_busy_owners(struct super_block *sb,
				    struct fscrypt_master_key *mk,
				    u64 retired_gen)
{
	struct inode *inode;
	const struct fscrypt_info *ci;
	bool busy = false;

	if (!atomic_read(&mk->owners))
		return false;

	/* Fast path when generation has not advanced from concurrent re-ADD. */
	if (!READ_ONCE(mk->present) || READ_ONCE(mk->generation) == retired_gen)
		return true;

	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		spin_lock(&inode->i_lock);
		if (!(inode->i_state & (I_FREEING | I_WILL_FREE | I_NEW))) {
			/*
			 * Pairs with cmpxchg(&inode->i_crypt_info, NULL, ci)
			 * release barrier when publishing ci_owner.
			 */
			ci = smp_load_acquire(&inode->i_crypt_info);
			if (fscrypt_ci_is_managed(ci) &&
			    ci->ci_owner.key == mk &&
			    ci->ci_owner.generation <= retired_gen) {
				busy = true;
				spin_unlock(&inode->i_lock);
				break;
			}
		}
		spin_unlock(&inode->i_lock);
	}
	spin_unlock(&sb->s_inode_list_lock);
	return busy;
}

static int try_to_lock_encrypted_files(struct super_block *sb,
				       struct fscrypt_master_key *mk,
				       u64 retired_gen)
{
	int err1;
	int err2;

	down_read(&sb->s_umount);
	err1 = sync_filesystem(sb);
	up_read(&sb->s_umount);

	evict_dentries_for_decrypted_inodes(sb, mk, retired_gen);
	err2 = has_retired_busy_owners(sb, mk, retired_gen) ? -EBUSY : 0;
	return err1 ?: err2;
}

static int do_remove_key(struct file *filp, void __user *_uarg, bool all_users)
{
	struct super_block *sb = file_inode(filp)->i_sb;
	struct fscrypt_remove_key_arg __user *uarg = _uarg;
	struct fscrypt_remove_key_arg arg;
	struct fscrypt_master_key *mk;
	u32 status_flags = 0;
	bool has_owners = false;
	u64 retired_gen = 0;
	int spec_err;
	int err;

	BUILD_BUG_ON(sizeof(struct fscrypt_remove_key_arg) != 64);

	(void)all_users;
	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;

	spec_err = validate_key_spec(&arg.key_spec);
	if (spec_err && spec_err != -EOPNOTSUPP)
		return spec_err;

	if (memchr_inv(arg.__reserved, 0, sizeof(arg.__reserved)))
		return -EINVAL;

	if (spec_err == -EOPNOTSUPP)
		return -EOPNOTSUPP;

	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	mk = fscrypt_registry_lookup(sb, arg.key_spec.u.descriptor);
	if (IS_ERR(mk)) {
		err = PTR_ERR(mk);
		return err == -ENOENT ? -ENOKEY : err;
	}

	err = fscrypt_mk_begin_remove(mk, &has_owners, &retired_gen);
	if (err) {
		fscrypt_mk_put(mk);
		return err;
	}

	if (has_owners) {
		err = try_to_lock_encrypted_files(sb, mk, retired_gen);
		if (err == -EBUSY) {
			status_flags |=
				FSCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY;
			err = 0;
		}
	}
	fscrypt_mk_put(mk);
	if (err == 0 && put_user(status_flags, &uarg->removal_status_flags))
		err = -EFAULT;
	return err;
}

int fscrypt_ioctl_remove_key(struct file *filp, void __user *uarg)
{
	return do_remove_key(filp, uarg, false);
}
EXPORT_SYMBOL_GPL(fscrypt_ioctl_remove_key);

int fscrypt_ioctl_remove_key_all_users(struct file *filp, void __user *uarg)
{
	return do_remove_key(filp, uarg, true);
}
EXPORT_SYMBOL_GPL(fscrypt_ioctl_remove_key_all_users);

int fscrypt_ioctl_get_key_status(struct file *filp, void __user *_uarg)
{
	struct super_block *sb = file_inode(filp)->i_sb;
	struct fscrypt_get_key_status_arg __user *uarg = _uarg;
	struct fscrypt_get_key_status_arg arg;
	struct fscrypt_master_key *mk;
	int spec_err;
	int err = 0;

	BUILD_BUG_ON(sizeof(struct fscrypt_get_key_status_arg) != 128);

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;

	spec_err = validate_key_spec(&arg.key_spec);
	if (spec_err && spec_err != -EOPNOTSUPP)
		return spec_err;

	if (memchr_inv(arg.__reserved, 0, sizeof(arg.__reserved)))
		return -EINVAL;

	if (spec_err == -EOPNOTSUPP)
		return -EOPNOTSUPP;

	arg.status_flags = 0;
	arg.user_count = 0;
	memset(arg.__out_reserved, 0, sizeof(arg.__out_reserved));

	mk = fscrypt_registry_lookup(sb, arg.key_spec.u.descriptor);
	if (IS_ERR(mk)) {
		err = PTR_ERR(mk);
		if (err != -ENOENT)
			return err;
		arg.status = FSCRYPT_KEY_STATUS_ABSENT;
		err = 0;
		goto out;
	}

	switch (fscrypt_mk_status(mk)) {
	case FSCRYPT_MK_PRESENT:
		arg.status = FSCRYPT_KEY_STATUS_PRESENT;
		break;
	case FSCRYPT_MK_BUSY:
		arg.status = FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED;
		break;
	case FSCRYPT_MK_ABSENT:
		arg.status = FSCRYPT_KEY_STATUS_ABSENT;
		break;
	}
	fscrypt_mk_put(mk);
out:
	if (!err && copy_to_user(uarg, &arg, sizeof(arg)))
		err = -EFAULT;
	return err;
}
EXPORT_SYMBOL_GPL(fscrypt_ioctl_get_key_status);
