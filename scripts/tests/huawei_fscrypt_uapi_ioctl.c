// SPDX-License-Identifier: GPL-2.0
/*
 * Host ASan/UBSan verification harness for Huawei fscrypt UAPI ioctls,
 * VFS inode/dentry reclaim on key removal, generation retirement, and
 * test_dummy_encryption AES-GCM key derivation.
 */
#include "uapi_host_shim.h"

static void model_evict_inode(struct inode *inode)
{
	struct fscrypt_info *ci = inode->i_crypt_info;

	spin_lock(&inode->i_sb->s_inode_list_lock);
	list_del_init(&inode->i_sb_list);
	spin_unlock(&inode->i_sb->s_inode_list_lock);
	if (ci) {
		fscrypt_mk_drop_owner(&ci->ci_owner);
		crypto_free_aead(ci->ci_gtfm);
		kfree(ci);
		inode->i_crypt_info = NULL;
	}
	inode->evicted = true;
}

static struct super_operations ext4_test_sops = {
	.drop_inode = ext4_drop_inode,
};
static struct super_operations f2fs_test_sops = {
	.drop_inode = f2fs_drop_inode,
};
static struct super_operations hmfs_test_sops = {
	.drop_inode = hmfs_drop_inode,
};

static bool sb_dummy_context(struct inode *inode)
{
	return inode->dummy_unencrypted;
}
static bool sb_is_encrypted(struct inode *inode)
{
	return inode->has_ctx;
}
static int sb_get_context(struct inode *inode, void *buf, size_t len)
{
	if (!inode->has_ctx)
		return -ENODATA;
	CHECK(len == sizeof(inode->ctx));
	memcpy(buf, &inode->ctx, len);
	return (int)len;
}
static const struct fscrypt_operations test_cops = {
	.key_prefix = "f2fs:",
	.get_context = sb_get_context,
	.dummy_context = sb_dummy_context,
	.is_encrypted = sb_is_encrypted,
};

static void sb_init(struct super_block *sb,
		    const struct super_operations *sops, bool has_encrypt)
{
	memset(sb, 0, sizeof(*sb));
	snprintf(sb->s_id, sizeof(sb->s_id), "loop0");
	spin_lock_init(&sb->s_inode_list_lock);
	INIT_LIST_HEAD(&sb->s_inodes);
	init_rwsem(&sb->s_umount);
	sb->s_op = sops;
	sb->s_cop = &test_cops;
	sb->has_encrypt = has_encrypt;
}

static void sb_teardown(struct super_block *sb)
{
	struct inode *all[64];
	size_t n = 0;
	struct inode *inode;

	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		CHECK(n < ARRAY_SIZE(all));
		all[n++] = inode;
	}
	for (size_t i = 0; i < n; i++) {
		all[i]->i_nlink = 0;
		while (all[i]->open_refs > 0) {
			all[i]->open_refs--;
			iput(all[i]);
		}
	}
	for (size_t i = 0; i < n; i++) {
		struct dentry *d;

		if (all[i]->evicted)
			continue;
		d = d_find_any_alias(all[i]);
		if (d && !d->d_parent) {
			d->pin_count = 0;
			shrink_dcache_parent(d);
			d_prune_aliases(all[i]);
		}
	}
	for (size_t i = 0; i < n; i++) {
		while (!all[i]->evicted && !list_empty(&all[i]->dentries)) {
			struct dentry *d = list_first_entry(&all[i]->dentries,
							    struct dentry,
							    d_alias);

			d->pin_count = 0;
			drop_dentry(d);
		}
		if (!all[i]->evicted) {
			if (atomic_read(&all[i]->i_count) > 0) {
				atomic_set(&all[i]->i_count, 1);
				iput(all[i]);
			} else {
				model_evict_inode(all[i]);
			}
		}
		free(all[i]);
	}
	if (sb->s_fscrypt_keys) {
		key_put(sb->s_fscrypt_keys);
		sb->s_fscrypt_keys = NULL;
	}
	if (sb->s_fscrypt_keys_owner) {
		module_put(sb->s_fscrypt_keys_owner);
		sb->s_fscrypt_keys_owner = NULL;
	}
	destroy_rwsem(&sb->s_umount);
}

static struct inode *inode_alloc(struct super_block *sb, unsigned long ino,
				 umode_t mode)
{
	struct inode *inode = calloc(1, sizeof(*inode));

	CHECK(inode);
	inode->i_ino = ino;
	inode->i_mode = mode;
	inode->i_nlink = 1;
	inode->i_sb = sb;
	atomic_set(&inode->i_count, 0);
	spin_lock_init(&inode->i_lock);
	INIT_LIST_HEAD(&inode->i_sb_list);
	INIT_LIST_HEAD(&inode->dentries);
	spin_lock(&sb->s_inode_list_lock);
	list_add_tail(&inode->i_sb_list, &sb->s_inodes);
	spin_unlock(&sb->s_inode_list_lock);
	return inode;
}

static struct dentry *dentry_attach(struct inode *inode, struct dentry *parent,
				    int pin_count)
{
	struct dentry *d = calloc(1, sizeof(*d));

	CHECK(d);
	d->d_parent = parent;
	d->d_inode = inode;
	d->pin_count = pin_count;
	INIT_LIST_HEAD(&d->d_children);
	INIT_LIST_HEAD(&d->d_child);
	INIT_LIST_HEAD(&d->d_alias);
	if (parent)
		list_add_tail(&d->d_child, &parent->d_children);
	list_add_tail(&d->d_alias, &inode->dentries);
	atomic_inc(&inode->i_count);
	return d;
}

static void inode_open_fd(struct inode *inode)
{
	inode->open_refs++;
	atomic_inc(&inode->i_count);
}

static void inode_close_fd(struct inode *inode)
{
	CHECK(inode->open_refs > 0);
	inode->open_refs--;
	iput(inode);
}

static int enroll_inode_owner(struct inode *inode, const u8 *desc)
{
	struct fscrypt_master_key *mk = fscrypt_registry_lookup(inode->i_sb,
								desc);
	struct fscrypt_mk_lease lease = { 0 };
	struct fscrypt_info *ci;
	int err;

	if (IS_ERR(mk))
		return (int)PTR_ERR(mk);
	err = fscrypt_mk_acquire(mk, 0, &lease);
	fscrypt_mk_put(mk);
	if (err)
		return err;
	ci = kzalloc(sizeof(*ci), GFP_NOFS);
	CHECK(ci);
	err = fscrypt_mk_enroll(&lease, &ci->ci_owner);
	fscrypt_mk_release(&lease);
	CHECK(!err);
	memcpy(ci->ci_master_key, desc, FS_KEY_DESCRIPTOR_SIZE);
	/* Pairs with smp_load_acquire(&inode->i_crypt_info) in reclaim. */
	smp_store_release(&inode->i_crypt_info, ci);
	return 0;
}

static void free_evicted_inodes(struct inode **list, size_t n)
{
	for (size_t i = 0; i < n; i++)
		free(list[i]);
}

static void make_key_bytes(u8 *raw, u8 seed, u8 *desc, u8 dseed)
{
	for (size_t i = 0; i < 64; i++)
		raw[i] = (u8)(seed + i);
	for (size_t i = 0; i < 8; i++)
		desc[i] = (u8)(dseed + i);
}

static struct fscrypt_add_key_arg *alloc_add_arg(const u8 *desc, const u8 *raw,
						 u32 raw_size)
{
	struct fscrypt_add_key_arg *arg = calloc(1, sizeof(*arg) + raw_size);

	CHECK(arg);
	arg->key_spec.type = FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR;
	memcpy(arg->key_spec.u.descriptor, desc, FS_KEY_DESCRIPTOR_SIZE);
	arg->raw_size = raw_size;
	if (raw && raw_size)
		memcpy(arg->raw, raw, raw_size);
	return arg;
}

static int do_ioctl_add(struct file *filp, const u8 *desc, const u8 *raw)
{
	struct fscrypt_add_key_arg *arg = alloc_add_arg(desc, raw, 64);
	int err = fscrypt_ioctl_add_key(filp, arg);

	free(arg);
	return err;
}

static int do_ioctl_remove(struct file *filp, const u8 *desc, u32 *flags_out,
			   bool all_users)
{
	struct fscrypt_remove_key_arg arg;
	int err;

	memset(&arg, 0, sizeof(arg));
	arg.key_spec.type = FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR;
	memcpy(arg.key_spec.u.descriptor, desc, FS_KEY_DESCRIPTOR_SIZE);
	err = all_users ? fscrypt_ioctl_remove_key_all_users(filp, &arg) :
			  fscrypt_ioctl_remove_key(filp, &arg);
	if (flags_out)
		*flags_out = arg.removal_status_flags;
	return err;
}

static int do_ioctl_status(struct file *filp, const u8 *desc,
			   struct fscrypt_get_key_status_arg *out)
{
	memset(out, 0, sizeof(*out));
	out->key_spec.type = FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR;
	memcpy(out->key_spec.u.descriptor, desc, FS_KEY_DESCRIPTOR_SIZE);
	return fscrypt_ioctl_get_key_status(filp, out);
}

static void install_legacy_logon_key(const u8 *desc, const u8 *raw)
{
	char full[2 * FS_KEY_DESCRIPTOR_SIZE + FS_KEY_DESC_PREFIX_SIZE + 1];
	struct fscrypt_key fk;

	memcpy(full, FS_KEY_DESC_PREFIX, FS_KEY_DESC_PREFIX_SIZE);
	*bin2hex(full + FS_KEY_DESC_PREFIX_SIZE, desc,
		 FS_KEY_DESCRIPTOR_SIZE) = '\0';
	legacy_logon_key = new_test_key(&key_type_logon, full, false,
					KEY_POS_SEARCH);
	legacy_logon_key->positive = true;
	legacy_logon_key->rcu_payload =
		calloc(1, sizeof(struct user_key_payload));
	CHECK(legacy_logon_key->rcu_payload);
	memset(&fk, 0, sizeof(fk));
	fk.size = 64;
	memcpy(fk.raw, raw, 64);
	legacy_logon_key->rcu_payload->datalen = sizeof(fk);
	memcpy(legacy_logon_key->rcu_payload->data, &fk, sizeof(fk));
}

static void drop_legacy_logon_key(void)
{
	if (legacy_logon_key) {
		key_put(legacy_logon_key);
		legacy_logon_key = NULL;
	}
}

static void case_uapi_abi_parity(void)
{
	CHECK(sizeof(struct fscrypt_key_specifier) == 40);
	CHECK(sizeof(struct fscrypt_add_key_arg) == 80);
	CHECK(offsetof(struct fscrypt_add_key_arg, key_spec) == 0);
	CHECK(offsetof(struct fscrypt_add_key_arg, raw_size) == 40);
	CHECK(offsetof(struct fscrypt_add_key_arg, key_id) == 44);
	CHECK(offsetof(struct fscrypt_add_key_arg, flags) == 48);
	CHECK(offsetof(struct fscrypt_add_key_arg, __flags) == 76);
	CHECK(offsetof(struct fscrypt_add_key_arg, raw) == 80);
	CHECK(sizeof(struct fscrypt_remove_key_arg) == 64);
	CHECK(offsetof(struct fscrypt_remove_key_arg,
		       removal_status_flags) == 40);
	CHECK(sizeof(struct fscrypt_get_key_status_arg) == 128);
	CHECK(offsetof(struct fscrypt_get_key_status_arg, status) == 64);
	CHECK(offsetof(struct fscrypt_get_key_status_arg, status_flags) == 68);
	CHECK(offsetof(struct fscrypt_get_key_status_arg, user_count) == 72);
#ifdef HAS_BIONIC_UAPI
	CHECK(sizeof(struct fscrypt_key_specifier) ==
	      sizeof(struct bionic_fscrypt_key_specifier));
	CHECK(sizeof(struct fscrypt_add_key_arg) ==
	      sizeof(struct bionic_fscrypt_add_key_arg));
	CHECK(offsetof(struct fscrypt_add_key_arg, __flags) ==
	      offsetof(struct bionic_fscrypt_add_key_arg, __flags));
	CHECK(offsetof(struct fscrypt_add_key_arg, raw) ==
	      offsetof(struct bionic_fscrypt_add_key_arg, raw));
	CHECK(sizeof(struct fscrypt_remove_key_arg) ==
	      sizeof(struct bionic_fscrypt_remove_key_arg));
	CHECK(sizeof(struct fscrypt_get_key_status_arg) ==
	      sizeof(struct bionic_fscrypt_get_key_status_arg));
	CHECK(FS_IOC_ADD_ENCRYPTION_KEY == BIONIC_FS_IOC_ADD_ENCRYPTION_KEY);
	CHECK(FS_IOC_REMOVE_ENCRYPTION_KEY ==
	      BIONIC_FS_IOC_REMOVE_ENCRYPTION_KEY);
	CHECK(FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS ==
	      BIONIC_FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS);
	CHECK(FS_IOC_GET_ENCRYPTION_KEY_STATUS ==
	      BIONIC_FS_IOC_GET_ENCRYPTION_KEY_STATUS);
#endif
}

static void case_add_status_remove_clean(void)
{
	struct super_block sb;
	struct inode *root;
	struct dentry *root_d;
	struct file filp;
	struct fscrypt_get_key_status_arg st;
	u8 raw[64], desc[8];
	u32 rflags = 99;

	sb_init(&sb, &ext4_test_sops, true);
	root = inode_alloc(&sb, 2, S_IFDIR | 0755);
	root_d = dentry_attach(root, NULL, 1);
	filp.f_inode = root;
	make_key_bytes(raw, 0x10, desc, 0x20);

	CHECK(do_ioctl_status(&filp, desc, &st) == 0);
	CHECK(st.status == FSCRYPT_KEY_STATUS_ABSENT);
	CHECK(do_ioctl_remove(&filp, desc, &rflags, false) == -ENOKEY);
	CHECK(do_ioctl_add(&filp, desc, raw) == 0);
	st.status_flags = 0x55;
	st.user_count = 7;
	CHECK(do_ioctl_status(&filp, desc, &st) == 0);
	CHECK(st.status == FSCRYPT_KEY_STATUS_PRESENT);
	CHECK(st.status_flags == 0 && st.user_count == 0);
	CHECK(do_ioctl_remove(&filp, desc, &rflags, false) == 0);
	CHECK(rflags == 0);
	CHECK(do_ioctl_status(&filp, desc, &st) == 0);
	CHECK(st.status == FSCRYPT_KEY_STATUS_ABSENT);
	CHECK(do_ioctl_remove(&filp, desc, &rflags, false) == -ENOKEY);

	root_d->pin_count = 0;
	sb_teardown(&sb);
}

static void case_idempotent_and_conflicting_readd(void)
{
	struct super_block sb;
	struct inode *root, *f1;
	struct dentry *root_d;
	struct file filp;
	struct fscrypt_master_key *mk;
	u8 raw1[64], raw2[64], desc[8];
	u32 rflags = 0;

	sb_init(&sb, &f2fs_test_sops, true);
	root = inode_alloc(&sb, 2, S_IFDIR | 0755);
	root_d = dentry_attach(root, NULL, 1);
	filp.f_inode = root;
	make_key_bytes(raw1, 0x11, desc, 0x21);
	make_key_bytes(raw2, 0x77, desc, 0x21);

	CHECK(do_ioctl_add(&filp, desc, raw1) == 0);
	CHECK(do_ioctl_add(&filp, desc, raw1) == 0);
	CHECK(do_ioctl_add(&filp, desc, raw2) == -EKEYREJECTED);

	f1 = inode_alloc(&sb, 10, S_IFREG | 0644);
	(void)dentry_attach(f1, root_d, 0);
	inode_open_fd(f1);
	CHECK(enroll_inode_owner(f1, desc) == 0);

	mk = fscrypt_registry_lookup(&sb, desc);
	CHECK(!IS_ERR(mk) && mk->generation == 1);
	fscrypt_mk_put(mk);

	CHECK(do_ioctl_remove(&filp, desc, &rflags, false) == 0);
	CHECK(rflags == FSCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY);
	CHECK(do_ioctl_add(&filp, desc, raw2) == -EKEYREJECTED);
	CHECK(do_ioctl_add(&filp, desc, raw1) == 0);

	mk = fscrypt_registry_lookup(&sb, desc);
	CHECK(!IS_ERR(mk) && mk->generation == 2);
	fscrypt_mk_put(mk);

	inode_close_fd(f1);
	free(f1);
	root_d->pin_count = 0;
	sb_teardown(&sb);
}

static void case_busy_inode_retry_lifecycle(void)
{
	struct super_block sb;
	struct inode *root, *busy;
	struct dentry *root_d;
	struct file filp;
	struct fscrypt_get_key_status_arg st;
	u8 raw[64], desc[8];
	u32 rflags = 0;

	sb_init(&sb, &ext4_test_sops, true);
	root = inode_alloc(&sb, 2, S_IFDIR | 0755);
	root_d = dentry_attach(root, NULL, 1);
	filp.f_inode = root;
	make_key_bytes(raw, 0x30, desc, 0x40);

	CHECK(do_ioctl_add(&filp, desc, raw) == 0);
	busy = inode_alloc(&sb, 11, S_IFREG | 0644);
	(void)dentry_attach(busy, root_d, 0);
	inode_open_fd(busy);
	CHECK(enroll_inode_owner(busy, desc) == 0);

	CHECK(do_ioctl_remove(&filp, desc, &rflags, false) == 0);
	CHECK(rflags == FSCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY);
	CHECK(!busy->evicted);
	CHECK(do_ioctl_status(&filp, desc, &st) == 0);
	CHECK(st.status == FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED);

	/* Re-attach cached LRU dentry before close to test retry REMOVE */
	(void)dentry_attach(busy, root_d, 0);
	inode_close_fd(busy);
	CHECK(!busy->evicted);

	CHECK(do_ioctl_remove(&filp, desc, &rflags, false) == 0);
	CHECK(rflags == 0);
	CHECK(busy->evicted);
	CHECK(do_ioctl_status(&filp, desc, &st) == 0);
	CHECK(st.status == FSCRYPT_KEY_STATUS_ABSENT);

	free(busy);
	root_d->pin_count = 0;
	sb_teardown(&sb);
}

static void case_dirty_inode_retained_until_sync(void)
{
	struct super_block sb;
	struct inode *root, *dirty;
	struct dentry *root_d;
	struct file filp;
	struct fscrypt_get_key_status_arg st;
	u8 raw[64], desc[8];
	u32 rflags = 0;

	sb_init(&sb, &ext4_test_sops, true);
	root = inode_alloc(&sb, 2, S_IFDIR | 0755);
	root_d = dentry_attach(root, NULL, 1);
	filp.f_inode = root;
	make_key_bytes(raw, 0x50, desc, 0x60);

	CHECK(do_ioctl_add(&filp, desc, raw) == 0);
	dirty = inode_alloc(&sb, 12, S_IFREG | 0644);
	dentry_attach(dirty, root_d, 0);
	dirty->i_state |= I_DIRTY_PAGES;
	CHECK(enroll_inode_owner(dirty, desc) == 0);

	/* Dirty pages survive failed sync: fscrypt_drop_inode retains inode */
	sync_leaves_dirty = true;
	CHECK(do_ioctl_remove(&filp, desc, &rflags, false) == 0);
	sync_leaves_dirty = false;
	CHECK(rflags == FSCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY);
	CHECK(!dirty->evicted);
	CHECK(fscrypt_drop_inode(dirty) == 0);

	/* Re-attach LRU dentry & fail sync: error must propagate */
	dentry_attach(dirty, root_d, 0);
	fail_sync = -EIO;
	CHECK(do_ioctl_remove(&filp, desc, &rflags, false) == -EIO);
	fail_sync = 0;
	CHECK(!dirty->evicted);

	/* Normal sync clears I_DIRTY_ALL and permits clean eviction */
	dentry_attach(dirty, root_d, 0);
	CHECK(do_ioctl_remove(&filp, desc, &rflags, false) == 0);
	CHECK(rflags == 0);
	CHECK(dirty->evicted);
	CHECK(do_ioctl_status(&filp, desc, &st) == 0);
	CHECK(st.status == FSCRYPT_KEY_STATUS_ABSENT);

	free(dirty);
	root_d->pin_count = 0;
	sb_teardown(&sb);
}

static void case_readd_advances_gen_retires_old(void)
{
	struct super_block sb;
	struct inode *root, *old_i, *new_i;
	struct dentry *root_d;
	struct file filp;
	struct fscrypt_master_key *mk;
	u8 raw[64], desc[8];
	u32 rflags = 0;

	sb_init(&sb, &f2fs_test_sops, true);
	root = inode_alloc(&sb, 2, S_IFDIR | 0755);
	root_d = dentry_attach(root, NULL, 1);
	filp.f_inode = root;
	make_key_bytes(raw, 0x70, desc, 0x80);

	CHECK(do_ioctl_add(&filp, desc, raw) == 0);
	old_i = inode_alloc(&sb, 20, S_IFREG | 0644);
	dentry_attach(old_i, root_d, 0);
	inode_open_fd(old_i);
	CHECK(enroll_inode_owner(old_i, desc) == 0);
	CHECK(old_i->i_crypt_info->ci_owner.generation == 1);

	CHECK(do_ioctl_remove(&filp, desc, &rflags, false) == 0);
	CHECK(rflags == FSCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY);
	CHECK(do_ioctl_add(&filp, desc, raw) == 0);

	new_i = inode_alloc(&sb, 21, S_IFREG | 0644);
	dentry_attach(new_i, root_d, 0);
	CHECK(enroll_inode_owner(new_i, desc) == 0);
	CHECK(new_i->i_crypt_info->ci_owner.generation == 2);

	/* New gen-2 inode is valid; old gen-1 inode is retired even now! */
	CHECK(fscrypt_drop_inode(new_i) == 0);
	CHECK(f2fs_drop_inode(new_i) == 0);
	CHECK(fscrypt_drop_inode(old_i) == 1);

	dentry_attach(old_i, root_d, 0);
	inode_close_fd(old_i);
	CHECK(!old_i->evicted);
	/* Trigger drop via dentry shrink as on later reclaim / remove */
	d_prune_aliases(old_i);
	CHECK(old_i->evicted);
	CHECK(!new_i->evicted);

	mk = fscrypt_registry_lookup(&sb, desc);
	CHECK(!IS_ERR(mk) && atomic_read(&mk->owners) == 1);
	fscrypt_mk_put(mk);

	CHECK(do_ioctl_remove(&filp, desc, &rflags, false) == 0);
	CHECK(rflags == 0 && new_i->evicted);

	free(old_i);
	free(new_i);
	root_d->pin_count = 0;
	sb_teardown(&sb);
}

static void case_concurrent_readd_owner_check(void)
{
	struct super_block sb;
	struct inode *root, *old_i, *new_i;
	struct dentry *root_d;
	struct fscrypt_master_key *mk;
	struct file filp;
	u8 raw[64], desc[8];
	bool busy;

	sb_init(&sb, &ext4_test_sops, true);
	root = inode_alloc(&sb, 2, S_IFDIR | 0755);
	root_d = dentry_attach(root, NULL, 1);
	filp.f_inode = root;
	make_key_bytes(raw, 0x90, desc, 0xa0);

	CHECK(do_ioctl_add(&filp, desc, raw) == 0);
	mk = fscrypt_registry_lookup(&sb, desc);
	CHECK(!IS_ERR(mk));

	/*
	 * Busy gen-1 owner survives REMOVE + re-ADD (gen=2): slow scan
	 * must find retired_gen=1 busy until evicted, then false.
	 */
	old_i = inode_alloc(&sb, 29, S_IFREG | 0644);
	(void)dentry_attach(old_i, root_d, 0);
	inode_open_fd(old_i);
	CHECK(enroll_inode_owner(old_i, desc) == 0);
	CHECK(fscrypt_mk_remove(mk));
	CHECK(!fscrypt_mk_add(mk, raw, 64));
	CHECK(has_retired_busy_owners(&sb, mk, 1));
	inode_close_fd(old_i);
	d_prune_aliases(old_i);
	CHECK(old_i->evicted);

	new_i = inode_alloc(&sb, 30, S_IFREG | 0644);
	(void)dentry_attach(new_i, root_d, 0);
	CHECK(enroll_inode_owner(new_i, desc) == 0);
	CHECK(new_i->i_crypt_info->ci_owner.generation == 2);

	/* Gen-2 owner exists, but retired_gen=1 has NO remaining owners */
	busy = has_retired_busy_owners(&sb, mk, 1);
	CHECK(!busy);
	busy = has_retired_busy_owners(&sb, mk, 2);
	CHECK(busy);

	free(old_i);
	fscrypt_mk_put(mk);
	root_d->pin_count = 0;
	sb_teardown(&sb);
}

static void case_tombstone_blocks_legacy_fallback(void)
{
	struct super_block sb;
	struct inode *root, *child;
	struct dentry *root_d;
	struct file filp;
	struct fscrypt_ce_scope *scope = NULL;
	struct fscrypt_context ctx;
	u8 raw[64], desc[8], plain[80], derived[64];
	u32 rflags = 0;

	sb_init(&sb, &f2fs_test_sops, true);
	root = inode_alloc(&sb, 2, S_IFDIR | 0755);
	root_d = dentry_attach(root, NULL, 1);
	child = inode_alloc(&sb, 40, S_IFREG | 0644);
	filp.f_inode = root;
	make_key_bytes(raw, 0xb0, desc, 0xc0);
	install_legacy_logon_key(desc, raw);

	/* Before managed ADD, legacy key works */
	CHECK(fscrypt_check_unmanaged_descriptor(&sb, desc) == 0);
	CHECK(fscrypt_ce_scope_open(child, desc, POLICY_WRAP, &scope) == 0);
	memset(plain, 0x31, FS_KEY_DERIVATION_NONCE_SIZE);
	memset(plain + FS_KEY_DERIVATION_NONCE_SIZE, 0,
	       FS_KEY_DERIVATION_TAG_SIZE);
	memset(&ctx, 0, sizeof(ctx));
	ctx.format = FS_ENCRYPTION_CONTEXT_FORMAT_V2;
	memcpy(ctx.master_key_descriptor, desc, FS_KEY_DESCRIPTOR_SIZE);
	CHECK(fscrypt_ce_scope_crypt(scope, plain, ctx.nonce, ctx.iv,
				     true) == 0);
	fscrypt_ce_scope_put(scope);
	scope = NULL;

	/* Managed ADD + REMOVE leaves linked tombstone in s_fscrypt_keys */
	CHECK(do_ioctl_add(&filp, desc, raw) == 0);
	CHECK(do_ioctl_remove(&filp, desc, &rflags, false) == 0);
	CHECK(sb.s_fscrypt_keys != NULL);
	CHECK(fscrypt_check_unmanaged_descriptor(&sb, desc) == -EOPNOTSUPP);
	CHECK(fscrypt_ce_scope_open(child, desc, FILE_UNWRAP,
				    &scope) == -ENOKEY);
	CHECK(find_and_derive_key(child, NULL, &ctx, derived,
				  sizeof(derived)) == -ENOKEY);

	drop_legacy_logon_key();
	root_d->pin_count = 0;
	sb_teardown(&sb);
}

static void case_cap_sys_admin_gating(void)
{
	struct super_block sb;
	struct inode *root;
	struct dentry *root_d;
	struct file filp;
	struct fscrypt_get_key_status_arg st;
	u8 raw[64], desc[8];
	u32 rflags = 0;

	sb_init(&sb, &ext4_test_sops, true);
	root = inode_alloc(&sb, 2, S_IFDIR | 0755);
	root_d = dentry_attach(root, NULL, 1);
	filp.f_inode = root;
	make_key_bytes(raw, 0x12, desc, 0x22);

	test_admin = false;
	CHECK(do_ioctl_add(&filp, desc, raw) == -EACCES);
	CHECK(do_ioctl_remove(&filp, desc, &rflags, false) == -EACCES);
	CHECK(do_ioctl_remove(&filp, desc, &rflags, true) == -EACCES);
	CHECK(do_ioctl_status(&filp, desc, &st) == 0);
	CHECK(st.status == FSCRYPT_KEY_STATUS_ABSENT);

	test_admin = true;
	CHECK(do_ioctl_add(&filp, desc, raw) == 0);
	test_admin = false;
	CHECK(do_ioctl_status(&filp, desc, &st) == 0);
	CHECK(st.status == FSCRYPT_KEY_STATUS_PRESENT);
	CHECK(do_ioctl_remove(&filp, desc, &rflags, false) == -EACCES);
	CHECK(do_ioctl_remove(&filp, desc, &rflags, true) == -EACCES);
	test_admin = true;

	root_d->pin_count = 0;
	sb_teardown(&sb);
}

static void case_unsupported_v2_and_wrapped_flags(void)
{
	struct super_block sb;
	struct inode *root;
	struct dentry *root_d;
	struct file filp;
	struct fscrypt_add_key_arg *a;
	struct fscrypt_remove_key_arg rm;
	struct fscrypt_get_key_status_arg st;
	u8 raw[64], desc[8];

	sb_init(&sb, &ext4_test_sops, true);
	root = inode_alloc(&sb, 2, S_IFDIR | 0755);
	root_d = dentry_attach(root, NULL, 1);
	filp.f_inode = root;
	make_key_bytes(raw, 0x13, desc, 0x23);

	a = alloc_add_arg(desc, raw, 64);
	a->flags = FSCRYPT_ADD_KEY_FLAG_HW_WRAPPED;
	CHECK(fscrypt_ioctl_add_key(&filp, a) == -EOPNOTSUPP);
	a->flags = 0;
	a->__flags = __FSCRYPT_ADD_KEY_FLAG_HW_WRAPPED;
	CHECK(fscrypt_ioctl_add_key(&filp, a) == -EOPNOTSUPP);
	a->__flags = 0;
	a->key_id = 123;
	CHECK(fscrypt_ioctl_add_key(&filp, a) == -EINVAL);
	a->raw_size = 0;
	CHECK(fscrypt_ioctl_add_key(&filp, a) == -EOPNOTSUPP);
	free(a);

	a = calloc(1, sizeof(*a) + 64);
	CHECK(a);
	a->key_spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
	memset(a->key_spec.u.identifier, 0x55, FSCRYPT_KEY_IDENTIFIER_SIZE);
	a->raw_size = 64;
	memcpy(a->raw, raw, 64);
	CHECK(fscrypt_ioctl_add_key(&filp, a) == -EOPNOTSUPP);
	free(a);

	memset(&rm, 0, sizeof(rm));
	rm.key_spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
	CHECK(fscrypt_ioctl_remove_key(&filp, &rm) == -EOPNOTSUPP);
	CHECK(fscrypt_ioctl_remove_key_all_users(&filp, &rm) == -EOPNOTSUPP);

	memset(&st, 0, sizeof(st));
	st.key_spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
	CHECK(fscrypt_ioctl_get_key_status(&filp, &st) == -EOPNOTSUPP);

	root_d->pin_count = 0;
	sb_teardown(&sb);
}

static void case_reserved_and_size_validation(void)
{
	struct super_block sb;
	struct inode *root;
	struct dentry *root_d;
	struct file filp;
	struct fscrypt_add_key_arg *a;
	struct fscrypt_remove_key_arg rm;
	struct fscrypt_get_key_status_arg st;
	u8 raw[64], desc[8];

	sb_init(&sb, &ext4_test_sops, true);
	root = inode_alloc(&sb, 2, S_IFDIR | 0755);
	root_d = dentry_attach(root, NULL, 1);
	filp.f_inode = root;
	make_key_bytes(raw, 0x14, desc, 0x24);

	a = alloc_add_arg(desc, raw, 64);
	a->key_spec.__reserved = 1;
	CHECK(fscrypt_ioctl_add_key(&filp, a) == -EINVAL);
	a->key_spec.__reserved = 0;
	a->key_spec.u.__reserved[FS_KEY_DESCRIPTOR_SIZE] = 1;
	CHECK(fscrypt_ioctl_add_key(&filp, a) == -EINVAL);
	a->key_spec.u.__reserved[FS_KEY_DESCRIPTOR_SIZE] = 0;
	a->__reserved[5] = 1;
	CHECK(fscrypt_ioctl_add_key(&filp, a) == -EINVAL);
	a->__reserved[5] = 0;
	a->raw_size = 32;
	CHECK(fscrypt_ioctl_add_key(&filp, a) == -EINVAL);
	a->key_spec.type = 99;
	a->raw_size = 64;
	CHECK(fscrypt_ioctl_add_key(&filp, a) == -EINVAL);
	a->key_spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
	a->key_spec.u.__reserved[FSCRYPT_KEY_IDENTIFIER_SIZE] = 1;
	CHECK(fscrypt_ioctl_add_key(&filp, a) == -EINVAL);
	free(a);

	memset(&rm, 0, sizeof(rm));
	rm.key_spec.type = FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR;
	rm.__reserved[0] = 1;
	CHECK(fscrypt_ioctl_remove_key(&filp, &rm) == -EINVAL);

	memset(&st, 0, sizeof(st));
	st.key_spec.type = FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR;
	st.__reserved[2] = 1;
	CHECK(fscrypt_ioctl_get_key_status(&filp, &st) == -EINVAL);

	root_d->pin_count = 0;
	sb_teardown(&sb);
}

static void case_efault_copy_and_secret_wipe(void)
{
	struct super_block sb;
	struct inode *root;
	struct dentry *root_d;
	struct file filp;
	struct fscrypt_add_key_arg *a;
	struct fscrypt_remove_key_arg rm;
	struct fscrypt_get_key_status_arg st;
	u8 raw[64], desc[8];

	sb_init(&sb, &ext4_test_sops, true);
	root = inode_alloc(&sb, 2, S_IFDIR | 0755);
	root_d = dentry_attach(root, NULL, 1);
	filp.f_inode = root;
	make_key_bytes(raw, 0x15, desc, 0x25);

	CHECK(fscrypt_ioctl_add_key(&filp, NULL) == -EFAULT);
	a = alloc_add_arg(desc, raw, 64);
	fault_user_addr = a->raw;
	CHECK(fscrypt_ioctl_add_key(&filp, a) == -EFAULT);
	fault_user_addr = NULL;
	CHECK(fscrypt_ioctl_add_key(&filp, a) == 0);
	free(a);

	memset(&rm, 0, sizeof(rm));
	rm.key_spec.type = FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR;
	memcpy(rm.key_spec.u.descriptor, desc, FS_KEY_DESCRIPTOR_SIZE);
	fault_user_addr = &rm.removal_status_flags;
	CHECK(fscrypt_ioctl_remove_key(&filp, &rm) == -EFAULT);
	fault_user_addr = NULL;

	memset(&st, 0, sizeof(st));
	st.key_spec.type = FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR;
	memcpy(st.key_spec.u.descriptor, desc, FS_KEY_DESCRIPTOR_SIZE);
	fault_user_addr = &st;
	CHECK(fscrypt_ioctl_get_key_status(&filp, &st) == -EFAULT);
	fault_user_addr = NULL;

	root_d->pin_count = 0;
	sb_teardown(&sb);
}

static void case_remove_all_users_parity(void)
{
	struct super_block sb;
	struct inode *root;
	struct dentry *root_d;
	struct file filp;
	struct fscrypt_get_key_status_arg st;
	u8 raw[64], desc[8];
	u32 rflags = 0;

	sb_init(&sb, &hmfs_test_sops, true);
	root = inode_alloc(&sb, 2, S_IFDIR | 0755);
	root_d = dentry_attach(root, NULL, 1);
	filp.f_inode = root;
	make_key_bytes(raw, 0x16, desc, 0x26);

	CHECK(do_ioctl_add(&filp, desc, raw) == 0);
	CHECK(do_ioctl_remove(&filp, desc, &rflags, true) == 0);
	CHECK(rflags == 0);
	CHECK(do_ioctl_status(&filp, desc, &st) == 0);
	CHECK(st.status == FSCRYPT_KEY_STATUS_ABSENT);

	root_d->pin_count = 0;
	sb_teardown(&sb);
}

static void case_fs_feature_gate(void)
{
	struct super_block ext4_sb, f2fs_sb, hmfs_sb;
	struct inode *e_i, *f_i, *h_i;
	struct dentry *e_d, *f_d, *h_d;
	struct file e_f, f_f, h_f;
	struct fscrypt_add_key_arg *a;
	struct fscrypt_remove_key_arg rm;
	struct fscrypt_get_key_status_arg st;
	u8 raw[64], desc[8];

	sb_init(&ext4_sb, &ext4_test_sops, false);
	sb_init(&f2fs_sb, &f2fs_test_sops, false);
	sb_init(&hmfs_sb, &hmfs_test_sops, false);
	e_i = inode_alloc(&ext4_sb, 2, S_IFDIR | 0755);
	f_i = inode_alloc(&f2fs_sb, 2, S_IFDIR | 0755);
	h_i = inode_alloc(&hmfs_sb, 2, S_IFDIR | 0755);
	e_d = dentry_attach(e_i, NULL, 1);
	f_d = dentry_attach(f_i, NULL, 1);
	h_d = dentry_attach(h_i, NULL, 1);
	e_f.f_inode = e_i;
	f_f.f_inode = f_i;
	h_f.f_inode = h_i;
	make_key_bytes(raw, 0x17, desc, 0x27);

	a = alloc_add_arg(desc, raw, 64);
	memset(&rm, 0, sizeof(rm));
	rm.key_spec.type = FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR;
	memcpy(rm.key_spec.u.descriptor, desc, 8);
	memset(&st, 0, sizeof(st));
	st.key_spec.type = FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR;
	memcpy(st.key_spec.u.descriptor, desc, 8);

	CHECK(subj_ext4_fscrypt_ioctl(&e_f, FS_IOC_ADD_ENCRYPTION_KEY,
				      (unsigned long)a) == -EOPNOTSUPP);
	CHECK(subj_ext4_fscrypt_ioctl(&e_f, FS_IOC_REMOVE_ENCRYPTION_KEY,
				      (unsigned long)&rm) == -EOPNOTSUPP);
	CHECK(subj_ext4_fscrypt_ioctl(&e_f,
				      FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS,
				      (unsigned long)&rm) == -EOPNOTSUPP);
	CHECK(subj_ext4_fscrypt_ioctl(&e_f, FS_IOC_GET_ENCRYPTION_KEY_STATUS,
				      (unsigned long)&st) == -EOPNOTSUPP);

	CHECK(subj_f2fs_fscrypt_ioctl(&f_f, FS_IOC_ADD_ENCRYPTION_KEY,
				      (unsigned long)a) == -EOPNOTSUPP);
	CHECK(subj_f2fs_fscrypt_ioctl(&f_f, FS_IOC_REMOVE_ENCRYPTION_KEY,
				      (unsigned long)&rm) == -EOPNOTSUPP);
	CHECK(subj_f2fs_fscrypt_ioctl(&f_f,
				      FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS,
				      (unsigned long)&rm) == -EOPNOTSUPP);
	CHECK(subj_f2fs_fscrypt_ioctl(&f_f, FS_IOC_GET_ENCRYPTION_KEY_STATUS,
				      (unsigned long)&st) == -EOPNOTSUPP);

	CHECK(subj_hmfs_fscrypt_ioctl(&h_f, FS_IOC_ADD_ENCRYPTION_KEY,
				      (unsigned long)a) == -EOPNOTSUPP);
	CHECK(subj_hmfs_fscrypt_ioctl(&h_f, FS_IOC_REMOVE_ENCRYPTION_KEY,
				      (unsigned long)&rm) == -EOPNOTSUPP);
	CHECK(subj_hmfs_fscrypt_ioctl(&h_f,
				      FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS,
				      (unsigned long)&rm) == -EOPNOTSUPP);
	CHECK(subj_hmfs_fscrypt_ioctl(&h_f, FS_IOC_GET_ENCRYPTION_KEY_STATUS,
				      (unsigned long)&st) == -EOPNOTSUPP);

	ext4_sb.has_encrypt = true;
	f2fs_sb.has_encrypt = true;
	hmfs_sb.has_encrypt = true;
	CHECK(subj_ext4_fscrypt_ioctl(&e_f, FS_IOC_ADD_ENCRYPTION_KEY,
				      (unsigned long)a) == 0);
	CHECK(subj_f2fs_fscrypt_ioctl(&f_f, FS_IOC_ADD_ENCRYPTION_KEY,
				      (unsigned long)a) == 0);
	CHECK(subj_hmfs_fscrypt_ioctl(&h_f, FS_IOC_ADD_ENCRYPTION_KEY,
				      (unsigned long)a) == 0);
	CHECK(subj_ext4_fscrypt_ioctl(&e_f, FS_IOC_GET_ENCRYPTION_KEY_STATUS,
				      (unsigned long)&st) == 0);
	CHECK(st.status == FSCRYPT_KEY_STATUS_PRESENT);
	CHECK(subj_hmfs_fscrypt_ioctl(&h_f, FS_IOC_REMOVE_ENCRYPTION_KEY,
				      (unsigned long)&rm) == 0);
	CHECK(subj_hmfs_fscrypt_ioctl(&h_f, FS_IOC_GET_ENCRYPTION_KEY_STATUS,
				      (unsigned long)&st) == 0);
	CHECK(st.status == FSCRYPT_KEY_STATUS_ABSENT);

	free(a);
	e_d->pin_count = 0;
	f_d->pin_count = 0;
	h_d->pin_count = 0;
	sb_teardown(&ext4_sb);
	sb_teardown(&f2fs_sb);
	sb_teardown(&hmfs_sb);
}

static void case_nested_dir_shrink_order(void)
{
	struct super_block sb;
	struct inode *root, *pdir, *cdir, *leaf;
	struct dentry *root_d, *p_d, *c_d;
	struct file filp;
	struct fscrypt_get_key_status_arg st;
	u8 raw[64], desc[8];
	u32 rflags = 0;

	sb_init(&sb, &hmfs_test_sops, true);
	root = inode_alloc(&sb, 2, S_IFDIR | 0755);
	root_d = dentry_attach(root, NULL, 1);
	filp.f_inode = root;
	make_key_bytes(raw, 0x18, desc, 0x28);
	CHECK(do_ioctl_add(&filp, desc, raw) == 0);

	/*
	 * Place parent before child and leaf in s_inodes to exercise
	 * shrink_dcache_parent() clearing descendant dentries bottom-up.
	 */
	pdir = inode_alloc(&sb, 100, S_IFDIR | 0755);
	cdir = inode_alloc(&sb, 101, S_IFDIR | 0755);
	leaf = inode_alloc(&sb, 102, S_IFREG | 0644);
	p_d = dentry_attach(pdir, root_d, 0);
	c_d = dentry_attach(cdir, p_d, 0);
	dentry_attach(leaf, c_d, 0);
	CHECK(enroll_inode_owner(pdir, desc) == 0);
	CHECK(enroll_inode_owner(cdir, desc) == 0);
	CHECK(enroll_inode_owner(leaf, desc) == 0);

	CHECK(do_ioctl_remove(&filp, desc, &rflags, false) == 0);
	CHECK(rflags == 0);
	CHECK(pdir->evicted && cdir->evicted && leaf->evicted);
	CHECK(do_ioctl_status(&filp, desc, &st) == 0);
	CHECK(st.status == FSCRYPT_KEY_STATUS_ABSENT);

	free(pdir);
	free(cdir);
	free(leaf);
	root_d->pin_count = 0;
	sb_teardown(&sb);
}

static void case_test_dummy_encryption_gcm(void)
{
	struct super_block sb;
	struct inode *root;
	struct dentry *root_d;
	struct file filp;
	struct fscrypt_context ctx;
	struct fscrypt_info ci1, ci2;
	u8 raw[64], desc[8], key1[64], key2[64];

	sb_init(&sb, &ext4_test_sops, true);
	root = inode_alloc(&sb, 2, S_IFDIR | 0755);
	root->dummy_unencrypted = true;
	root_d = dentry_attach(root, NULL, 1);
	filp.f_inode = root;
	make_key_bytes(raw, 0x19, desc, 0x42);
	memset(desc, 0x42, sizeof(desc));

	CHECK(do_ioctl_add(&filp, desc, raw) == 0);
	memset(&ctx, 0, sizeof(ctx));
	ctx.format = FS_ENCRYPTION_CONTEXT_FORMAT_V2;
	ctx.contents_encryption_mode = 1;
	ctx.filenames_encryption_mode = 4;
	memcpy(ctx.master_key_descriptor, desc, FS_KEY_DESCRIPTOR_SIZE);

	memset(&ci1, 0, sizeof(ci1));
	memset(&ci2, 0, sizeof(ci2));
	CHECK(find_and_derive_key_with_scope(root, &ci1, &ctx, key1,
					     sizeof(key1), NULL, true) == 0);
	CHECK(find_and_derive_key_with_scope(root, &ci2, &ctx, key2,
					     sizeof(key2), NULL, true) == 0);
	CHECK(!memcmp(key1, key2, sizeof(key1)));
	CHECK(fscrypt_ci_is_managed(&ci1));

	fscrypt_mk_drop_owner(&ci1.ci_owner);
	fscrypt_ce_tfm_put(ci1.ci_gtfm_owner);
	fscrypt_mk_drop_owner(&ci2.ci_owner);
	fscrypt_ce_tfm_put(ci2.ci_gtfm_owner);
	root_d->pin_count = 0;
	sb_teardown(&sb);
}

int main(int argc, char **argv)
{
	const char *name;

	CHECK(argc == 2);
	name = argv[1];
	CHECK(fscrypt_registry_init() == 0);

	if (!strcmp(name, "uapi-abi-parity"))
		case_uapi_abi_parity();
	else if (!strcmp(name, "add-status-remove-clean"))
		case_add_status_remove_clean();
	else if (!strcmp(name, "idempotent-and-conflicting-readd"))
		case_idempotent_and_conflicting_readd();
	else if (!strcmp(name, "busy-inode-retry-lifecycle"))
		case_busy_inode_retry_lifecycle();
	else if (!strcmp(name, "dirty-inode-retained-until-sync"))
		case_dirty_inode_retained_until_sync();
	else if (!strcmp(name, "readd-advances-gen-retires-old"))
		case_readd_advances_gen_retires_old();
	else if (!strcmp(name, "concurrent-readd-during-remove-owner-check"))
		case_concurrent_readd_owner_check();
	else if (!strcmp(name, "tombstone-blocks-legacy-fallback"))
		case_tombstone_blocks_legacy_fallback();
	else if (!strcmp(name, "cap-sys-admin-gating"))
		case_cap_sys_admin_gating();
	else if (!strcmp(name, "unsupported-v2-and-wrapped-flags"))
		case_unsupported_v2_and_wrapped_flags();
	else if (!strcmp(name, "reserved-and-size-validation"))
		case_reserved_and_size_validation();
	else if (!strcmp(name, "efault-copy-and-secret-wipe"))
		case_efault_copy_and_secret_wipe();
	else if (!strcmp(name, "remove-all-users-parity"))
		case_remove_all_users_parity();
	else if (!strcmp(name, "fs-feature-gate"))
		case_fs_feature_gate();
	else if (!strcmp(name, "nested-dir-shrink-order"))
		case_nested_dir_shrink_order();
	else if (!strcmp(name, "test-dummy-encryption-gcm"))
		case_test_dummy_encryption_gcm();
	else
		return 2;

	fscrypt_registry_exit();
	CHECK(live_kmallocs == 0);
	CHECK(aead_allocs == 0);
	return 0;
}
