/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t nid_t;
typedef unsigned int umode_t;
#define GFP_NOFS 0
#define XATTR_CREATE 1
#define F2FS_XATTR_INDEX_ENCRYPTION 9
#define F2FS_XATTR_NAME_ENCRYPTION_CONTEXT "c"
#define FI_NEW_INODE 1
#define REQ_TIME 1
#define CHILD_WRAP 3
#define EAGAIN 11
#define WHITEOUT_DEV 0
#define IS_ERR(pointer) (!(pointer))
#define PTR_ERR(pointer) (-ENOMEM)
#define container_of(pointer, type, member) \
	((type *)((char *)(pointer) - offsetof(type, member)))

enum fscrypt_context_origin {
	FSCRYPT_CTX_OWNED_POLICY = 0,
	FSCRYPT_CTX_BORROWED_INHERIT = 1,
};
enum fscrypt_context_phase {
	FSCRYPT_CTX_PREPARED = 0,
	FSCRYPT_CTX_INSTALLED,
	FSCRYPT_CTX_FINISHED,
};
struct inode;
struct fscrypt_context_op;
struct fscrypt_operations {
	int (*prepare_context)(struct inode *, enum fscrypt_context_origin,
			       void *, struct fscrypt_context_op **);
};
struct fscrypt_context_op {
	const struct fscrypt_operations *cop;
	struct inode *inode;
	enum fscrypt_context_origin origin;
	enum fscrypt_context_phase phase;
	void *fs_data;
	bool owns_fs_data;
	int *retry_count;
};
struct rw_semaphore { int write_depth; };
struct page { int id; };
struct super_block {
	const struct fscrypt_operations *s_cop;
	bool lost_found;
};
struct f2fs_sb_info {
	struct super_block *sb;
	unsigned long root_ino;
	bool dummy_encryption;
};
struct f2fs_inode_info {
	struct rw_semaphore i_sem;
	struct rw_semaphore i_xattr_sem;
	bool encrypted;
	bool new_inode;
};
struct address_space { const void *a_ops; };
struct inode {
	unsigned long i_ino;
	umode_t i_mode;
	struct super_block *i_sb;
	struct f2fs_sb_info *sbi;
	struct f2fs_inode_info fi;
	const void *i_op;
	const void *i_fop;
	struct address_space *i_mapping;
	void *i_crypt_info;
};
struct fscrypt_ce_scope { int id; };
struct qstr { const unsigned char *name; unsigned int len; };
struct fscrypt_name {
	const struct qstr *usr_fname;
	struct { unsigned char *name; uint32_t len; } disk_name;
};
struct dentry { int unused; };
#define fname_name(fname) ((fname)->disk_name.name)
#define fname_len(fname) ((fname)->disk_name.len)
#define F2FS_I_SB(inode) ((inode)->sbi)
#define F2FS_I(inode) (&(inode)->fi)
#define F2FS_ROOT_INO(sbi) ((sbi)->root_ino)
#define DUMMY_ENCRYPTION_ENABLED(sbi) ((sbi)->dummy_encryption)

#ifdef TEST_HMFS
#define tested_prepare hmfs_prepare_context
#define tested_install hmfs_set_context_prepared
#define tested_finish hmfs_finish_context
#define tested_add_dentry hmfs_add_dentry
#define tested_context_type hmfs_fscrypt_context_op
#define tested_context_op hmfs_context_op
#define tested_setxattr __hmfs_setxattr
#define tested_add_inline hmfs_add_inline_entry
#define tested_add_regular hmfs_add_regular_entry
#define SUBJECT_HEADER "subject_hmfs.h"
#else
#define tested_prepare f2fs_prepare_context
#define tested_install f2fs_set_context_prepared
#define tested_finish f2fs_finish_context
#define tested_add_dentry f2fs_add_dentry
#define tested_context_type f2fs_fscrypt_context_op
#define tested_context_op f2fs_context_op
#define tested_setxattr __f2fs_setxattr
#define tested_add_inline f2fs_add_inline_entry
#define tested_add_regular f2fs_add_regular_entry
#define SUBJECT_HEADER "subject_f2fs.h"
#endif

struct tested_context_type {
	struct fscrypt_context_op op;
	struct f2fs_sb_info *sbi;
	struct page *ipage;
};

static int quota_calls, balance_calls, lock_calls, unlock_calls, updates;
static int xattr_calls, scope_opens, scope_puts, inline_calls, regular_calls;
static int order, lock_order, scope_order, child_lock_order, unlock_order;
static int scope_open_error, orphan_error, tmpfile_error;
static int orphan_releases, failed_inodes, tmpfile_calls;
static int get_info_calls, get_info_order, allocation_balance;
static bool cp_locked;
static struct inode *created_inode;
static struct page *seen_ipage;
static struct fscrypt_ce_scope *inline_scope, *regular_scope;
static struct fscrypt_ce_scope fixture_scope;

static struct tested_context_type *
tested_context_op(struct inode *inode, struct fscrypt_context_op *op)
{
	if (!op || op->cop != inode->i_sb->s_cop || op->inode != inode ||
	    op->phase == FSCRYPT_CTX_FINISHED)
		return NULL;
	return container_of(op, struct tested_context_type, op);
}
static void *kzalloc(size_t size, int flags)
{
	void *pointer;

	(void)flags;
	pointer = calloc(1, size);
	if (pointer)
		allocation_balance++;
	return pointer;
}
static void kfree(const void *pointer)
{
	if (pointer)
		allocation_balance--;
	assert(allocation_balance >= 0);
	free((void *)pointer);
}
static bool f2fs_sb_has_lost_found(struct super_block *sb)
{
	return sb->lost_found;
}
static int f2fs_dquot_initialize(struct inode *inode)
{
	(void)inode;
	quota_calls++;
	return 0;
}
static void f2fs_balance_fs(struct f2fs_sb_info *sbi, bool need)
{
	(void)sbi;
	assert(need);
	balance_calls++;
}
static void hmfs_balance_fs(struct f2fs_sb_info *sbi, bool need)
	__attribute__((unused));
static void hmfs_balance_fs(struct f2fs_sb_info *sbi, bool need)
{
	f2fs_balance_fs(sbi, need);
}
static void f2fs_lock_op(struct f2fs_sb_info *sbi)
{
	(void)sbi;
	assert(!cp_locked);
	cp_locked = true;
	lock_calls++;
	lock_order = ++order;
}
static void f2fs_unlock_op(struct f2fs_sb_info *sbi)
{
	(void)sbi;
	assert(cp_locked);
	cp_locked = false;
	unlock_calls++;
	unlock_order = ++order;
}
static void f2fs_update_time(struct f2fs_sb_info *sbi, int type)
{
	(void)sbi;
	assert(type == REQ_TIME);
	if (unlock_calls)
		assert(!cp_locked);
	updates++;
}
static void down_write(struct rw_semaphore *sem)
{
	assert(cp_locked);
	sem->write_depth++;
	if (!child_lock_order)
		child_lock_order = ++order;
}
static void up_write(struct rw_semaphore *sem)
{
	assert(sem->write_depth == 1);
	sem->write_depth--;
}
static int __f2fs_setxattr(struct inode *inode, int index, const char *name,
		const void *value, size_t size, struct page *ipage, int flags)
{
	(void)inode;
	(void)value;
	(void)size;
	assert(index == F2FS_XATTR_INDEX_ENCRYPTION && !strcmp(name, "c"));
	assert(flags == XATTR_CREATE);
	seen_ipage = ipage;
	xattr_calls++;
	return 0;
}
static int __hmfs_setxattr(struct inode *inode, int index, const char *name,
		const void *value, size_t size, struct page *ipage, int flags)
	__attribute__((unused));
static int __hmfs_setxattr(struct inode *inode, int index, const char *name,
		const void *value, size_t size, struct page *ipage, int flags)
{
	return __f2fs_setxattr(inode, index, name, value, size, ipage, flags);
}
static bool f2fs_has_inline_dentry(struct inode *dir)
{
	(void)dir;
	return true;
}
static bool f2fs_encrypted_inode(struct inode *inode)
{
	return inode->fi.encrypted;
}
static bool f2fs_may_encrypt(struct inode *inode)
{
	(void)inode;
	return true;
}
static bool fscrypt_has_encryption_key(struct inode *inode)
{
	return inode->i_crypt_info != NULL;
}
static int fscrypt_get_encryption_info(struct inode *inode)
{
	get_info_calls++;
	get_info_order = ++order;
	inode->i_crypt_info = &fixture_scope;
	return 0;
}
static bool is_inode_flag_set(struct inode *inode, int flag)
{
	assert(flag == FI_NEW_INODE);
	return inode->fi.new_inode;
}
static int fscrypt_ce_scope_open_cached(struct inode *inode, int purpose,
				       struct fscrypt_ce_scope **scope)
{
	(void)inode;
	assert(cp_locked && purpose == CHILD_WRAP);
	scope_opens++;
	scope_order = ++order;
	if (!inode->i_crypt_info) {
		*scope = NULL;
		return -ENOKEY;
	}
	if (scope_open_error) {
		*scope = NULL;
		return scope_open_error;
	}
	*scope = &fixture_scope;
	return 0;
}
static void fscrypt_ce_scope_put(struct fscrypt_ce_scope *scope)
{
	if (!scope)
		return;
	assert(scope == &fixture_scope);
	scope_puts++;
}
static int f2fs_add_inline_entry(struct inode *dir, const struct qstr *new_name,
		const struct qstr *orig_name, struct dentry *dentry,
		struct inode *inode, nid_t ino, umode_t mode,
		struct fscrypt_ce_scope *scope)
{
	(void)dir; (void)new_name; (void)orig_name; (void)dentry; (void)inode;
	(void)ino; (void)mode;
	assert(cp_locked && scope_order && !child_lock_order);
	inline_scope = scope;
	inline_calls++;
	return -EAGAIN;
}
static int hmfs_add_inline_entry(struct inode *dir, const struct qstr *new_name,
		const struct qstr *orig_name, struct dentry *dentry,
		struct inode *inode, nid_t ino, umode_t mode,
		struct fscrypt_ce_scope *scope) __attribute__((unused));
static int hmfs_add_inline_entry(struct inode *dir, const struct qstr *new_name,
		const struct qstr *orig_name, struct dentry *dentry,
		struct inode *inode, nid_t ino, umode_t mode,
		struct fscrypt_ce_scope *scope)
{
	return f2fs_add_inline_entry(dir, new_name, orig_name, dentry, inode,
				     ino, mode, scope);
}
static int f2fs_add_regular_entry(struct inode *dir,
		const struct qstr *new_name, const struct qstr *orig_name,
		struct dentry *dentry, struct inode *inode, nid_t ino, umode_t mode,
		struct fscrypt_ce_scope *scope)
{
	(void)dir; (void)new_name; (void)orig_name; (void)dentry; (void)inode;
	(void)ino; (void)mode;
	assert(cp_locked && scope_order && !child_lock_order);
	regular_scope = scope;
	regular_calls++;
	return 0;
}
static int hmfs_add_regular_entry(struct inode *dir,
		const struct qstr *new_name, const struct qstr *orig_name,
		struct dentry *dentry, struct inode *inode, nid_t ino, umode_t mode,
		struct fscrypt_ce_scope *scope) __attribute__((unused));
static int hmfs_add_regular_entry(struct inode *dir,
		const struct qstr *new_name, const struct qstr *orig_name,
		struct dentry *dentry, struct inode *inode, nid_t ino, umode_t mode,
		struct fscrypt_ce_scope *scope)
{
	return f2fs_add_regular_entry(dir, new_name, orig_name, dentry, inode,
				      ino, mode, scope);
}

static int f2fs_special_inode_operations, f2fs_file_inode_operations;
static int f2fs_file_operations, f2fs_dblock_aops;
static int hmfs_special_inode_operations, hmfs_file_inode_operations;
static int hmfs_file_operations, hmfs_dblock_aops;

static struct inode *f2fs_new_inode(struct inode *dir, umode_t mode)
{
	assert(created_inode && created_inode->i_sb == dir->i_sb);
	created_inode->i_mode = mode;
	return created_inode;
}

static void init_special_inode(struct inode *inode, umode_t mode, int device)
{
	(void)device;
	inode->i_mode = mode;
}

static int f2fs_acquire_orphan_inode(struct f2fs_sb_info *sbi)
{
	(void)sbi;
	return orphan_error;
}

static int hmfs_acquire_orphan_inode(struct f2fs_sb_info *sbi)
{
	return f2fs_acquire_orphan_inode(sbi);
}

static int run_tmpfile_metadata(struct inode *inode,
		struct fscrypt_ce_scope *scope)
{
	assert(cp_locked && scope == &fixture_scope);
	assert(scope_order && !child_lock_order);
	tmpfile_calls++;
	down_write(&F2FS_I(inode)->i_sem);
	up_write(&F2FS_I(inode)->i_sem);
	return tmpfile_error;
}

static int f2fs_do_tmpfile(struct inode *inode, struct dentry *dentry,
		struct inode *dir, struct fscrypt_ce_scope *scope)
{
	(void)dentry;
	(void)dir;
	return run_tmpfile_metadata(inode, scope);
}

static int hmfs_do_tmpfile(struct inode *inode, struct dentry *dentry,
		struct inode *dir, struct fscrypt_ce_scope *scope)
{
	return f2fs_do_tmpfile(inode, dentry, dir, scope);
}

static void f2fs_add_orphan_inode(struct inode *inode) { (void)inode; }
static void hmfs_add_orphan_inode(struct inode *inode) { (void)inode; }
static void f2fs_alloc_nid_done(struct f2fs_sb_info *sbi, nid_t ino)
{
	(void)sbi;
	(void)ino;
}
static void hmfs_alloc_nid_done(struct f2fs_sb_info *sbi, nid_t ino)
{
	f2fs_alloc_nid_done(sbi, ino);
}
static void f2fs_i_links_write(struct inode *inode, bool inc)
{
	(void)inode;
	(void)inc;
}
static void d_tmpfile(struct dentry *dentry, struct inode *inode)
{
	(void)dentry;
	(void)inode;
}
static void unlock_new_inode(struct inode *inode) { (void)inode; }
static void f2fs_release_orphan_inode(struct f2fs_sb_info *sbi)
{
	(void)sbi;
	orphan_releases++;
}
static void hmfs_release_orphan_inode(struct f2fs_sb_info *sbi)
{
	f2fs_release_orphan_inode(sbi);
}
static void f2fs_handle_failed_inode(struct inode *inode)
{
	assert(cp_locked);
	failed_inodes++;
	f2fs_unlock_op(F2FS_I_SB(inode));
}
static void hmfs_handle_failed_inode(struct inode *inode)
{
	f2fs_handle_failed_inode(inode);
}

#include SUBJECT_HEADER

static pthread_mutex_t schedule_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t schedule_cond = PTHREAD_COND_INITIALIZER;
static int schedule_phase;
static struct inode *schedule_inode;
static struct fscrypt_context_op *schedule_op;

static void wait_for_phase(int phase)
{
	while (schedule_phase != phase)
		assert(!pthread_cond_wait(&schedule_cond, &schedule_lock));
}

static void advance_phase(int phase)
{
	schedule_phase = phase;
	assert(!pthread_cond_broadcast(&schedule_cond));
}

static void *parent_task(void *unused)
{
	(void)unused;
	assert(!tested_prepare(schedule_inode, FSCRYPT_CTX_OWNED_POLICY, NULL,
			       &schedule_op));
	assert(!pthread_mutex_lock(&schedule_lock));
	advance_phase(1); /* P: prepared, cp_rwsem held. */
	wait_for_phase(4);
	assert(!cp_locked);
	advance_phase(5); /* P: can make progress again. */
	assert(!pthread_mutex_unlock(&schedule_lock));
	return NULL;
}

static void *child_task(void *unused)
{
	(void)unused;
	assert(!pthread_mutex_lock(&schedule_lock));
	wait_for_phase(1);
	assert(cp_locked);
	advance_phase(2); /* C */
	assert(!pthread_mutex_unlock(&schedule_lock));
	return NULL;
}

static void *install_task(void *unused)
{
	(void)unused;
	assert(!pthread_mutex_lock(&schedule_lock));
	wait_for_phase(2);
	assert(!tested_install(schedule_inode, "ctx", 3, schedule_op));
	advance_phase(3); /* I */
	assert(!pthread_mutex_unlock(&schedule_lock));
	return NULL;
}

static void *release_task(void *unused)
{
	bool retry = true;

	(void)unused;
	assert(!pthread_mutex_lock(&schedule_lock));
	wait_for_phase(3);
	assert(!tested_finish(schedule_inode, schedule_op, 0, &retry));
	assert(!retry);
	advance_phase(4); /* R */
	assert(!pthread_mutex_unlock(&schedule_lock));
	return NULL;
}

static void run_four_task_schedule(struct inode *inode)
{
	pthread_t tasks[4];

	schedule_phase = 0;
	schedule_inode = inode;
	schedule_op = NULL;
	assert(!pthread_create(&tasks[0], NULL, parent_task, NULL));
	assert(!pthread_create(&tasks[1], NULL, child_task, NULL));
	assert(!pthread_create(&tasks[2], NULL, install_task, NULL));
	assert(!pthread_create(&tasks[3], NULL, release_task, NULL));
	for (size_t i = 0; i < 4; i++)
		assert(!pthread_join(tasks[i], NULL));
	assert(schedule_phase == 5);
}

static void reset_fixture(void)
{
	assert(allocation_balance == 0);
	quota_calls = balance_calls = lock_calls = unlock_calls = updates = 0;
	xattr_calls = scope_opens = scope_puts = inline_calls = regular_calls = 0;
	order = lock_order = scope_order = child_lock_order = unlock_order = 0;
	scope_open_error = orphan_error = tmpfile_error = 0;
	orphan_releases = failed_inodes = tmpfile_calls = 0;
	get_info_calls = get_info_order = 0;
	cp_locked = false;
	created_inode = NULL;
	seen_ipage = NULL;
	inline_scope = regular_scope = NULL;
}

int main(int argc, char **argv)
{
	struct fscrypt_operations cops = { .prepare_context = tested_prepare };
	struct super_block sb = { .s_cop = &cops, .lost_found = true };
	struct f2fs_sb_info sbi = { .sb = &sb, .root_ino = 1 };
	struct address_space mapping = { 0 };
	struct inode inode = { .i_ino = 9, .i_sb = &sb, .sbi = &sbi,
		.fi = { .encrypted = true, .new_inode = true },
		.i_mapping = &mapping };
	struct inode dir = { .i_ino = 8, .i_sb = &sb, .sbi = &sbi,
		.fi = { .encrypted = true }, .i_crypt_info = &fixture_scope };
	struct page ipage = { .id = 1 };
	struct fscrypt_context_op *op = NULL;
	struct qstr user = { (const unsigned char *)"name", 4 };
	struct fscrypt_name fname = { .usr_fname = &user,
		.disk_name = { (unsigned char *)"disk", 4 } };
	bool retry = true;
	int result;

	assert(argc == 2);
	reset_fixture();
	if (strstr(argv[1], "four-task-order")) {
		inode.i_ino = 1;
		assert(tested_prepare(&inode, FSCRYPT_CTX_OWNED_POLICY, NULL,
				      &op) == -EPERM && op == NULL);
		inode.i_ino = 9;
		run_four_task_schedule(&inode);
		assert(!cp_locked && quota_calls == 1 && balance_calls == 1);
		assert(seen_ipage == NULL && inode.fi.i_sem.write_depth == 0 &&
		       inode.fi.i_xattr_sem.write_depth == 0);
		assert(!cp_locked && unlock_order < order + 1 && updates == 1);
		assert(lock_order < child_lock_order && child_lock_order < unlock_order);

		reset_fixture();
		assert(!tested_prepare(&inode, FSCRYPT_CTX_BORROWED_INHERIT,
					&ipage, &op));
		assert(!cp_locked && quota_calls == 0 && balance_calls == 0);
		assert(!tested_install(&inode, "ctx", 3, op));
		assert(seen_ipage == &ipage);
		assert(!tested_finish(&inode, op, 0, &retry));
		assert(unlock_calls == 0 && updates == 0);

		reset_fixture();
		op = NULL;
		assert(!tested_prepare(&inode, FSCRYPT_CTX_OWNED_POLICY,
					NULL, &op));
		assert(tested_finish(&inode, op, -EIO, NULL) == -EIO);
		assert(!cp_locked && unlock_calls == 1 && updates == 1 &&
		       allocation_balance == 0);
	} else if (strstr(argv[1], "inline-regular-one-scope")) {
		cp_locked = true;
		lock_order = ++order;
		result = tested_add_dentry(&dir, &fname, NULL, &inode, 9, 0100644);
		assert(result != -ENOKEY);
		assert(!result);
		assert(scope_opens == 1 && scope_puts == 1);
		assert(inline_calls == 1 && regular_calls == 1);
		assert(inline_scope == &fixture_scope && regular_scope == inline_scope);
		assert(lock_order < scope_order);
	} else if (strstr(argv[1], "dummy-unencrypted-dir")) {
		dir.fi.encrypted = false;
		dir.i_crypt_info = NULL;
		sbi.dummy_encryption = true;
		cp_locked = true;
		lock_order = ++order;
		result = tested_add_dentry(&dir, &fname, NULL, &inode, 9, 0100644);
		assert(result != -ENOKEY);
		assert(!result);
		assert(get_info_calls == 1 && dir.i_crypt_info == &fixture_scope);
		assert(lock_order < get_info_order && get_info_order < scope_order);
		assert(scope_opens == 1 && scope_puts == 1);
	} else if (strstr(argv[1], "tmpfile-order")) {
		created_inode = &inode;
		assert(!__f2fs_tmpfile(&dir, NULL, 0100600, NULL));
		assert(scope_opens == 1 && scope_puts == 1 && tmpfile_calls == 1);
		assert(lock_order < scope_order && scope_order < child_lock_order &&
		       child_lock_order < unlock_order);
		assert(!cp_locked && !failed_inodes && !orphan_releases);

		reset_fixture();
		created_inode = &inode;
		scope_open_error = -ENOKEY;
		assert(__f2fs_tmpfile(&dir, NULL, 0100600, NULL) == -ENOKEY);
		assert(scope_opens == 1 && scope_puts == 0 && tmpfile_calls == 0);
		assert(failed_inodes == 1 && !cp_locked);

		reset_fixture();
		created_inode = &inode;
		orphan_error = -ENOSPC;
		assert(__f2fs_tmpfile(&dir, NULL, 0100600, NULL) == -ENOSPC);
		assert(scope_puts == 1 && tmpfile_calls == 0 &&
		       failed_inodes == 1 && !cp_locked);

		reset_fixture();
		created_inode = &inode;
		tmpfile_error = -EIO;
		assert(__f2fs_tmpfile(&dir, NULL, 0100600, NULL) == -EIO);
		assert(scope_puts == 1 && tmpfile_calls == 1 &&
		       orphan_releases == 1 && failed_inodes == 1 && !cp_locked);
	} else {
		return 2;
	}
	assert(allocation_balance == 0);
	printf("PASS %s\n", argv[1]);
	return 0;
}
