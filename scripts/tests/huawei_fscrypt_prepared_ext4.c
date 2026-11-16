/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
#define EXT4_ROOT_INO 2
#define EXT4_HT_MISC 7
#define EXT4_INODE_ENCRYPT 1
#define EXT4_STATE_MAY_INLINE_DATA 2
#define EXT4_XATTR_INDEX_ENCRYPTION 9
#define EXT4_XATTR_NAME_ENCRYPTION_CONTEXT "c"
#define FS_KEY_DERIVATION_CIPHER_SIZE 80
#define FS_KEY_DERIVATION_IV_SIZE 16
#define FS_KEY_DESCRIPTOR_SIZE 8
#define GFP_NOFS 0
#define __GFP_ZERO 0
#define CHILD_WRAP 3
#define IS_ERR(pointer) ((pointer) == (void *)-1)
#define PTR_ERR(pointer) (-ENOMEM)
#define WARN_ON_ONCE(condition) (!!(condition))
#define BUG_ON(condition) assert(!(condition))
#define EXT4_XATTR_MAX_DEFERRED_IPUTS 32
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
struct ext4_xattr_deferred_iputs {
	unsigned int count;
	struct inode *inodes[32];
};
struct handle { int h_buffer_credits; };
typedef struct handle handle_t;
struct buffer_head { int unused; };
struct super_block { const struct fscrypt_operations *s_cop; };
struct ext4_inode_info { unsigned int flags, state; };
struct inode {
	unsigned long i_ino;
	struct super_block *i_sb;
	struct ext4_inode_info ext4;
	int id;
};
#define EXT4_I(inode) (&(inode)->ext4)
struct fscrypt_context {
	u8 format, contents_encryption_mode, filenames_encryption_mode, flags;
	u8 descriptor[FS_KEY_DESCRIPTOR_SIZE];
	u8 nonce[FS_KEY_DERIVATION_CIPHER_SIZE];
	u8 iv[FS_KEY_DERIVATION_IV_SIZE];
} __attribute__((packed));
struct ext4_fscrypt_context_op {
	struct fscrypt_context_op op;
	handle_t *handle;
	int retries;
	struct ext4_xattr_deferred_iputs deferred_iputs;
};
struct fscrypt_ce_scope { int id; };

static int order, inline_order, dquot_order, credits_order, start_order;
static int inline_error, quota_error, credits_error, xattr_error, dirty_error;
static int starts, stops, stop_error, retries_called, retry_answer;
static int marks, inode_flags, iputs, scope_opens, scope_puts, inherits;
static int allocation_balance;
static handle_t owned_handle;
static struct fscrypt_ce_scope child_scope;
static const struct fscrypt_ce_scope *inherit_scope;
static void *inherit_fs_data;
static bool inherit_preload;

void ext4_xattr_defer_iput(struct ext4_xattr_deferred_iputs *,
			   struct inode *);
void ext4_xattr_drain_deferred_iputs(struct ext4_xattr_deferred_iputs *);

static struct ext4_fscrypt_context_op *
ext4_context_op(struct inode *inode, struct fscrypt_context_op *op)
{
	if (!op || op->cop != inode->i_sb->s_cop || op->inode != inode ||
	    op->phase == FSCRYPT_CTX_FINISHED)
		return NULL;
	return container_of(op, struct ext4_fscrypt_context_op, op);
}

static void *kvmalloc(size_t size, int flags)
{
	void *pointer;

	(void)flags;
	pointer = calloc(1, size);
	if (pointer)
		allocation_balance++;
	return pointer;
}
static void kvfree(const void *pointer)
{
	if (pointer)
		allocation_balance--;
	assert(allocation_balance >= 0);
	free((void *)pointer);
}
static int ext4_convert_inline_data(struct inode *inode)
{
	(void)inode;
	inline_order = ++order;
	return inline_error;
}
static int dquot_initialize(struct inode *inode)
{
	(void)inode;
	dquot_order = ++order;
	return quota_error;
}
static int ext4_xattr_set_credits(struct inode *inode, size_t len,
				  bool create, int *credits)
{
	(void)inode;
	assert(len == sizeof(struct fscrypt_context));
	assert(!create);
	credits_order = ++order;
	*credits = 19;
	return credits_error;
}
static handle_t *ext4_journal_start(struct inode *inode, int type, int credits)
{
	(void)inode;
	assert(type == EXT4_HT_MISC && credits == 19);
	start_order = ++order;
	starts++;
	return &owned_handle;
}
static int ext4_journal_stop(handle_t *handle)
{
	assert(handle == &owned_handle);
	stops++;
	return stop_error;
}
static int ext4_xattr_set_handle_prepared(handle_t *handle, struct inode *inode,
		int index, const char *name, const void *value, size_t len,
		int flags, struct ext4_xattr_deferred_iputs *deferred)
{
	(void)value;
	assert(handle != NULL && inode != NULL && index == 9 && !strcmp(name, "c"));
	assert(len == sizeof(struct fscrypt_context) && flags == 0 && deferred);
	if (!xattr_error)
		ext4_xattr_defer_iput(deferred, inode);
	return xattr_error;
}
static void ext4_set_inode_flag(struct inode *inode, int flag)
{
	assert(flag == EXT4_INODE_ENCRYPT);
	inode->ext4.flags |= 1;
}
static void ext4_clear_inode_state(struct inode *inode, int state)
{
	assert(state == EXT4_STATE_MAY_INLINE_DATA);
	inode->ext4.state &= ~1U;
}
static void ext4_set_inode_flags(struct inode *inode)
{
	assert(inode->ext4.flags & 1);
	inode_flags++;
}
static int ext4_mark_inode_dirty(handle_t *handle, struct inode *inode)
{
	assert(handle == &owned_handle && inode != NULL);
	marks++;
	return dirty_error;
}
#define EXT4_ERROR_INODE(...) ((void)0)
static bool ext4_should_retry_alloc(struct super_block *sb,
				    int *retries)
{
	(void)sb;
	retries_called++;
	(*retries)++;
	return retry_answer;
}
static void iput(struct inode *inode)
{
	assert(inode != NULL);
	assert(stops || !starts);
	iputs++;
}
static int fscrypt_ce_scope_open_cached(struct inode *inode, int purpose,
				       struct fscrypt_ce_scope **scope)
{
	(void)inode;
	assert(purpose == CHILD_WRAP);
	scope_opens++;
	*scope = &child_scope;
	return 0;
}
static int fscrypt_inherit_context_prepared(struct inode *parent,
		struct inode *child, void *fs_data, struct fscrypt_ce_scope *scope,
		bool preload)
{
	assert(parent && child);
	inherits++;
	inherit_fs_data = fs_data;
	inherit_scope = scope;
	inherit_preload = preload;
	return 0;
}
static void fscrypt_ce_scope_put(struct fscrypt_ce_scope *scope)
{
	assert(scope == &child_scope);
	scope_puts++;
}

static int extension, restarts, metadata_error;
#define ext4_handle_valid(handle) ((handle) != NULL)
#define ext4_warning(...) ((void)0)
static int ext4_journal_extend(handle_t *handle, int credits)
{
	(void)handle;
	(void)credits;
	return extension;
}
static int ext4_journal_restart(handle_t *handle, int credits)
{
	(void)handle;
	(void)credits;
	restarts++;
	return 0;
}
static void ext4_xattr_block_csum_set(struct inode *inode,
				     struct buffer_head *bh)
{
	(void)inode;
	(void)bh;
}
static int ext4_handle_dirty_metadata(handle_t *handle, void *inode,
				      struct buffer_head *bh)
{
	(void)handle;
	(void)inode;
	(void)bh;
	return metadata_error;
}
static int ext4_journal_get_write_access(handle_t *handle,
					 struct buffer_head *bh)
{
	(void)handle;
	(void)bh;
	return 0;
}

#include "subject_ext4.h"

static void reset_fixture(void)
{
	assert(allocation_balance == 0);
	order = inline_order = dquot_order = credits_order = start_order = 0;
	inline_error = quota_error = credits_error = xattr_error = dirty_error = 0;
	starts = stops = stop_error = retries_called = retry_answer = 0;
	marks = inode_flags = iputs = scope_opens = scope_puts = inherits = 0;
	inherit_scope = NULL;
	inherit_fs_data = NULL;
	inherit_preload = false;
	extension = restarts = metadata_error = 0;
	owned_handle.h_buffer_credits = 64;
}

int main(int argc, char **argv)
{
	struct fscrypt_operations cops = { .prepare_context = ext4_prepare_context };
	struct super_block sb = { .s_cop = &cops };
	struct inode inode = { .i_ino = 11, .i_sb = &sb, .ext4.state = 1, .id = 1 };
	struct inode parent = { .i_ino = 10, .i_sb = &sb, .id = 2 };
	struct fscrypt_context context = { 0 };
	struct fscrypt_context_op *op = NULL;
	int retry_count = 0;
	bool retry = false;
	int result;

	assert(argc == 2);
	reset_fixture();
	if (!strcmp(argv[1], "ext4-owned-root-inline-stop-retry-credit")) {
		inode.i_ino = EXT4_ROOT_INO;
		assert(ext4_prepare_context(&inode, FSCRYPT_CTX_OWNED_POLICY,
					   NULL, &op) == -EPERM && op == NULL);
		inode.i_ino = 11;
		assert(!ext4_prepare_context(&inode, FSCRYPT_CTX_OWNED_POLICY,
					    NULL, &op));
		assert(inline_order && inline_order < dquot_order &&
		       dquot_order < credits_order && credits_order < start_order);
		op->retry_count = &retry_count;
		assert(!ext4_set_context_prepared(&inode, &context, sizeof(context), op));
		stop_error = -EIO;
		result = ext4_finish_context(&inode, op, -ENOSPC, &retry);
		assert(result == -ENOSPC && !retry && stops == 1 && iputs == 1);
		assert(retries_called == 1 && retry_count == 1);

		reset_fixture();
		op = NULL;
		assert(!ext4_prepare_context(&inode, FSCRYPT_CTX_OWNED_POLICY,
					    NULL, &op));
		op->retry_count = &retry_count;
		stop_error = -EIO;
		assert(ext4_finish_context(&inode, op, 0, &retry) == -EIO);

		reset_fixture();
		retry_count = 0;
		op = NULL;
		assert(!ext4_prepare_context(&inode, FSCRYPT_CTX_OWNED_POLICY,
					    NULL, &op));
		op->retry_count = &retry_count;
		assert(!ext4_set_context_prepared(&inode, &context,
						 sizeof(context), op));
		stop_error = -ENOSPC;
		retry_answer = true;
		assert(ext4_finish_context(&inode, op, 0, &retry) == -ENOSPC);
		assert(retry && retries_called == 1 && retry_count == 1);

		reset_fixture();
		op = NULL;
		assert(!ext4_prepare_context(&inode, FSCRYPT_CTX_OWNED_POLICY,
					    NULL, &op));
		assert(ext4_finish_context(&inode, op, -EIO, NULL) == -EIO);
		assert(stops == 1 && allocation_balance == 0);

		owned_handle.h_buffer_credits = 19;
		assert(!ext4_xattr_ensure_credits(&owned_handle, &inode, 19,
						  NULL, false, false));
		assert(restarts == 0);
	} else if (!strcmp(argv[1], "ext4-borrowed-handle-flags-preload")) {
		handle_t borrowed = { .h_buffer_credits = 64 };
		assert(!ext4_prepare_context(&inode, FSCRYPT_CTX_BORROWED_INHERIT,
					    &borrowed, &op));
		assert(starts == 0 && dquot_order == 0 && op->fs_data == &borrowed);
		assert(!ext4_set_context_prepared(&inode, &context, sizeof(context), op));
		assert((inode.ext4.flags & 1) && !(inode.ext4.state & 1));
		assert(!ext4_finish_context(&inode, op, 0, &retry));
		assert(stops == 0 && iputs == 1);
		assert(!ext4_inherit_context(&parent, &inode, &borrowed));
		assert(scope_opens == 1 && scope_puts == 1 && inherits == 1);
		assert(inherit_scope == &child_scope && inherit_fs_data == &borrowed &&
		       inherit_preload);
	} else if (!strcmp(argv[1], "ext4-deferred-iput-array")) {
		struct ext4_xattr_deferred_iputs deferred = { 0 };
		struct inode inodes[EXT4_XATTR_MAX_DEFERRED_IPUTS + 1] = { 0 };
		unsigned int index;

		for (index = 0; index < EXT4_XATTR_MAX_DEFERRED_IPUTS; index++) {
			inodes[index].i_sb = &sb;
			inodes[index].id = index + 1;
			ext4_xattr_defer_iput(&deferred, &inodes[index]);
		}
		assert(iputs == 0 &&
		       deferred.count == EXT4_XATTR_MAX_DEFERRED_IPUTS);
		ext4_xattr_defer_iput(&deferred,
				       &inodes[EXT4_XATTR_MAX_DEFERRED_IPUTS]);
		assert(deferred.count == EXT4_XATTR_MAX_DEFERRED_IPUTS);
		ext4_xattr_drain_deferred_iputs(&deferred);
		assert(iputs == EXT4_XATTR_MAX_DEFERRED_IPUTS &&
		       deferred.count == 0);
	} else if (!strcmp(argv[1], "ext4-deferred-iput-direct")) {
		struct ext4_xattr_deferred_iputs deferred = { 0 };
		struct inode other = { .i_sb = &sb, .id = 3 };

		ext4_xattr_defer_iput(&deferred, &inode);
		ext4_xattr_defer_iput(&deferred, &other);
		assert(iputs == 0 && deferred.count == 2);
		ext4_xattr_drain_deferred_iputs(&deferred);
		assert(iputs == 2 && deferred.count == 0);
	} else {
		return 2;
	}
	assert(allocation_balance == 0);
	printf("PASS %s\n", argv[1]);
	return 0;
}
