/* SPDX-License-Identifier: GPL-2.0 */
/* Sequential model bridge, never a kernel or filesystem API. */
#ifndef HUAWEI_FSCRYPT_VOLD_MODEL_H
#define HUAWEI_FSCRYPT_VOLD_MODEL_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
struct model_stats {
    unsigned generation, owners, readers, refs, acquired, released, transferred;
    int present, managed, secret_zero;
};
void model_reset(void);
int model_add(const unsigned char *bytes, size_t size);
int model_remove(void);
unsigned model_status(void);
int model_begin(unsigned candidate);
int model_publish(unsigned candidate, unsigned inode);
int model_abort(unsigned candidate);
int model_inode_drop(unsigned inode);
void model_inode_flags(unsigned inode, int busy, int dirty);
int model_access(unsigned inode);
int model_wrap_allowed(unsigned inode);
int model_inherit_begin(unsigned inode);
int model_inherit_end(void);
int model_lookup(void);
void model_failure(unsigned stage);
struct model_stats model_get_stats(void);
#ifdef __cplusplus
}
#endif
#endif
