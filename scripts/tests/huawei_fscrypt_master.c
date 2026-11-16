/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint64_t u64;
typedef atomic_int atomic_t;
typedef atomic_uint refcount_t;
#define U64_MAX UINT64_MAX
#define GFP_KERNEL 0
#define SHA256_DIGEST_SIZE 32
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define WARN_ON_ONCE(x) ({ bool bad = !!(x); assert(!bad); bad; })
#define atomic_read(p) atomic_load(p)
#define atomic_set(p, n) atomic_store(p, n)
#define atomic_dec(p) ((void)atomic_fetch_sub(p, 1))
static bool atomic_add_unless(atomic_t *p, int n, int unless)
{
    int v = atomic_load(p);
    do { if (v == unless) return false; }
    while (!atomic_compare_exchange_weak(p, &v, v + n));
    return true;
}
#define refcount_set(p,n) atomic_store(p,n)
#define refcount_read(p) atomic_load(p)
static void refcount_inc(refcount_t *p) { assert(atomic_fetch_add(p, 1) > 0); }
static bool refcount_dec_and_test(refcount_t *p) { unsigned n=atomic_fetch_sub(p,1); assert(n); return n==1; }
struct rw_semaphore { pthread_rwlock_t lock; };
static atomic_bool race_active,writer_blocked,finished;
static void init_rwsem(struct rw_semaphore *s) { assert(!pthread_rwlock_init(&s->lock,NULL)); }
static void down_read(struct rw_semaphore *s) { assert(!pthread_rwlock_rdlock(&s->lock)); }
static void up_read(struct rw_semaphore *s) { assert(!pthread_rwlock_unlock(&s->lock)); }
static void down_write(struct rw_semaphore *s)
{
    if(atomic_load(&race_active)) {
        assert(pthread_rwlock_trywrlock(&s->lock)==EBUSY);
        atomic_store(&writer_blocked,true);
    }
    assert(!pthread_rwlock_wrlock(&s->lock));
}
static void up_write(struct rw_semaphore *s) { assert(!pthread_rwlock_unlock(&s->lock)); }
static void memzero_explicit(void *p,size_t n) { volatile u8 *v=p; while(n--) *v++=0; }
static int crypto_memneq(const void *a,const void *b,size_t n) { return memcmp(a,b,n)!=0; }
static int fail_alloc,fail_hash_alloc,fail_digest,allocations,frees,hashes;
static void check_before_free(void *p);
static void *kzalloc(size_t n,int flags) { if(fail_alloc) return NULL; void *p=calloc(1,n); assert(p); allocations++; return p; }
static void kfree(void *p) { if(p) { check_before_free(p); frees++; free(p); } }
struct crypto_shash { int dummy; };
struct shash_desc { struct crypto_shash *tfm; int flags; };
#define SHASH_DESC_ON_STACK(n,t) struct shash_desc storage_##n = {0}, *n=&storage_##n
static struct crypto_shash *crypto_alloc_shash(const char *name,int t,int m) { assert(!strcmp(name,"sha256")); if(fail_hash_alloc) return ERR_PTR(-ENOMEM); hashes++; return calloc(1,sizeof(struct crypto_shash)); }
static void crypto_free_shash(struct crypto_shash *p) { hashes--; free(p); }
static int crypto_shash_digest(struct shash_desc *d,const u8 *data,size_t n,u8 *out) { if(fail_digest) { memset(out,0xa5,13); return -EIO; } assert(SHA256(data,n,out)); return 0; }
static void shash_desc_zero(struct shash_desc *d) { memzero_explicit(d,sizeof(*d)); }
#include "subject.h"
static void check_before_free(void *p)
{
#ifndef RED_STUB
    struct fscrypt_master_key *k=p;
    for(size_t i=0;i<sizeof(k->raw);i++) assert(k->raw[i]==0);
    for(size_t i=0;i<sizeof(k->fingerprint);i++) assert(k->fingerprint[i]==0);
    assert(!pthread_rwlock_destroy(&k->secret_sem.lock));
#endif
}

static u8 raw[64],other[64];
static struct fscrypt_master_key *make(void) { struct fscrypt_master_key *k=fscrypt_mk_alloc(raw,sizeof(raw)); assert(!IS_ERR(k)); return k; }
static void basic(void)
{
    struct fscrypt_master_key *k=make(); struct fscrypt_mk_lease l={0};
    assert(fscrypt_mk_status(k)==FSCRYPT_MK_PRESENT);
    assert(!fscrypt_mk_acquire(k,0,&l)); assert(l.generation==1);
    assert(!memcmp(fscrypt_mk_secret(&l),raw,64));
    fscrypt_mk_release(&l); assert(!l.key && !l.generation);
    fscrypt_mk_release(&l); fscrypt_mk_put(k);
}
static void remove_case(void)
{
    struct fscrypt_master_key *k=make(); struct fscrypt_mk_lease l={0};
    assert(!fscrypt_mk_remove(k)); assert(fscrypt_mk_status(k)==FSCRYPT_MK_ABSENT);
#ifndef RED_STUB
    for(size_t i=0;i<sizeof(k->raw);i++) assert(k->raw[i]==0);
#endif
    assert(fscrypt_mk_acquire(k,0,&l)==-ENOKEY); assert(!l.key);
    assert(!fscrypt_mk_remove(k)); fscrypt_mk_put(k);
}
static void owners(void)
{
    struct fscrypt_master_key *k=make(); struct fscrypt_mk_lease l={0}; struct fscrypt_mk_owner a={0},b={0};
    assert(!fscrypt_mk_acquire(k,0,&l)); assert(!fscrypt_mk_enroll(&l,&a)); assert(!fscrypt_mk_enroll(&l,&b)); fscrypt_mk_release(&l);
    assert(fscrypt_mk_remove(k)); assert(fscrypt_mk_status(k)==FSCRYPT_MK_BUSY);
    fscrypt_mk_drop_owner(&a); assert(fscrypt_mk_status(k)==FSCRYPT_MK_BUSY);
    fscrypt_mk_drop_owner(&b); assert(fscrypt_mk_status(k)==FSCRYPT_MK_ABSENT);
    fscrypt_mk_drop_owner(&b); fscrypt_mk_put(k);
}
static void readd(void)
{
    struct fscrypt_master_key *k=make(); struct fscrypt_mk_lease l={0}; struct fscrypt_mk_owner old={0},new={0};
    assert(!fscrypt_mk_acquire(k,0,&l)); assert(!fscrypt_mk_enroll(&l,&old)); fscrypt_mk_release(&l);
    assert(fscrypt_mk_remove(k)); assert(!fscrypt_mk_add(k,raw,64));
    assert(fscrypt_mk_status(k)==FSCRYPT_MK_PRESENT);
    assert(fscrypt_mk_acquire(k,old.generation,&l)==-ENOKEY);
    assert(!fscrypt_mk_acquire(k,0,&l)); assert(l.generation==2);
    assert(!fscrypt_mk_enroll(&l,&new)); fscrypt_mk_release(&l);
    fscrypt_mk_drop_owner(&old); assert(fscrypt_mk_remove(k));
    fscrypt_mk_drop_owner(&new); assert(fscrypt_mk_status(k)==FSCRYPT_MK_ABSENT); fscrypt_mk_put(k);
}
static void identity(void)
{
    struct fscrypt_master_key *k=make(); struct fscrypt_mk_lease l={0}; struct fscrypt_mk_owner o={0};
    assert(!fscrypt_mk_add(k,raw,64)); assert(fscrypt_mk_add(k,other,64)==-EKEYREJECTED);
    assert(!fscrypt_mk_acquire(k,0,&l)); assert(l.generation==1); assert(!fscrypt_mk_enroll(&l,&o)); fscrypt_mk_release(&l);
    fscrypt_mk_remove(k); assert(fscrypt_mk_add(k,other,64)==-EKEYREJECTED);
    assert(fscrypt_mk_status(k)==FSCRYPT_MK_BUSY); fscrypt_mk_drop_owner(&o);
    assert(!fscrypt_mk_add(k,other,64)); assert(!fscrypt_mk_acquire(k,0,&l));
    assert(!memcmp(fscrypt_mk_secret(&l),other,64)); fscrypt_mk_release(&l); fscrypt_mk_put(k);
}
static void generation(void)
{
    struct fscrypt_master_key *k=make(); struct fscrypt_mk_lease l={0};
    for(u64 g=1;g<40;g++) { assert(!fscrypt_mk_acquire(k,g,&l)); fscrypt_mk_release(&l); fscrypt_mk_remove(k); assert(!fscrypt_mk_add(k,raw,64)); }
    assert(fscrypt_mk_acquire(k,1,&l)==-ENOKEY); fscrypt_mk_put(k);
}
static void failures(void)
{
    assert(PTR_ERR(fscrypt_mk_alloc(NULL,64))==-EINVAL);
    assert(PTR_ERR(fscrypt_mk_alloc(raw,32))==-EINVAL);
    fail_alloc=1; assert(PTR_ERR(fscrypt_mk_alloc(raw,64))==-ENOMEM); fail_alloc=0;
    fail_hash_alloc=1; assert(PTR_ERR(fscrypt_mk_alloc(raw,64))==-ENOMEM); fail_hash_alloc=0;
    fail_digest=1; assert(PTR_ERR(fscrypt_mk_alloc(raw,64))==-EIO); fail_digest=0;
    struct fscrypt_master_key *k=make(); fscrypt_mk_remove(k);
    assert(fscrypt_mk_add(k,NULL,64)==-EINVAL);
    assert(fscrypt_mk_add(k,raw,63)==-EINVAL);
    fail_digest=1; assert(fscrypt_mk_add(k,raw,64)==-EIO); fail_digest=0;
    assert(fscrypt_mk_status(k)==FSCRYPT_MK_ABSENT); assert(!fscrypt_mk_add(k,raw,64)); fscrypt_mk_put(k);
}
static void tokens(void)
{
    struct fscrypt_master_key *k=make(); struct fscrypt_mk_lease l={0}; struct fscrypt_mk_owner o={0};
    assert(fscrypt_mk_enroll(&l,&o)==-EINVAL);
    assert(!fscrypt_mk_acquire(k,0,&l)); assert(fscrypt_mk_acquire(k,0,&l)==-EBUSY);
    assert(!fscrypt_mk_enroll(&l,&o)); assert(fscrypt_mk_enroll(&l,&o)==-EBUSY);
    fscrypt_mk_release(&l); fscrypt_mk_drop_owner(&o); assert(!o.key && !o.generation); fscrypt_mk_put(k);
}
static void lifetime(void)
{
    struct fscrypt_master_key *k=make(); struct fscrypt_mk_lease l={0}; struct fscrypt_mk_owner o={0};
    fscrypt_mk_get(k); fscrypt_mk_put(k);
    assert(!fscrypt_mk_acquire(k,0,&l)); assert(!fscrypt_mk_enroll(&l,&o));
    fscrypt_mk_put(k); assert(!memcmp(fscrypt_mk_secret(&l),raw,64));
    fscrypt_mk_release(&l); assert(frees==0); fscrypt_mk_drop_owner(&o);
}
static void *remover(void *p) { assert(fscrypt_mk_remove(p)); atomic_store(&finished,true); return NULL; }
static void admission_race(void)
{
    struct fscrypt_master_key *k=make(); struct fscrypt_mk_lease l={0}; struct fscrypt_mk_owner o={0}; pthread_t t;
    assert(!fscrypt_mk_acquire(k,0,&l)); atomic_store(&race_active,true);
    assert(!pthread_create(&t,NULL,remover,k));
    while(!atomic_load(&writer_blocked) && !atomic_load(&finished)) sched_yield();
    assert(atomic_load(&writer_blocked) && !atomic_load(&finished));
    assert(!fscrypt_mk_enroll(&l,&o)); fscrypt_mk_release(&l);
    assert(!pthread_join(t,NULL)); assert(atomic_load(&finished));
    atomic_store(&race_active,false);
    assert(fscrypt_mk_acquire(k,o.generation,&l)==-ENOKEY);
    fscrypt_mk_drop_owner(&o); fscrypt_mk_put(k);
}
static void overflow(void)
{
    struct fscrypt_master_key *k=make();
#ifndef RED_STUB
    struct fscrypt_mk_lease l={0}; struct fscrypt_mk_owner o={0};
    assert(!fscrypt_mk_acquire(k,0,&l)); atomic_set(&k->owners,INT_MAX);
    assert(fscrypt_mk_enroll(&l,&o)==-EOVERFLOW); assert(!o.key);
    assert(refcount_read(&k->refs)==2); atomic_set(&k->owners,0); fscrypt_mk_release(&l);
    fscrypt_mk_remove(k); k->generation=U64_MAX;
    assert(fscrypt_mk_add(k,raw,64)==-EOVERFLOW);
    assert(k->generation==U64_MAX && fscrypt_mk_status(k)==FSCRYPT_MK_ABSENT);
#endif
    fscrypt_mk_put(k);
}
static void immutable(void)
{
    u8 input[64]; memcpy(input,raw,64);
    struct fscrypt_master_key *k=fscrypt_mk_alloc(input,64); assert(!IS_ERR(k));
    struct fscrypt_mk_lease l={0}; input[0]^=1;
    assert(!fscrypt_mk_acquire(k,0,&l)); assert(!memcmp(fscrypt_mk_secret(&l),raw,64));
    fscrypt_mk_release(&l); fscrypt_mk_remove(k);
    assert(input[0]==(u8)(raw[0]^1)); fscrypt_mk_put(k);
}
static void backend_failure_preserves(void)
{
    struct fscrypt_master_key *k=make();
#ifndef RED_STUB
    struct fscrypt_mk_lease l={0}; struct fscrypt_mk_owner o={0};
    assert(!fscrypt_mk_acquire(k,0,&l)); assert(!fscrypt_mk_enroll(&l,&o)); fscrypt_mk_release(&l);
    for(int busy=0;busy<2;busy++) {
        if(busy) assert(fscrypt_mk_remove(k));
        u8 secret[64],fingerprint[32]; memcpy(secret,k->raw,64); memcpy(fingerprint,k->fingerprint,32);
        u64 generation=k->generation; unsigned refs=refcount_read(&k->refs); int owners=atomic_read(&k->owners);
        for(int allocation=0;allocation<2;allocation++) {
            fail_hash_alloc=allocation; fail_digest=!allocation;
            assert(fscrypt_mk_add(k,other,64)==(allocation ? -ENOMEM : -EIO));
            fail_hash_alloc=fail_digest=0;
            assert(!memcmp(secret,k->raw,64)); assert(!memcmp(fingerprint,k->fingerprint,32));
            assert(k->generation==generation && refcount_read(&k->refs)==refs && atomic_read(&k->owners)==owners);
            assert(fscrypt_mk_status(k)==(busy ? FSCRYPT_MK_BUSY : FSCRYPT_MK_PRESENT));
        }
    }
    fscrypt_mk_drop_owner(&o);
#endif
    fscrypt_mk_put(k);
}
int main(int argc,char **argv)
{
    assert(argc==2); for(int i=0;i<64;i++) raw[i]=(u8)(i+7); memcpy(other,raw,64); other[63]^=0x80;
    const char *n=argv[1];
    if(!strcmp(n,"basic")) basic(); else if(!strcmp(n,"remove")) remove_case(); else if(!strcmp(n,"owners")) owners();
    else if(!strcmp(n,"readd")) readd(); else if(!strcmp(n,"identity")) identity(); else if(!strcmp(n,"generation")) generation();
    else if(!strcmp(n,"failures")) failures(); else if(!strcmp(n,"tokens")) tokens(); else if(!strcmp(n,"lifetime")) lifetime();
    else if(!strcmp(n,"admission-race")) admission_race(); else if(!strcmp(n,"overflow")) overflow();
    else if(!strcmp(n,"immutable")) immutable();
    else if(!strcmp(n,"backend-failure-preserves")) backend_failure_preserves(); else abort();
    assert(allocations==frees); assert(hashes==0); puts("PASS");
}
