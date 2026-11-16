/* SPDX-License-Identifier: GPL-2.0 */
#include "core-shim.h"
#include "core.h"
static void check_before_free(void *p)
{
    struct fscrypt_master_key *k=p;
    for(size_t i=0;i<sizeof(k->raw);i++) assert(!k->raw[i]);
    for(size_t i=0;i<sizeof(k->fingerprint);i++) assert(!k->fingerprint[i]);
    assert(!pthread_rwlock_destroy(&k->secret_sem.lock));
}
#define __init
#define __exit
#define CONFIG_FS_ENCRYPTION 1
#define IS_ENABLED(x) (x)
#define FS_KEY_DESCRIPTOR_SIZE 8
#define CAP_SYS_ADMIN 21
#define GLOBAL_ROOT_UID 0
#define GLOBAL_ROOT_GID 0
#define KEY_POS_SEARCH 0x08000000
#define KEY_USR_SEARCH 0x00080000
#define KEY_USR_READ 0x00020000
#define KEY_USR_VIEW 0x00010000
#define KEY_ALLOC_NOT_IN_QUOTA 2
#define KEY_FLAG_KEEP 8
#define KEY_FLAG_INVALIDATED 5
#define KEY_FLAG_REVOKED 1
#define KEY_GRP_ALL 0x3f00
#define KEY_NEED_ALL 0x3f
#define KEY_NEED_LINK 0x10
#define KEY_NEED_VIEW 0x01
typedef unsigned int key_perm_t;
#define KEY_FLAG_ROOT_CAN_INVAL 7
#define KEY_NEED_SEARCH 8
#define kenter(...) ((void)0)
#define kleave(...) ((void)0)
typedef int key_serial_t;
static bool test_bit(int bit,const unsigned long *p) { return (*p & (1UL<<bit))!=0; }
static void set_bit(int bit,unsigned long *p) { *p |= 1UL<<bit; }
#define ERR_CAST(p) ((void *)(p))
#define DEFINE_MUTEX(n) pthread_mutex_t n=PTHREAD_MUTEX_INITIALIZER
#define mutex_lock(p) assert(!pthread_mutex_lock(p))
#define mutex_unlock(p) assert(!pthread_mutex_unlock(p))
#define smp_load_acquire(p) __atomic_load_n(p,__ATOMIC_ACQUIRE)
#define smp_store_release(p,v) __atomic_store_n(p,v,__ATOMIC_RELEASE)
#define READ_ONCE(x) __atomic_load_n(&(x),__ATOMIC_RELAXED)
struct module { int refs; bool going; };
static struct module test_module;
#define THIS_MODULE (&test_module)
static bool try_module_get(struct module *m) { if(m->going)return false; m->refs++;return true; }
static void module_put(struct module *m) { if(m) { assert(m->refs>0);m->refs--; } }
static bool admin=true;
static bool capable(int cap) { assert(cap==CAP_SYS_ADMIN);return admin; }
struct cred { int fsuid, fsgid; void *group_info; };
static struct cred test_cred;
static const struct cred *current_cred(void) { return &test_cred; }
static bool uid_eq(int a,int b) { return a==b; }
static bool gid_eq(int a,int b) { return a==b; }
static bool gid_valid(int g) { return g>=0; }
static bool groups_search(void *groups,int g) { return false; }
struct seq_file { char data[128]; };
static void seq_puts(struct seq_file *m,const char *s) { strcat(m->data,s); }
static char *bin2hex(char *out,const void *in,size_t n) { static const char h[]="0123456789abcdef";const u8 *p=in;while(n--){*out++=h[*p>>4];*out++=h[*p++&15];}return out; }
struct key;
struct key_preparsed_payload { const void *data; size_t datalen; };
struct key_type { const char *name;int(*instantiate)(struct key *,struct key_preparsed_payload *);void(*destroy)(struct key *);void(*describe)(const struct key *,struct seq_file *); };
struct key { key_perm_t perm; int uid,gid; unsigned long flags;atomic_int refs;struct key_type *type;char *description;struct { void *data[1]; } payload;struct rw_semaphore sem;bool positive,ring;int state_error;pthread_mutex_t links_lock;struct key *links[32];size_t count;struct key *gc_next; };
struct super_block { char s_id[32];struct key *s_fscrypt_keys;struct module *s_fscrypt_keys_owner; };
typedef struct key *key_ref_t;
static struct key_type *registered;
static struct key *garbage,*test_first_ring;
static int registration_error,ring_error,key_error,link_error,search_error,keys_created,keys_destroyed;
static int register_key_type(struct key_type *t) { if(registration_error)return registration_error;assert(!registered);registered=t;return 0; }
static void collect(void);
static void unregister_key_type(struct key_type *t) { assert(registered==t);assert(!test_module.refs);collect();registered=NULL; }
static int interleave_kind,interleave_count;
static long interleave_result;
static void publication_interleave(struct key *k);
static struct key *new_key(struct key_type *t,const char *d,bool ring,key_perm_t perm)
{
 struct key *k=calloc(1,sizeof(*k));assert(k);atomic_init(&k->refs,1);k->type=t;k->description=strdup(d);k->ring=ring;k->perm=perm;k->uid=GLOBAL_ROOT_UID;k->gid=GLOBAL_ROOT_GID;init_rwsem(&k->sem);assert(!pthread_mutex_init(&k->links_lock,NULL));keys_created++;return k;
}
static struct key *keyring_alloc(const char *d,int uid,int gid,const struct cred *cred,int perm,int flags,void *restriction,void *dest)
{
 assert(!uid&&!gid&&cred==current_cred()&&flags==KEY_ALLOC_NOT_IN_QUOTA);
 if(ring_error)return ERR_PTR(ring_error);struct key *k=new_key(NULL,d,true,perm);k->positive=true;if(!test_first_ring)test_first_ring=k;
 /* keyring_alloc publishes its instantiated ring before returning. */
 publication_interleave(k);return k;
}
static struct key *key_alloc(struct key_type *t,const char *d,int uid,int gid,const struct cred *cred,int perm,int flags,void *restriction)
{
 assert(t==registered&&!uid&&!gid&&cred==current_cred()&&flags==KEY_ALLOC_NOT_IN_QUOTA);
 if(key_error)return ERR_PTR(key_error);return new_key(t,d,false,perm);
}
static void key_put(struct key *k)
{
 if(!k)return;assert(!IS_ERR(k));int n=atomic_fetch_sub(&k->refs,1);assert(n>0);
 if(n==1){k->gc_next=garbage;garbage=k;}
}
static void collect(void)
{
 while(garbage){struct key *k=garbage;garbage=k->gc_next;
  if(k->ring){for(size_t i=0;i<k->count;i++)key_put(k->links[i]);}
  else if(k->positive){assert(registered==k->type);k->type->destroy(k);}
  assert(!pthread_rwlock_destroy(&k->sem.lock));assert(!pthread_mutex_destroy(&k->links_lock));free(k->description);free(k);keys_destroyed++;
 }
}
static int key_instantiate_and_link(struct key *k,const void *data,size_t len,struct key *ring,void *auth)
{
 /* Real key.c completes all fallible link preparation BEFORE instantiate. */
 if(link_error)return link_error;
 struct key_preparsed_payload prep={data,len};int err=k->type->instantiate(k,&prep);if(err)return err;
 /* key.c publishes positive state before inheriting KEEP. Direct serial
  * lookup waits for construction, so interleave at precisely this boundary. */
 k->positive=true;publication_interleave(k);if(test_bit(KEY_FLAG_KEEP,&ring->flags))set_bit(KEY_FLAG_KEEP,&k->flags);assert(!pthread_mutex_lock(&ring->links_lock));assert(ring->count<32);atomic_fetch_add(&k->refs,1);ring->links[ring->count++]=k;assert(!pthread_mutex_unlock(&ring->links_lock));return 0;
}
static key_ref_t make_key_ref(struct key *k,bool possessed){return (key_ref_t)((uintptr_t)k|(possessed?1UL:0UL));}
static struct key *key_ref_to_ptr(key_ref_t k){return (struct key *)((uintptr_t)k&~1UL);}
static bool is_key_possessed(key_ref_t k){return (uintptr_t)k&1UL;}
static int lsm_error;
static int security_key_permission(key_ref_t key,const struct cred *cred,unsigned perm){return lsm_error;}
#include "permission.h"
static bool key_is_positive(const struct key *k){return k->positive;}
static int key_validate(const struct key *k){return k->state_error;}
static key_ref_t keyring_search(key_ref_t ring_ref,struct key_type *t,const char *d)
{
 struct key *ring=key_ref_to_ptr(ring_ref);
 if(search_error)return ERR_PTR(search_error);
 int err=key_task_permission(ring_ref,current_cred(),KEY_NEED_SEARCH);
 if(err)return ERR_PTR(err);
 /* Real search_nested_keyrings skips an invalidated root, leaving EAGAIN. */
 if(ring->flags&((1UL<<KEY_FLAG_INVALIDATED)|(1UL<<KEY_FLAG_REVOKED)))return ERR_PTR(-EAGAIN);
 assert(!pthread_mutex_lock(&ring->links_lock));key_ref_t result=ERR_PTR(-EAGAIN);
 for(size_t i=0;i<ring->count;i++){
  struct key *k=ring->links[i];
  if(k->type!=t||strcmp(k->description,d))continue;
  key_ref_t ref=make_key_ref(k,is_key_possessed(ring_ref));
  if(k->flags&((1UL<<KEY_FLAG_INVALIDATED)|(1UL<<KEY_FLAG_REVOKED)))result=ERR_PTR(-EKEYREVOKED);
  else if(k->state_error)result=ERR_PTR(k->state_error);
  else if(key_task_permission(ref,current_cred(),KEY_NEED_SEARCH))result=ERR_PTR(-EACCES);
  else {atomic_fetch_add(&k->refs,1);result=ref;}
  break;
 }
 assert(!pthread_mutex_unlock(&ring->links_lock));return result;
}
static struct key *invalidate_target;
/* Private keys are not linked into a process keyring. The KEEP-only test
 * explicitly supplies synthetic possession to exercise that separate guard. */
static bool invalidate_possessed;
static key_ref_t lookup_user_key(key_serial_t id,int flags,int perm)
{
 assert(invalidate_target&&invalidate_target->positive);
 key_ref_t ref=make_key_ref(invalidate_target,invalidate_possessed);
 int err=key_task_permission(ref,current_cred(),perm);
 if(err)return ERR_PTR(err);
 atomic_fetch_add(&invalidate_target->refs,1);return ref;
}
static void key_ref_put(key_ref_t k) { key_put(key_ref_to_ptr(k)); }
static bool test_and_set_bit(int bit,unsigned long *p){bool old=test_bit(bit,p);set_bit(bit,p);return old;}
#define key_check(k) ((void)0)
#define down_write_nested(s,n) down_write(s)
#define key_schedule_gc_links() ((void)0)
#include "key-invalidate.h"
#include "invalidate.h"
static void publication_interleave(struct key *k)
{
 if(!interleave_kind||((interleave_kind==1)!=k->ring))return;
 assert(k->positive&&!test_bit(KEY_FLAG_KEEP,&k->flags));
 assert(!invalidate_possessed&&admin&&current_cred()->fsuid==GLOBAL_ROOT_UID);
 interleave_count++;
 invalidate_target=k;
 interleave_result=keyctl_invalidate_key(1);
}
#define WQ_HIGHPRI 1
#define SLAB_RECLAIM_ACCOUNT 1
static void *fscrypt_read_workqueue,*fscrypt_ctx_cachep,*fscrypt_info_cachep;
static int resource_step,resource_fail,resources;
static void *resource_alloc(void){resource_step++;if(resource_step==resource_fail)return NULL;resources++;return malloc(1);}
static void resource_free(void *p){assert(p&&resources>0);resources--;free(p);}
#define alloc_workqueue(...) resource_alloc()
#define KMEM_CACHE(...) resource_alloc()
#define destroy_workqueue(p) resource_free(p)
#define kmem_cache_destroy(p) resource_free(p)
static void fscrypt_destroy(void){assert(!registered);}
static void fscrypt_essiv_cleanup(void){}
#include "subject.h"
static const u8 descriptor[8]={0,1,2,3,0xfc,0xfd,0xfe,0xff};
static u8 raw[64],other[64];
static struct super_block make_sb(void){struct super_block s={0};strcpy(s.s_id,"same-device-label");return s;}
static struct fscrypt_master_key *lookup(struct super_block *s){struct fscrypt_master_key *k=fscrypt_registry_lookup(s,descriptor);assert(!IS_ERR(k));return k;}
static void add(struct super_block *s){assert(!fscrypt_registry_add(s,descriptor,raw,64));}
static void release_sb(struct super_block *s){fscrypt_registry_sb_free(s);assert(!s->s_fscrypt_keys&&!s->s_fscrypt_keys_owner);collect();}
static void namespace_case(void){struct super_block a=make_sb(),b=make_sb();add(&a);assert(PTR_ERR(fscrypt_registry_lookup(&b,descriptor))==-ENOENT);assert(!fscrypt_registry_add(&b,descriptor,other,64));struct fscrypt_master_key *x=lookup(&a),*y=lookup(&b);assert(x!=y);assert(!memcmp(x->raw,raw,64)&&!memcmp(y->raw,other,64));fscrypt_mk_remove(x);assert(fscrypt_mk_status(y)==FSCRYPT_MK_PRESENT);fscrypt_mk_put(x);fscrypt_mk_put(y);release_sb(&a);release_sb(&b);}
static pthread_barrier_t first_barrier;
static void *add_thread(void *s){int ret=pthread_barrier_wait(&first_barrier);assert(ret==0||ret==PTHREAD_BARRIER_SERIAL_THREAD);add(s);return NULL;}
static void concurrent_first(void){struct super_block s=make_sb();pthread_t t[8];assert(!pthread_barrier_init(&first_barrier,NULL,8));for(int i=0;i<8;i++)assert(!pthread_create(&t[i],NULL,add_thread,&s));for(int i=0;i<8;i++)assert(!pthread_join(t[i],NULL));assert(s.s_fscrypt_keys->count==1&&test_module.refs==1);struct fscrypt_master_key *k=lookup(&s);assert(k->generation==1&&refcount_read(&k->refs)==2);fscrypt_mk_put(k);release_sb(&s);assert(!pthread_barrier_destroy(&first_barrier));}
static void duplicate(void){struct super_block s=make_sb();add(&s);struct fscrypt_master_key *k=lookup(&s);add(&s);assert(fscrypt_registry_add(&s,descriptor,other,64)==-EKEYREJECTED);struct fscrypt_master_key *j=lookup(&s);assert(k==j&&k->generation==1&&!memcmp(k->raw,raw,64));fscrypt_mk_put(j);fscrypt_mk_put(k);release_sb(&s);}
static void root_case(void){struct super_block s=make_sb();admin=false;assert(fscrypt_registry_add(&s,descriptor,raw,64)==-EPERM);assert(!s.s_fscrypt_keys&&!allocations&&!test_module.refs);admin=true;add(&s);admin=false;struct fscrypt_master_key *k=lookup(&s);fscrypt_mk_put(k);assert(fscrypt_registry_add(&s,descriptor,raw,64)==-EPERM);admin=true;release_sb(&s);}
static void format_case(void){struct super_block s=make_sb();assert(fscrypt_registry_add(&s,NULL,raw,64)==-EINVAL);assert(fscrypt_registry_add(&s,descriptor,NULL,64)==-EINVAL);for(size_t n=0;n<=65;n++)if(n!=64)assert(fscrypt_registry_add(&s,descriptor,raw,n)==-EINVAL);assert(!s.s_fscrypt_keys&&!test_module.refs);assert(PTR_ERR(fscrypt_registry_lookup(&s,NULL))==-EINVAL);}
static void missing(void){struct super_block s=make_sb();assert(PTR_ERR(fscrypt_registry_lookup(&s,descriptor))==-ENOENT);add(&s);u8 absent[8]={0};assert(PTR_ERR(fscrypt_registry_lookup(&s,absent))==-ENOENT);release_sb(&s);}
static void errors(void){struct super_block s=make_sb();add(&s);int errs[]={-EACCES,-EPERM,-ENOMEM,-ENOKEY,-EKEYREVOKED,-EKEYEXPIRED,-EIO};for(size_t i=0;i<sizeof(errs)/sizeof(*errs);i++){search_error=errs[i];assert(PTR_ERR(fscrypt_registry_lookup(&s,descriptor))==errs[i]);assert(fscrypt_registry_add(&s,descriptor,raw,64)==errs[i]);assert(s.s_fscrypt_keys->count==1);}search_error=0;release_sb(&s);}
static void tombstone(void){struct super_block s=make_sb();add(&s);struct fscrypt_master_key *k=lookup(&s);fscrypt_mk_remove(k);fscrypt_mk_put(k);collect();k=lookup(&s);assert(fscrypt_mk_status(k)==FSCRYPT_MK_ABSENT);struct fscrypt_mk_lease l={0};assert(fscrypt_mk_acquire(k,0,&l)==-ENOKEY);fscrypt_mk_put(k);release_sb(&s);}
static void readd(void){struct super_block s=make_sb();add(&s);struct fscrypt_master_key *k=lookup(&s);fscrypt_mk_remove(k);add(&s);struct fscrypt_master_key *j=lookup(&s);assert(k==j&&k->generation==2);fscrypt_mk_put(j);fscrypt_mk_put(k);release_sb(&s);}
static void stable_ref(void){struct super_block s=make_sb();add(&s);struct fscrypt_master_key *k=lookup(&s);release_sb(&s);assert(refcount_read(&k->refs)==1);assert(fscrypt_mk_status(k)==FSCRYPT_MK_ABSENT);fscrypt_mk_put(k);}
static void failures(void){struct super_block s=make_sb();ring_error=-EDQUOT;assert(fscrypt_registry_add(&s,descriptor,raw,64)==-EDQUOT);assert(!s.s_fscrypt_keys&&!test_module.refs);ring_error=0;key_error=-EACCES;assert(fscrypt_registry_add(&s,descriptor,raw,64)==-EACCES);key_error=0;assert(PTR_ERR(fscrypt_registry_lookup(&s,descriptor))==-ENOENT);collect();assert(allocations==frees);link_error=-ENOMEM;assert(fscrypt_registry_add(&s,descriptor,raw,64)==-ENOMEM);link_error=0;collect();assert(allocations==frees);fail_alloc=1;assert(fscrypt_registry_add(&s,descriptor,raw,64)==-ENOMEM);fail_alloc=0;fail_digest=1;assert(fscrypt_registry_add(&s,descriptor,raw,64)==-EIO);fail_digest=0;add(&s);release_sb(&s);}
static void module_case(void){struct super_block s=make_sb();test_module.going=true;assert(fscrypt_registry_add(&s,descriptor,raw,64)==-ENODEV);assert(!s.s_fscrypt_keys&&!test_module.refs);test_module.going=false;add(&s);assert(test_module.refs==1);fscrypt_registry_sb_free(&s);assert(test_module.refs==0);fscrypt_registry_sb_free(&s);collect();}
static void register_failure(void){fscrypt_registry_exit();registration_error=-EEXIST;assert(fscrypt_registry_init()==-EEXIST);assert(!registered);registration_error=0;assert(!fscrypt_registry_init());}
static void payload_null(void){struct super_block s=make_sb();add(&s);struct key *k=s.s_fscrypt_keys->links[0];void *save=k->payload.data[0];k->payload.data[0]=NULL;assert(PTR_ERR(fscrypt_registry_lookup(&s,descriptor))==-EBADMSG);k->payload.data[0]=save;release_sb(&s);}
static void init_unwind(void){fscrypt_registry_exit();for(int i=1;i<=3;i++){resource_step=0;resource_fail=i;assert(fscrypt_init()==-ENOMEM);assert(!resources&&!registered);}resource_fail=0;resource_step=0;registration_error=-EEXIST;assert(fscrypt_init()==-EEXIST);assert(!resources&&!registered);registration_error=0;resource_step=0;assert(!fscrypt_init());assert(resources==3&&registered);fscrypt_exit();assert(!resources&&!registered);assert(!fscrypt_registry_init());}
static void keep(void){struct super_block s=make_sb();add(&s);invalidate_possessed=true;struct fscrypt_master_key *k=lookup(&s);fscrypt_mk_remove(k);fscrypt_mk_put(k);invalidate_target=s.s_fscrypt_keys;assert(keyctl_invalidate_key(1)==-EPERM);invalidate_target=s.s_fscrypt_keys->links[0];assert(keyctl_invalidate_key(1)==-EPERM);invalidate_possessed=false;k=lookup(&s);assert(fscrypt_mk_status(k)==FSCRYPT_MK_ABSENT);fscrypt_mk_put(k);release_sb(&s);}
static void publication_case(int kind)
{
 struct super_block s=make_sb();
 interleave_kind=kind;
 int added=fscrypt_registry_add(&s,descriptor,raw,64);
 interleave_kind=0;
 struct fscrypt_master_key *k=fscrypt_registry_lookup(&s,descriptor);
 printf("%s: ADD=%d invalidate=%ld lookup=%ld interleavings=%d\n",
        kind==1?"ring":"entry",added,interleave_result,
        IS_ERR(k)?(long)PTR_ERR(k):0L,interleave_count);
 fflush(stdout);
 assert(added==0&&interleave_count==1&&interleave_result==-EACCES);
 assert(!test_bit(KEY_FLAG_INVALIDATED,&invalidate_target->flags));
 assert(test_bit(KEY_FLAG_KEEP,&invalidate_target->flags));
 assert(!IS_ERR(k)&&fscrypt_mk_status(k)==FSCRYPT_MK_PRESENT);
 fscrypt_mk_remove(k);
 struct fscrypt_master_key *again=lookup(&s);
 assert(again==k&&fscrypt_mk_status(again)==FSCRYPT_MK_ABSENT);
 fscrypt_mk_put(again);fscrypt_mk_put(k);release_sb(&s);
}
static void publication_ring(void){publication_case(1);}
static void publication_entry(void){publication_case(2);}
static void permissions(void)
{
 struct super_block s=make_sb();add(&s);
 struct key *targets[]={s.s_fscrypt_keys,s.s_fscrypt_keys->links[0]};
 for(size_t i=0;i<2;i++){
  assert(key_task_permission(make_key_ref(targets[i],false),current_cred(),KEY_NEED_SEARCH)==-EACCES);
  assert(key_task_permission(make_key_ref(targets[i],false),current_cred(),KEY_NEED_LINK)==-EACCES);
  assert(key_task_permission(make_key_ref(targets[i],false),current_cred(),KEY_NEED_VIEW)==0);
  assert(key_task_permission(make_key_ref(targets[i],true),current_cred(),KEY_NEED_SEARCH)==0);
 }
 /* Possessed lookup remains available to non-root consumers, subject to LSM. */
 test_cred.fsuid=1000;test_cred.fsgid=1000;admin=false;
 struct fscrypt_master_key *k=lookup(&s);fscrypt_mk_put(k);
 lsm_error=-EACCES;
 assert(PTR_ERR(fscrypt_registry_lookup(&s,descriptor))==-EACCES);
 lsm_error=0;admin=true;test_cred.fsuid=0;test_cred.fsgid=0;release_sb(&s);
}
static void description(void){struct super_block s=make_sb();add(&s);struct key *k=s.s_fscrypt_keys->links[0];assert(!strcmp(k->description,"00010203fcfdfeff"));assert(registered->name[0]=='.');struct seq_file m={0};k->type->describe(k,&m);assert(!strcmp(m.data,"00010203fcfdfeff"));release_sb(&s);}
int main(int argc,char **argv){assert(argc==2);memset(raw,0x35,64);memset(other,0x97,64);assert(!fscrypt_registry_init());
#define CASE(n,f) if(!strcmp(argv[1],n))f();else
CASE("namespace",namespace_case) CASE("concurrent-first",concurrent_first) CASE("duplicate",duplicate) CASE("root",root_case) CASE("format",format_case) CASE("missing",missing) CASE("errors",errors) CASE("tombstone",tombstone) CASE("readd",readd) CASE("stable-ref",stable_ref) CASE("failures",failures) CASE("module",module_case) CASE("register-failure",register_failure) CASE("payload-null",payload_null) CASE("description",description) CASE("keep",keep) CASE("init-unwind",init_unwind) CASE("publication-ring",publication_ring) CASE("publication-entry",publication_entry) CASE("permissions",permissions) assert(false);
fscrypt_registry_exit();assert(!registered&&!test_module.refs);assert(keys_created==keys_destroyed&&allocations==frees&&!hashes);return 0;}
