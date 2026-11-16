/* SPDX-License-Identifier: GPL-2.0 */
/* Storage, security, charging and workqueue doubles. BTF and map paths are real. */
typedef struct { int count; } atomic_t;
typedef struct { long long count; } atomic64_t;
struct mutex { bool initialized; };
static void mutex_init(struct mutex *m) {m->initialized=true;}
static void atomic64_set(atomic64_t *p,long long n) {p->count=n;}
static void *memchr_inv(const void *data,int value,size_t length)
{
	const u8 *p=data;
	for(size_t i=0;i<length;i++) if(p[i]!=(u8)value) return (void *)(p+i);
	return NULL;
}
static void atomic_set(atomic_t *p, int n) { p->count=n; }
static bool atomic_dec_and_test(atomic_t *p) { CHECK(p->count>0); return !--p->count; }
struct work_struct { void (*fn)(struct work_struct *); };
struct user_struct { int unused; };
#define ____cacheline_aligned
#define INIT_WORK(p,f) ((p)->fn=(f))
static void schedule_work(struct work_struct *w) { w->fn(w); }
struct bpf_map;
struct vm_area_struct;
struct poll_table_struct;
#include "map_structures.h"

static int storage_error, alloc_security_error, charge_error, map_id_error, open_security_error;
static unsigned storage_live, security_live, charge_live, map_ids;
static bool hold_published;
static struct bpf_map *held_map;
static struct bpf_map *last_map;
static int bpf_map_release(struct inode *,struct file *);
static const struct file_operations bpf_map_fops={.release=bpf_map_release};

static struct bpf_map *storage_alloc(union bpf_attr *a)
{
	if(storage_error) return ERR_PTR(storage_error);
	struct bpf_map *m=host_alloc(sizeof(*m),true);
	if(!m) return ERR_PTR(-ENOMEM);
	m->key_size=a->key_size;m->value_size=a->value_size;
	m->max_entries=a->max_entries;m->map_flags=a->map_flags;
	storage_live++;last_map=m;return m;
}
static void storage_free(struct bpf_map *m)
{
	CHECK(storage_live);storage_live--;
	if(m->btf) CHECK(m->btf->refcnt.refs>0); /* valid through storage release */
	host_free(m);
}
#include "array_subject.c"
#include "array_registration.h"
static const struct bpf_map_ops hash_map_ops={.map_alloc=storage_alloc,.map_free=storage_free};
static struct bpf_map *find_and_alloc_map(union bpf_attr *a)
{
	struct bpf_map *m=storage_alloc(a);
	if(IS_ERR(m)) return m;
	m->map_type=a->map_type;
	m->ops=a->map_type==BPF_MAP_TYPE_ARRAY?&array_map_ops:&hash_map_ops;
	return m;
}
static int security_bpf_map_alloc(struct bpf_map *m)
{ (void)m;if(alloc_security_error)return alloc_security_error;security_live++;return 0; }
static void security_bpf_map_free(struct bpf_map *m)
{ (void)m;CHECK(security_live);security_live--; }
static int bpf_map_charge_memlock(struct bpf_map *m)
{ (void)m;if(charge_error)return charge_error;charge_live++;return 0; }
static void bpf_map_uncharge_memlock(struct bpf_map *m)
{ (void)m;CHECK(charge_live);charge_live--; }
static int bpf_map_alloc_id(struct bpf_map *m)
{
	if(map_id_error)return map_id_error;
	m->id=100;map_ids++;
	if(hold_published){m->refcnt.count++;m->usercnt.count++;held_map=m;}
	return 0;
}
static void bpf_map_free_id(struct bpf_map *m,bool lock)
{ (void)m;(void)lock;CHECK(map_ids);map_ids--; }
#define NUMA_NO_NODE (-1)
static unsigned nr_node_ids=1;
static bool node_online(int n) { return n==0; }
static int bpf_map_attr_numa_node(const union bpf_attr *a)
{ return (a->map_flags&BPF_F_NUMA_NODE)?(int)a->numa_node:NUMA_NO_NODE; }
#define OPEN_FMODE(flags) (flags)
static int security_bpf_map(struct bpf_map *m,int flags)
{ (void)m;(void)flags;return open_security_error; }
#define trace_bpf_map_create(m,fd) ((void)(m),(void)(fd))

#include "map_subject.c"

#define CAP_SYS_ADMIN 21
#define unlikely(x) (x)
#define PAGE_SIZE 4096
#define VERIFY_READ 0
static bool host_admin=true;
static bool capable(int capability) { CHECK(capability==CAP_SYS_ADMIN);return host_admin; }
static bool access_ok(int operation,const void *p,size_t size)
{ CHECK(operation==VERIFY_READ);return !size||p!=NULL; }
#define get_user(value,p) ({ (value)=*(p);0; })
static const struct file_operations bpf_prog_fops={0};
static int bpf_prog_get_info_by_fd(void *prog,const union bpf_attr *attr,union bpf_attr *uattr)
{ (void)prog;(void)attr;(void)uattr;return -EOPNOTSUPP; }
#include "gateway_subject.c"

static void maps_balanced(void)
{
	CHECK(!storage_live&&!security_live&&!charge_live&&!map_ids&&!held_map);
}
static void maps_reset(void)
{
	storage_error=alloc_security_error=charge_error=map_id_error=open_security_error=0;
	hold_published=false;host_reset_faults();
}
static union bpf_attr map_attr(int fd,u32 kind,u32 key,u32 value,u32 ksize,u32 vsize)
{
	union bpf_attr a={0};a.map_type=kind;a.key_size=ksize;a.value_size=vsize;
	a.max_entries=2;a.btf_fd=fd;a.btf_key_type_id=key;a.btf_value_type_id=value;
	strcpy(a.map_name,"typed");return a;
}
static void case_maps(void)
{
	types_fixture();int source=load();CHECK(source>=0);
	struct btf *b=host_files[source].private_data;
	union bpf_attr a=map_attr(source,BPF_MAP_TYPE_ARRAY,7,6,4,16);
	int array=map_create(&a);CHECK(array>=0);
	CHECK(last_map->btf==b&&last_map->btf_key_type_id==7&&last_map->btf_value_type_id==6);
	CHECK(b->refcnt.refs==2);
	a=map_attr(source,BPF_MAP_TYPE_HASH,6,3,16,12);
	int hash=map_create(&a);CHECK(hash>=0&&b->refcnt.refs==3);
	host_close(source);CHECK(b->refcnt.refs==2);
	host_close(array);CHECK(b->refcnt.refs==1);
	host_close(hash);maps_balanced();host_balanced();

	/* fd0 is a valid simulated BTF descriptor, unrelated to host stdin. */
	source=load();host_files[0]=host_files[source];memset(&host_files[source],0,sizeof(host_files[source]));
	a=map_attr(0,BPF_MAP_TYPE_HASH,7,6,4,16);int zero=map_create(&a);CHECK(zero>=0);
	host_close(0);host_close(zero);maps_balanced();host_balanced();

	source=load();b=host_files[source].private_data;
	a=map_attr(source,BPF_MAP_TYPE_ARRAY,7,6,4,16);
	/* Failure points after acquisition keep exactly the source FD reference. */
	for(int which=0;which<7;which++) {
		maps_reset();union bpf_attr bad=a;int want=-EINVAL;
		switch(which) {
		case 0:bad.btf_key_type_id=999;break;
		case 1:bad.value_size=15;break;
		case 2:alloc_security_error=-EACCES;want=-EACCES;break;
		case 3:charge_error=-EPERM;want=-EPERM;break;
		case 4:map_id_error=-ENOSPC;want=-ENOSPC;break;
		case 5:open_security_error=-EACCES;want=-EACCES;break;
		case 6:host_fail_fd=true;want=-EMFILE;break;
		}
		CHECK(map_create(&bad)==want);CHECK(b->refcnt.refs==1);maps_balanced();
	}
	maps_reset();a=map_attr(source,BPF_MAP_TYPE_HASH,7,6,4,16);
	hold_published=true;host_fail_fd=true;
	CHECK(map_create(&a)==-EMFILE&&held_map&&b->refcnt.refs==2);
	CHECK(storage_live==1&&security_live==1&&charge_live==1&&map_ids==1);
	struct bpf_map *held=held_map;held_map=NULL;bpf_map_put_with_uref(held);
	CHECK(b->refcnt.refs==1);maps_balanced();maps_reset();

	union bpf_attr bad=a;bad.btf_key_type_id=0;CHECK(map_create(&bad)==-EINVAL);
	bad=a;bad.btf_value_type_id=0;CHECK(map_create(&bad)==-EINVAL);
	bad=a;bad.map_type=BPF_MAP_TYPE_PERCPU_HASH;CHECK(map_create(&bad)==-EOPNOTSUPP);
	bad=a;bad.map_ifindex=1;CHECK(map_create(&bad)==-EOPNOTSUPP);
	/* An fd without type IDs is unused, not a BTF association.  Match the
	 * loader contract even for a stale fd; never acquire a reference here.
	 */
	for (int fd_case=0;fd_case<2;fd_case++) {
		bad=a;bad.btf_key_type_id=0;bad.btf_value_type_id=0;
		if (fd_case) bad.btf_fd=61;
		int untyped=map_create(&bad);CHECK(untyped>=0);
		CHECK(last_map->btf==NULL && last_map->btf_key_type_id==0 &&
		      last_map->btf_value_type_id==0 && b->refcnt.refs==1);
		host_close(untyped);maps_balanced();
	}
	bad=a;bad.btf_fd=61;CHECK(map_create(&bad)==-EBADF);
	bad=a;bad.map_type=BPF_MAP_TYPE_ARRAY;bad.btf_key_type_id=6;bad.key_size=16;CHECK(map_create(&bad)==-EINVAL);
	CHECK(b->refcnt.refs==1);host_close(source);maps_balanced();host_balanced();
	/* Plain maps retain their existing path. */
	a=map_attr(0,BPF_MAP_TYPE_HASH,0,0,4,16);int plain=map_create(&a);CHECK(plain>=0&&last_map->btf==NULL);
	host_close(plain);maps_balanced();
}

static int map_file(int argc,char **argv)
{
	CHECK(argc==8);
	u32 values[5];
	for(int i=0;i<5;i++) {
		char *end=NULL;errno=0;unsigned long v=strtoul(argv[i+3],&end,10);
		CHECK(!errno&&end!=argv[i+3]&&!*end&&v<=UINT32_MAX);values[i]=v;
	}
	CHECK(values[0]==BPF_MAP_TYPE_ARRAY||values[0]==BPF_MAP_TYPE_HASH);
	FILE *fp=fopen(argv[2],"rb");CHECK(fp);
	CHECK(!fseek(fp,0,SEEK_END));long n=ftell(fp);CHECK(n>0&&n<=BTF_MAX_SIZE);
	CHECK(!fseek(fp,0,SEEK_SET));void *data=malloc(n);CHECK(data);
	CHECK(fread(data,1,n,fp)==(size_t)n&&!fclose(fp));
	int fd=load_bytes(data,n,diagnostics,sizeof(diagnostics));
	int result=fd;
	if(fd>=0) {
		union bpf_attr a=map_attr(fd,values[0],values[1],values[2],values[3],values[4]);
		int map=map_create(&a);result=map<0?map:0;
		if(map>=0) {
			CHECK(last_map->btf_key_type_id==values[1]&&last_map->btf_value_type_id==values[2]);
			host_close(fd);fd=-1;host_close(map);
		}
		if(fd>=0)host_close(fd);
	}
	free(data);maps_balanced();host_balanced();
	printf("{\"result\":%d}\n",result<0?result:0);
	if(result<0)fputs(diagnostics,stderr);
	return result<0?1:0;
}

static void case_gateway(void)
{
	fixture_init();int_type();size_t length=serialize();
	union bpf_attr a={0};a.btf=(u64)(uintptr_t)wire;a.btf_size=length;
	host_admin=false;CHECK(bpf_btf_load(&a)==-EPERM);host_balanced();host_admin=true;
	((u8 *)&a)[28]=1;CHECK(bpf_btf_load(&a)==-EINVAL);host_balanced();((u8 *)&a)[28]=0;
	int fd=bpf_btf_load(&a);CHECK(fd>=0);
	struct btf *btf=host_files[fd].private_data;
	union bpf_attr get={0};get.btf_id=btf->id;
	host_admin=false;CHECK(bpf_btf_get_fd_by_id(&get)==-EPERM);host_admin=true;
	get.next_id=1;CHECK(bpf_btf_get_fd_by_id(&get)==-EINVAL);get.next_id=0;
	int second=bpf_btf_get_fd_by_id(&get);CHECK(second>=0);host_close(second);
	unsigned char buffer[32]={0};
	union bpf_attr info={0},reply={0};info.info.bpf_fd=fd;
	info.info.info=(u64)(uintptr_t)buffer;info.info.info_len=sizeof(buffer);
	buffer[25]=1;CHECK(bpf_obj_get_info_by_fd(&info,&reply)==-E2BIG);buffer[25]=0;
	CHECK(bpf_obj_get_info_by_fd(&info,&reply)==0);
	struct bpf_btf_info copy;memcpy(&copy,buffer,sizeof(copy));
	CHECK(copy.id==btf->id&&copy.btf_size==length&&reply.info.info_len==sizeof(copy));
	info.info.info_len=0;info.info.info=0;CHECK(bpf_obj_get_info_by_fd(&info,&reply)==0);
	info.info.info_len=PAGE_SIZE+1;CHECK(bpf_obj_get_info_by_fd(&info,&reply)==-E2BIG);
	/* The map info bridge reports original typedef IDs, not resolved IDs. */
	host_close(fd);host_balanced();types_fixture();fd=load();
	a=map_attr(fd,BPF_MAP_TYPE_ARRAY,7,6,4,16);int map=map_create(&a);CHECK(map>=0);
	struct bpf_map_info mi={0};memset(&info,0,sizeof(info));
	info.info.bpf_fd=map;info.info.info_len=sizeof(mi);info.info.info=(u64)(uintptr_t)&mi;
	CHECK(bpf_obj_get_info_by_fd(&info,&reply)==0);
	CHECK(mi.btf_id&&mi.btf_key_type_id==7&&mi.btf_value_type_id==6);
	CHECK(!mi.ifindex&&!mi.btf_vmlinux_value_type_id&&!mi.netns_dev&&!mi.netns_ino);
	host_close(fd);host_close(map);maps_balanced();
	info.info.bpf_fd=63;CHECK(bpf_obj_get_info_by_fd(&info,&reply)==-EBADFD);
}
