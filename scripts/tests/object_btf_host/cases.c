/* SPDX-License-Identifier: GPL-2.0 */
/* Synthetic wire fixtures and assertions; parser/lifecycle are subject.c. */
#include "host.h"
#include "subject.h"
#include "subject.c"
#include "logger.c"

struct fixture {
	_Alignas(8) u8 types[1100000];
	char strings[4096];
	u32 offsets[70000], nr, nt, ns;
};
static struct fixture f;
static _Alignas(8) u8 wire[1200000];
static char diagnostics[131072];
static void fixture_init(void) { memset(&f,0,sizeof(f)); f.ns=1; }
static u32 name(const char *s)
{
	u32 off=f.ns; size_t n=strlen(s)+1;
	CHECK(n<sizeof(f.strings)-off); memcpy(f.strings+off,s,n); f.ns+=(u32)n; return off;
}
static u32 type(u32 kind,u32 no,u32 vlen,u32 sz,const void *extra,size_t n)
{
	struct btf_type t={.name_off=no,.info=(kind<<24)|vlen,.size=sz};
	CHECK(f.nr+1<ARRAY_SIZE(f.offsets) && sizeof(t)+n<sizeof(f.types)-f.nt);
	f.offsets[++f.nr]=f.nt;
	memcpy(f.types+f.nt,&t,sizeof(t)); f.nt+=sizeof(t);
	if (n) memcpy(f.types+f.nt,extra,n);
	f.nt+=(u32)n; return f.nr;
}
static struct btf_type *at(u32 id) { CHECK(id && id<=f.nr); return (void *)(f.types+f.offsets[id]); }
static u32 int_type(void)
{ u32 data=(BTF_INT_SIGNED<<24)|32; return type(BTF_KIND_INT,name("int"),0,4,&data,sizeof(data)); }
static u32 array_type(u32 elem,u32 idx,u32 count)
{ struct btf_array a={elem,idx,count}; return type(BTF_KIND_ARRAY,0,0,0,&a,sizeof(a)); }
static u32 var_type(const char *s,u32 id)
{ struct btf_var v={BTF_VAR_GLOBAL_ALLOCATED}; return type(BTF_KIND_VAR,name(s),0,id,&v,sizeof(v)); }
static size_t serialize(void)
{
	struct btf_header h={.magic=BTF_MAGIC,.version=BTF_VERSION,.hdr_len=sizeof(h),
		.type_len=f.nt,.str_off=f.nt,.str_len=f.ns};
	CHECK(sizeof(h)+f.nt+f.ns<sizeof(wire));
	memcpy(wire,&h,sizeof(h)); memcpy(wire+sizeof(h),f.types,f.nt);
	memcpy(wire+sizeof(h)+f.nt,f.strings,f.ns);
	return sizeof(h)+f.nt+f.ns;
}
static int load_bytes(void *data,size_t n,char *log,u32 log_size)
{
	union bpf_attr a={0};
	a.btf=(u64)(uintptr_t)data; a.btf_size=(u32)n;
	if (log) { memset(log,0,log_size); a.btf_log_buf=(u64)(uintptr_t)log; a.btf_log_size=log_size; a.btf_log_level=1; }
	return btf_new_fd(&a);
}
static int load(void) { size_t n=serialize(); return load_bytes(wire,n,NULL,0); }
static void release_fd(int fd) { if (fd>=0) host_close(fd); host_balanced(); }
static void expect_error(int ret,int want)
{
	if (ret!=want) fprintf(stderr,"expected %d, got %d; diagnostic: %s\n",want,ret,diagnostics);
	release_fd(ret); CHECK(ret==want);
}
static void reject(int want,const char *fragment)
{
	size_t n=serialize(); int ret=load_bytes(wire,n,diagnostics,sizeof(diagnostics));
	expect_error(ret,want);
	if (fragment) CHECK(strstr(diagnostics,fragment));
}
static void sized(const struct btf *b,u32 requested,u32 concrete,u32 bytes)
{
	u32 id=requested,size=0xdeadbeef;
	const struct btf_type *t=btf_type_id_size(b,&id,&size);
	CHECK(t && id==concrete && size==bytes);
	CHECK(t==btf_type_by_id(b,id));
}
static void unsized(const struct btf *b,u32 requested)
{
	u32 id=requested,size=0xdeadbeef;
	CHECK(!btf_type_id_size(b,&id,&size)); CHECK(id==requested && size==0xdeadbeef);
}
static void types_fixture(void)
{
	fixture_init(); int_type();
	type(BTF_KIND_PTR,0,0,3,NULL,0);
	type(BTF_KIND_TYPEDEF,name("arr_t"),0,4,NULL,0);
	array_type(1,1,3);
	type(BTF_KIND_TYPEDEF,name("ptr_t"),0,2,NULL,0);
	struct btf_member m[]={{name("key"),1,0},{name("values"),3,32}};
	type(BTF_KIND_STRUCT,name("Pair"),2,16,m,sizeof(m));
	type(BTF_KIND_TYPEDEF,name("key_t"),0,1,NULL,0);
	array_type(5,7,2);
}
static void case_types(void)
{
	types_fixture(); int fd=load(); CHECK(fd>=0);
	struct btf *b=btf_get_by_fd(fd); CHECK(!IS_ERR(b));
	sized(b,1,1,4); sized(b,2,2,8); sized(b,3,4,12); sized(b,4,4,12);
	sized(b,5,2,8); sized(b,6,6,16); sized(b,7,1,4); sized(b,8,8,16);
	/* Key/value sizes consumed by ordinary ARRAY/HASH plumbing. No map emulation. */
	CHECK(!strcmp(btf_name_by_offset(b,at(6)->name_off),"Pair"));
	CHECK(btf_type_is_void(btf_type_by_id(b,0))); CHECK(!btf_type_by_id(b,9));
	unsized(b,0); unsized(b,9); unsized(b,UINT_MAX);
	btf_put(b); release_fd(fd);
	/* TYPEDEF -> PTR -> ARRAY order as well as PTR -> TYPEDEF -> ARRAY above. */
	fixture_init(); int_type(); type(BTF_KIND_TYPEDEF,name("p"),0,3,NULL,0);
	type(BTF_KIND_PTR,0,0,4,NULL,0); array_type(1,1,3);
	fd=load(); CHECK(fd>=0); b=btf_get_by_fd(fd); CHECK(!IS_ERR(b));
	sized(b,2,3,8); sized(b,4,4,12); btf_put(b); release_fd(fd);
}
static void case_func(void)
{
	fixture_init(); int_type(); struct btf_param p={name("arg"),1};
	type(BTF_KIND_FUNC_PROTO,0,1,1,&p,sizeof(p));
	type(BTF_KIND_FUNC,name("run"),1,2,NULL,0);
	reject(-EINVAL,"vlen != 0");
	at(3)->info &= ~0xffffu;
	int fd=load(); CHECK(fd>=0); struct btf *b=btf_get_by_fd(fd);
	CHECK(!IS_ERR(b)); unsized(b,2); unsized(b,3); btf_put(b); release_fd(fd);
	at(3)->type=1; reject(-EINVAL,NULL);
}
static void datasec_fixture(u32 first,u32 modifier,bool section_first)
{
	fixture_init();
	u32 first_size=first==BTF_KIND_PTR?8:first==BTF_KIND_ARRAY?8:4;
	struct btf_var_secinfo vs[]={{2,0,first_size},{3,first_size,4}};
	if (section_first) type(BTF_KIND_DATASEC,name(".data"),2,first_size+4,vs,sizeof(vs));
	else int_type();
	var_type("first",4); var_type("second",5);
	if (first==BTF_KIND_PTR) type(first,0,0,0,NULL,0);
	else if (first==BTF_KIND_ARRAY) array_type(6,6,2);
	else { struct btf_member m={name("x"),6,0}; type(first,name("S"),1,4,&m,sizeof(m)); }
	type(modifier,modifier==BTF_KIND_TYPEDEF?name("alias"):0,0,6,NULL,0);
	if (section_first) int_type();
	else {
		int_type(); /* reference 6 remains a concrete int */
		type(BTF_KIND_DATASEC,name(".data"),2,first_size+4,vs,sizeof(vs));
	}
}
static void case_datasec(void)
{
	const u32 firsts[]={BTF_KIND_PTR,BTF_KIND_ARRAY,BTF_KIND_STRUCT,BTF_KIND_UNION};
	const u32 mods[]={BTF_KIND_TYPEDEF,BTF_KIND_CONST,BTF_KIND_VOLATILE,BTF_KIND_RESTRICT};
	unsigned bad=0, checked=0;
	for (unsigned i=0;i<ARRAY_SIZE(firsts);i++) for (unsigned j=0;j<ARRAY_SIZE(mods);j++)
	for (unsigned last=0;last<2;last++) {
		datasec_fixture(firsts[i],mods[j],!last); int fd=load();
		if(fd<0) fprintf(stderr,"datasec first=%u modifier=%u last=%u result=%d\n",firsts[i],mods[j],last,fd);
		CHECK(fd>=0); struct btf *b=btf_get_by_fd(fd); CHECK(!IS_ERR(b));
		u32 bytes=firsts[i]==BTF_KIND_PTR||firsts[i]==BTF_KIND_ARRAY?12:8;
		sized(b,last?7:1,last?7:1,bytes); sized(b,5,6,4);
		btf_put(b); release_fd(fd);
		/* Each VAR must fit independently, even when resolution suspends
		 * the DATASEC walk. Keep offsets/section size valid in every row.
		 */
		for (unsigned mask=1;mask<4;mask++) {
			datasec_fixture(firsts[i],mods[j],!last);
			struct btf_var_secinfo *vs=(void *)(at(last?7:1)+1);
			if (mask&1) vs[0].size--;
			if (mask&2) vs[1].size--;
			size_t n=serialize();
			int ret=load_bytes(wire,n,diagnostics,sizeof(diagnostics));
			if (ret!=-EINVAL || !strstr(diagnostics,"Invalid size")) {
				fprintf(stderr,"datasec size first=%u modifier=%u last=%u mask=%u: expected -EINVAL, got %d\n",
					firsts[i],mods[j],last,mask,ret);
				bad++;
			}
			release_fd(ret); checked++;
		}
	}
	printf("datasec size checks: %u invalid multi-VAR rows, %u unexpected results\n",checked,bad);
	CHECK(!bad);
}

static void enum_member_sizes(void)
{
	/* Literal wire bounds: ordinary members use the whole enum; bitfields
	 * may use at most its width and must fit at their bit offset.
	 */
	const struct { u32 size, bits; } sizes[]={{1,8},{2,16},{4,32},{8,64}};
	unsigned bad=0, checked=0;
	for (unsigned s=0;s<ARRAY_SIZE(sizes);s++) {
		u32 bytes=sizes[s].size, bits=sizes[s].bits;
		const struct { u32 container, offset, width; bool kflag; int want; } rows[]={
			{bytes,0,0,false,0}, {bytes,0,0,true,0},
			{bytes/2,0,0,false,-EINVAL}, {bytes/2,0,0,true,-EINVAL},
			{bytes+1,8,0,false,0}, {bytes+1,8,0,true,0},
			{bytes,8,0,false,-EINVAL}, {bytes,8,0,true,-EINVAL},
			{bytes+1,1,0,false,-EINVAL}, {bytes+1,1,0,true,-EINVAL},
			{bytes,0,1,true,0}, {bytes,0,bits,true,0},
			{bytes+1,0,bits+1,true,-EINVAL},
			{bytes,1,bits-1,true,0}, {bytes,1,bits,true,-EINVAL},
			{bytes+1,1,bits,true,0},
		};
		for (unsigned r=0;r<ARRAY_SIZE(rows);r++) {
			fixture_init();
			struct btf_enum e={name("ZERO"),0};
			u32 eid=type(BTF_KIND_ENUM,name("E"),1,bytes,&e,sizeof(e));
			struct btf_member m={name("value"),eid,rows[r].offset|(rows[r].width<<24)};
			u32 sid=type(BTF_KIND_STRUCT,name("S"),1,rows[r].container,&m,sizeof(m));
			if (rows[r].kflag) at(sid)->info|=1u<<31;
			size_t n=serialize();
			int ret=load_bytes(wire,n,diagnostics,sizeof(diagnostics));
			if ((ret<0?ret:0)!=rows[r].want) {
				fprintf(stderr,"enum size=%u row=%u container=%u offset=%u width=%u kflag=%u: expected %d, got %d\n",
					bytes,r,rows[r].container,rows[r].offset,rows[r].width,rows[r].kflag,rows[r].want,ret);
				bad++;
			}
			if (ret>=0) {
				struct btf *b=btf_get_by_fd(ret); CHECK(!IS_ERR(b));
				sized(b,eid,eid,bytes); sized(b,sid,sid,rows[r].container);
				btf_put(b);
			}
			release_fd(ret); checked++;
		}
	}
	printf("enum member checks: %u rows, %u unexpected results\n",checked,bad);
	CHECK(!bad);
}
static void case_headers(void)
{
	/* Literal expected errno values for hostile sections, no mirrored parser. */
	for(unsigned row=0;row<18;row++) {
		fixture_init(); int_type(); size_t n=serialize(); struct btf_header *h=(void *)wire;
		int want=-EINVAL;
		switch(row) {
		case 0: n=0; break;
		case 1: n=7; break;
		case 2: h->hdr_len=(u32)n+1; break;
		case 3: h->magic=0; break;
		case 4: h->version=2; want=-ENOTSUPP; break;
		case 5: h->flags=1; want=-ENOTSUPP; break;
		case 6: h->hdr_len=8; break;
		case 7: h->type_off=1; break;
		case 8: h->type_off=UINT_MAX; break;
		case 9: h->str_off--; break;
		case 10: h->str_off++; break;
		case 11: h->type_len=UINT_MAX; break;
		case 12: h->type_len=0; break;
		case 13: h->str_len=0; break;
		case 14: wire[n-1]='x'; break;
		case 15: wire[sizeof(*h)+h->str_off]='x'; break;
		case 16: h->str_len--; break;
		case 17: /* Valid extra header length, nonzero unsupported field. */
			memmove(wire+sizeof(*h)+4,wire+sizeof(*h),n-sizeof(*h));
			memset(wire+sizeof(*h),1,4); h->hdr_len+=4; n+=4; want=-E2BIG; break;
		}
		int r=load_bytes(wire,n,diagnostics,sizeof(diagnostics));
		if(r!=want) fprintf(stderr,"header row %u\n",row);
		expect_error(r,want);
	}
	/* Nonzero type_off with reordered sections is safely rejected (str must end). */
	fixture_init(); int_type(); size_t n=serialize(); struct btf_header *h=(void *)wire;
	u8 saved[64]; CHECK(f.nt<sizeof(saved)); memcpy(saved,wire+sizeof(*h),f.nt);
	memcpy(wire+sizeof(*h),f.strings,f.ns); memcpy(wire+sizeof(*h)+f.ns,saved,f.nt);
	h->str_off=0;h->type_off=f.ns;
	expect_error(load_bytes(wire,n,diagnostics,sizeof(diagnostics)),-EINVAL);
}
static void case_malformed(void)
{
	enum_member_sizes();
	for(unsigned row=0;row<19;row++) {
		fixture_init(); int_type(); int want=-EINVAL;
		switch(row) {
		case 0: f.nt-=1; break;
		case 1: f.nt=sizeof(struct btf_type); break;
		case 2: at(1)->info|=1u<<16; break;
		case 3: at(1)->info=0; break;
		case 4: at(1)->name_off=UINT_MAX; break;
		case 5: at(1)->size=1; break;
		case 6: *(u32 *)(at(1)+1)=0xf0000020; break;
		case 7: type(BTF_KIND_TYPEDEF,name("bad"),0,65535,NULL,0); break;
		case 8: array_type(65535,1,1); break;
		case 9: array_type(1,65535,1); break;
		case 10: array_type(1,1,UINT_MAX); break;
		case 11: { struct btf_member m={name("x"),65535,0}; type(BTF_KIND_STRUCT,name("S"),1,4,&m,sizeof(m)); break; }
		case 12: { struct btf_member m[]={{name("x"),1,32},{name("y"),1,0}}; type(BTF_KIND_STRUCT,name("S"),2,8,m,sizeof(m)); break; }
		case 13: { struct btf_member m[]={{name("x"),1,(4u<<24)|16},{name("y"),1,(4u<<24)|8}}; u32 id=type(BTF_KIND_STRUCT,name("S"),2,4,m,sizeof(m)); at(id)->info|=1u<<31; break; }
		case 14: { struct btf_member m={name("x"),1,8}; type(BTF_KIND_UNION,name("U"),1,8,&m,sizeof(m)); break; }
		case 15: type(BTF_KIND_TYPEDEF,name("loop"),0,2,NULL,0); want=-EEXIST; break;
		case 16: type(BTF_KIND_TYPEDEF,name("a"),0,3,NULL,0); type(BTF_KIND_CONST,0,0,2,NULL,0); want=-EEXIST; break;
		case 17: type(BTF_KIND_PTR,0,0,3,NULL,0); type(BTF_KIND_CONST,0,0,2,NULL,0); want=-EEXIST; break;
		case 18: { struct btf_member m={name("x"),2,0}; type(BTF_KIND_STRUCT,name("S"),1,4,&m,sizeof(m)); want=-EEXIST; break; }
		}
		size_t n=serialize(); int r=load_bytes(wire,n,diagnostics,sizeof(diagnostics));
		if(r!=want) fprintf(stderr,"malformed row %u\n",row);
		expect_error(r,want);
	}
	fixture_init(); int_type();
	for(unsigned i=0;i<40;i++) type(BTF_KIND_CONST,0,0,i==39?1:i+3,NULL,0);
	reject(-E2BIG,"Exceeded max resolving depth");
	/* Equal offsets with zero-length arrays and decoded kflag ordering are valid. */
	fixture_init(); int_type(); array_type(1,1,0);
	struct btf_member eq[]={{name("a"),2,0},{name("b"),2,0}};
	type(BTF_KIND_STRUCT,name("S"),2,0,eq,sizeof(eq)); int fd=load(); CHECK(fd>=0); release_fd(fd);
	fixture_init(); int_type();
	struct btf_member bits[]={{name("a"),1,(8u<<24)},{name("b"),1,(4u<<24)|8}};
	u32 id=type(BTF_KIND_STRUCT,name("S"),2,4,bits,sizeof(bits)); at(id)->info|=1u<<31;
	fd=load(); CHECK(fd>=0); release_fd(fd);
	/* A struct containing a pointer to itself is not a by-value cycle. */
	fixture_init(); int_type(); type(BTF_KIND_PTR,0,0,3,NULL,0);
	struct btf_member m={name("next"),2,0}; type(BTF_KIND_STRUCT,name("Node"),1,8,&m,sizeof(m));
	fd=load(); CHECK(fd>=0); release_fd(fd);
}
static void case_alloc(void)
{
	fixture_init(); for(unsigned i=0;i<80;i++) int_type();
	unsigned start=host_alloc_calls; int fd=load(); CHECK(fd>=0);
	unsigned count=host_alloc_calls-start; release_fd(fd); CHECK(count>=10);
	unsigned bad=0;
	for(unsigned n=1;n<=count;n++) {
		host_fail_alloc=host_alloc_calls+n;
		int r=load();
		if(r!=-ENOMEM) { fprintf(stderr,"allocation %u/%u: expected -ENOMEM, got %d\n",n,count,r); bad++; }
		release_fd(r); host_reset_faults();
	}
	printf("allocation sweep: %u positions, %u unexpected results\n",count,bad); CHECK(!bad);
}
static void case_capacity(void)
{
    fixture_init(); u32 no=name("int"),data=(BTF_INT_SIGNED<<24)|32;
    for(unsigned i=0;i<65535;i++) type(BTF_KIND_INT,no,0,4,&data,sizeof(data));
    expect_error(load(),-E2BIG);
}
static void case_info(void)
{
    types_fixture(); size_t n=serialize(); int fd=load_bytes(wire,n,NULL,0); CHECK(fd>=0);
    struct btf *b=btf_get_by_fd(fd); CHECK(!IS_ERR(b));
    u8 output[1024]; CHECK(n+2<sizeof(output)); memset(output,0xa5,sizeof(output));
    struct bpf_btf_info info={.btf=(u64)(uintptr_t)(output+1),.btf_size=(u32)n-1};
    union bpf_attr attr={0},uattr={0};
    attr.info.info=(u64)(uintptr_t)&info; attr.info.info_len=sizeof(info);
    CHECK(btf_get_info_by_fd(b,&attr,&uattr)==0);
    CHECK(info.id==btf_id(b) && info.btf_size==n && uattr.info.info_len==sizeof(info));
    CHECK(!memcmp(output+1,wire,n-1) && output[0]==0xa5 && output[n]==0xa5);
    /* Query only, full byte count is returned without a data buffer. */
    info=(struct bpf_btf_info){0};
    CHECK(btf_get_info_by_fd(b,&attr,&uattr)==0 && info.btf_size==n && info.id==btf_id(b));
    /* Short info structure writes only the requested prefix. */
    memset(&info,0,sizeof(info)); info.id=0xa5a5a5a5; attr.info.info_len=12;
    CHECK(btf_get_info_by_fd(b,&attr,&uattr)==0 && info.btf_size==n && info.id==0xa5a5a5a5);
    CHECK(uattr.info.info_len==12); attr.info.info_len=sizeof(info);
    host_input_limit=sizeof(info)-1; CHECK(btf_get_info_by_fd(b,&attr,&uattr)==-EFAULT); host_reset_faults();
    for(unsigned i=1;i<=3;i++) {
        info=(struct bpf_btf_info){.btf=(u64)(uintptr_t)(output+1),.btf_size=(u32)n};
        host_fail_to=host_to_calls+i; CHECK(btf_get_info_by_fd(b,&attr,&uattr)==-EFAULT); host_reset_faults();
        CHECK(b->refcnt.refs==2 && host_ids==1 && host_fds==1);
    }
    btf_put(b); release_fd(fd);
}
static void case_copy(void)
{
	types_fixture(); size_t n=serialize();
	const long limits[]={0,7,23,24,25,(long)n-1};
	for(unsigned i=0;i<ARRAY_SIZE(limits);i++) {
		host_input_limit=limits[i]; expect_error(load_bytes(wire,n,NULL,0),-EFAULT); host_reset_faults();
	}
	unsigned calls=host_from_calls; host_mutate_input=true;
	int fd=load_bytes(wire,n,NULL,0); CHECK(fd>=0); CHECK(host_from_calls==calls+1);
	struct btf *b=btf_get_by_fd(fd); CHECK(!IS_ERR(b));
	CHECK(((struct btf_header *)wire)->magic!=BTF_MAGIC && b->hdr.magic==BTF_MAGIC);
	sized(b,6,6,16); btf_put(b); host_reset_faults(); release_fd(fd);
}
static void case_publish(void)
{
	types_fixture(); host_fail_idr=true; expect_error(load(),-ENOSPC); host_reset_faults();
	host_fail_fd=true;
	unsigned frees=host_frees; int r=load(); CHECK(r==-EMFILE);
	CHECK(!host_ids && !host_fds && host_rcu_count==1 && host_live>0 && host_frees>frees);
	host_balanced(); host_reset_faults();
	int fd=load(); CHECK(fd>=0); struct btf *b=btf_get_by_fd(fd); CHECK(!IS_ERR(b));
	u32 id=btf_id(b); unsigned refs=b->refcnt.refs;
	host_fail_fd=true; CHECK(btf_get_fd_by_id(id)==-EMFILE); CHECK(b->refcnt.refs==refs);
	host_reset_faults(); btf_put(b); release_fd(fd);
	CHECK(PTR_ERR(btf_get_by_fd(-1))==-EBADF); CHECK(PTR_ERR(btf_get_by_fd(63))==-EBADF);
}
static void case_lifetime(void)
{
	types_fixture(); int fd=load(); CHECK(fd>=0);
	struct btf *held=btf_get_by_fd(fd); CHECK(!IS_ERR(held) && held->refcnt.refs==2);
	u32 id=btf_id(held); CHECK(id && host_ids==1);
	host_close(fd); CHECK(held->refcnt.refs==1 && host_ids==1 && !host_rcu_count);
	CHECK(PTR_ERR(btf_get_by_fd(fd))==-EBADF); sized(held,6,6,16);
	int second=btf_get_fd_by_id(id); CHECK(second>=0 && held->refcnt.refs==2);
	host_close(second); CHECK(held->refcnt.refs==1);
	btf_put(held); CHECK(!host_ids && host_rcu_count==1 && host_live>0);
	CHECK(btf_get_fd_by_id(id)==-ENOENT); CHECK(btf_get_fd_by_id(UINT_MAX)==-ENOENT);
	host_balanced(); CHECK(btf_get_fd_by_id(id)==-ENOENT);
	/* An IDR reader finding a zero-ref object cannot resurrect it. */
	fd=load(); CHECK(fd>=0); struct btf *b=host_files[fd].private_data;
	unsigned saved=b->refcnt.refs; b->refcnt.refs=0;
	CHECK(btf_get_fd_by_id(btf_id(b))==-ENOENT); b->refcnt.refs=saved; release_fd(fd);
	/* Non-BTF anon files reject without acquiring a BTF reference. */
	static const struct file_operations other_ops={0};
	host_files[5]=(struct file){&other_ops,NULL,1};
	CHECK(PTR_ERR(btf_get_by_fd(5))==-EINVAL); host_files[5].f_count=0; host_balanced();
}
static void direct_log(struct bpf_verifier_log *log,const char *fmt,...)
{ va_list ap; va_start(ap,fmt); bpf_verifier_vlog(log,fmt,ap); va_end(ap); }
static void case_log(void)
{
	types_fixture(); size_t n=serialize(); int fd=load_bytes(wire,n,diagnostics,sizeof(diagnostics));
	CHECK(fd>=0 && strstr(diagnostics,"[1] INT int") && strstr(diagnostics,"Pair") && strstr(diagnostics,"type_id=")); release_fd(fd);
	char out[130]; memset(out,0xa5,sizeof(out));
	/* Real parser multipart diagnostics reach full then stop copying. */
	int r=load_bytes(wire,n,out+1,128); CHECK(out[0]==(char)0xa5 && out[129]==(char)0xa5 && out[128]==0);
	expect_error(r,-ENOSPC);
	char a[20]={0},b[20]={0}; struct bpf_verifier_log one={.level=1,.ubuf=a,.len_total=sizeof(a)};
	struct bpf_verifier_log two={.level=1,.ubuf=b,.len_total=sizeof(b)};
	direct_log(&one,"id=%u",17u); direct_log(&one,":ok"); direct_log(&two,"second");
	CHECK(!strcmp(a,"id=17:ok") && !strcmp(b,"second") && one.len_used==8);
	one.len_total=9; unsigned calls=host_to_calls; direct_log(&one,"ignored"); CHECK(calls==host_to_calls);
	one.level=0; direct_log(&one,"ignored"); CHECK(calls==host_to_calls);
	one=(struct bpf_verifier_log){.level=1,.ubuf=a,.len_total=sizeof(a)};
	host_fail_to=host_to_calls+1; direct_log(&one,"broken"); CHECK(!one.ubuf && !one.len_used);
	calls=host_to_calls; direct_log(&one,"ignored"); CHECK(host_to_calls==calls); host_reset_faults();
	char line[1200],large[2048]; memset(line,'x',sizeof(line)-1);line[sizeof(line)-1]=0;
	one=(struct bpf_verifier_log){.level=1,.ubuf=large,.len_total=sizeof(large)};
	direct_log(&one,"%s",line); CHECK(one.len_used==1023 && large[1023]==0);
	/* Invalid partial log requests reject before publishing anything. */
	union bpf_attr attr={.btf=(u64)(uintptr_t)wire,.btf_size=(u32)n,.btf_log_size=128};
	expect_error(btf_new_fd(&attr),-EINVAL);
}
static void case_log_fault(void)
{
	types_fixture(); size_t n=serialize(); unsigned bad=0;
	/* First header fragment, middle header fragment, and type multipart output. */
	const unsigned fail_at[]={1,4,12};
	for(unsigned i=0;i<ARRAY_SIZE(fail_at);i++) {
		unsigned before=host_to_calls; host_fail_to=before+fail_at[i];
		int r=load_bytes(wire,n,diagnostics,sizeof(diagnostics));
		CHECK(host_to_calls==before+fail_at[i]);
		if(r!=-EFAULT) { fprintf(stderr,"log copy fault at write %u: expected -EFAULT got %d\n",fail_at[i],r);bad++; }
		release_fd(r);host_reset_faults();
	}
	CHECK(!bad);
}
static void case_datasec_overflow(void)
{
	fixture_init(); int_type(); var_type("x",1);
	struct btf_var_secinfo vs={2,0xfffffff0u,0x20};
	type(BTF_KIND_DATASEC,name(".data"),1,UINT_MAX,&vs,sizeof(vs));
	reject(-EINVAL,"offset+size");
	/* Exact-end control is accepted without allocating DATASEC-sized storage. */
	((struct btf_var_secinfo *)(at(3)+1))->size=15;
	int fd=load(); CHECK(fd>=0); release_fd(fd);
	((struct btf_var_secinfo *)(at(3)+1))->size=16;
	reject(-EINVAL,"offset+size");
}
static int parse_file(const char *path)
{
	FILE *fp=fopen(path,"rb"); if(!fp) { perror(path);return 2; }
	CHECK(fseek(fp,0,SEEK_END)==0); long n=ftell(fp); CHECK(n>=0 && n<=BTF_MAX_SIZE);
	CHECK(fseek(fp,0,SEEK_SET)==0); void *data=malloc((size_t)n?:1); CHECK(data);
	CHECK(fread(data,1,(size_t)n,fp)==(size_t)n); CHECK(fclose(fp)==0);
	int fd=load_bytes(data,(size_t)n,diagnostics,sizeof(diagnostics));
	printf("{\"result\":%d,\"types\":[",fd>=0?0:fd);
	if(fd>=0) {
		struct btf *b=btf_get_by_fd(fd); CHECK(!IS_ERR(b));
		for(u32 id=1;id<=b->nr_types;id++) {
			u32 resolved=id,size=0;const struct btf_type *t=btf_type_by_id(b,id);
			bool has=btf_type_id_size(b,&resolved,&size)!=NULL;
			printf("%s{\"id\":%u,\"kind\":%u,\"resolved_id\":%u,\"size\":",id==1?"":",",id,BTF_INFO_KIND(t->info),resolved);
			if(has) printf("%u",size);else printf("null");printf("}");
		}
		btf_put(b);
	}
	printf("]}\n"); if(fd<0) fputs(diagnostics,stderr);
	release_fd(fd);free(data);return fd<0?1:0;
}
#include "maps.h"

int main(int argc,char **argv)
{
	CHECK(sizeof(void *)==8); CHECK(argc>=2);
	if(argc==8 && !strcmp(argv[1],"--map")) return map_file(argc,argv);
	if(argc==3 && !strcmp(argv[1],"--file")) return parse_file(argv[2]);
	CHECK(argc==2);
	if(!strcmp(argv[1],"types")) case_types();
	else if(!strcmp(argv[1],"func")) case_func();
	else if(!strcmp(argv[1],"datasec")) case_datasec();
	else if(!strcmp(argv[1],"headers")) case_headers();
	else if(!strcmp(argv[1],"malformed")) case_malformed();
	else if(!strcmp(argv[1],"alloc")) case_alloc();
	else if(!strcmp(argv[1],"capacity")) case_capacity();
	else if(!strcmp(argv[1],"info")) case_info();
	else if(!strcmp(argv[1],"copy")) case_copy();
	else if(!strcmp(argv[1],"publish")) case_publish();
	else if(!strcmp(argv[1],"lifetime")) case_lifetime();
	else if(!strcmp(argv[1],"log")) case_log();
	else if(!strcmp(argv[1],"log-fault")) case_log_fault();
	else if(!strcmp(argv[1],"datasec-overflow")) case_datasec_overflow();
	else if(!strcmp(argv[1],"maps")) case_maps();
	else if(!strcmp(argv[1],"gateway")) case_gateway();
	else {fprintf(stderr,"unknown case %s\n",argv[1]);return 2;}
	host_balanced();
    printf("PASS %s (simulated kernel services): alloc/free=%u/%u ref(set+inc/dec+unpublished)=%u/%u fd(open/close)=%u/%u id(add/remove)=%u/%u rcu(queue/free)=%u/%u graces=%u\n",
        argv[1],host_alloc_successes,host_frees,host_ref_sets+host_ref_incs,host_ref_decs+host_ref_unpublished,
        host_fd_opens,host_fd_closes,host_id_adds,host_id_removes,host_rcu_calls,host_rcu_frees,host_graces);
    return 0;
}
