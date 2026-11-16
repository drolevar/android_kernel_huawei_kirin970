/* SPDX-License-Identifier: GPL-2.0 */
/* Current extracted production; key lookup, locks and crypto API are host shims. */
#include "huawei_fscrypt_acquisition_host.h"
#include "lease.h"
#include "crypto-subject.h"
#include "subject.h"
static struct fscrypt_context saved;
static int context_error;
static int save_context(struct inode *i, const void *p, size_t n, void *data)
{ CHECK(n == 108); CHECK(lookup_key->sem.readers == 0); memcpy(&saved, p, n); return context_error; }
static struct operations ops = { .set_context = save_context };
static struct super_block sb = { .s_cop = &ops };
static struct inode ino = { .i_sb = &sb };

static int host_get_sece_fek(struct f2fs_sdp_fscrypt_context *ctx, u8 *fek,
		u8 haspubkey)
{
	return f2fs_do_get_sece_fek(&sb, ctx, fek, haspubkey);
}

static int host_get_keyring_payload(u8 *descriptor, u8 *raw, size_t capacity,
		int *size, bool filepubkey, u32 expected_class)
{
	return f2fs_do_get_keyring_payload(&sb, descriptor, raw, capacity, size,
					   filepubkey, expected_class);
}

static struct fscrypt_policy policy = { .contents_encryption_mode = 1, .filenames_encryption_mode = 4 };
static struct user_key_payload ukp, alternate_ukp;
static struct key key, alternate;
static void setup(unsigned int size)
{
    memset(&ukp, 0, sizeof(ukp)); memset(&key, 0, sizeof(key));
    ukp.datalen = sizeof(struct fscrypt_key);
    struct fscrypt_key *p = (void *)ukp.data;
    p->size = size; p->raw[63] = 7;
    key.type = &key_type_logon; key.payload = &ukp; key.description = "synthetic-only";
    alternate_ukp = ukp; alternate = key; alternate.payload = &alternate_ukp;
    lookup_key = &key; alternate_key = &alternate;
    primary_error = alternate_error = lookups = context_error = 0;
    fail_alloc = fail_setkey = fail_unwrap = fail_request = 0;
    revoke_on_lock = false; ops.key_prefix = NULL;
}
static void balanced(void)
{ CHECK(key.refs == 0 && key.sem.readers == 0 && key.sem.underflow == 0 && key.sem.down == key.sem.up && tfm_live == 0 && request_live == 0);
  CHECK(alternate.refs == 0 && alternate.sem.readers == 0 && alternate.sem.underflow == 0 && alternate.sem.down == alternate.sem.up); }
static void unwrap(struct fscrypt_info *ci, int expected)
{ u8 raw[64]; CHECK(find_and_derive_key(&ino, ci, &saved, raw, sizeof(raw)) == expected); }
static void sdp(unsigned int cl, unsigned int n, unsigned int pub)
{
    memset(&ukp, 0, sizeof(ukp)); ukp.datalen = sizeof(struct fscrypt_sdp_key);
    struct fscrypt_sdp_key *p = (void *)ukp.data;
    p->sdpclass = cl; p->size = n; p->pubkeysize = pub;
}
int main(int argc, char **argv)
{
    CHECK(argc == 2); const char *c = argv[1]; setup(64);
    if (!strcmp(c, "immutable")) {
        struct fscrypt_key before = *(struct fscrypt_key *)ukp.data;
        CHECK(create_encryption_context_from_policy(&ino, &policy) == 0);
        struct fscrypt_info ci = {0}; unwrap(&ci, 0); fscrypt_ce_tfm_put(ci.ci_gtfm_owner);
        CHECK(!memcmp(&before, ukp.data, sizeof(before)));
	} else if (!strcmp(c, "tails")) {
		u8 cipher[80];
		int n;

		for (n = 0; n < 2; n++) {
			struct fscrypt_info ci = { .ci_key_index = -1 };
			struct fscrypt_ce_key lease;
			u8 *descriptor = saved.master_key_descriptor;
			size_t i;
			int err;

			setup(n ? 64 : 32);
			((struct fscrypt_key *)ukp.data)->raw[63] = n ? 19 : 7;
			CHECK(!create_encryption_context_from_policy(&ino,
							     &policy));
			if (!n)
				memcpy(cipher, saved.nonce, sizeof(cipher));
			else
				CHECK(!memcmp(cipher, saved.nonce,
					      sizeof(cipher)));
			err = fscrypt_acquire_ce_key(descriptor, NULL, &lease);
			CHECK(!err);
			CHECK(lease.material.size == (n ? 64U : 32U));
			CHECK(lease.material.raw[63] == (n ? 19 : 7));
			fscrypt_release_ce_key(&lease);
			for (i = 0; i < sizeof(lease); i++)
				CHECK(((u8 *)&lease)[i] == 0);
			unwrap(&ci, 0);
			CHECK(ci.ci_key_index == (n ? -1 : 7));
			fscrypt_ce_tfm_put(ci.ci_gtfm_owner);
			balanced();
		}
    } else if (!strcmp(c, "revocation")) {
        revoke_on_lock = true;
        CHECK(create_encryption_context_from_policy(&ino, &policy) == -EKEYREVOKED); balanced();
        setup(32); key.validation_error = -EKEYEXPIRED; ops.key_prefix = "f2fs:";
        struct fscrypt_ce_key lease;
        CHECK(fscrypt_acquire_ce_key(saved.master_key_descriptor, ops.key_prefix, &lease) == -EKEYEXPIRED);
        CHECK(lookups == 1);
    } else if (!strcmp(c, "prefix")) {
        int errors[] = {-ENOKEY, -EKEYEXPIRED, -EKEYREVOKED, -EACCES, -ENOMEM};
        for (unsigned i=0;i<sizeof(errors)/sizeof(errors[0]);i++) {
            setup(32); primary_error = errors[i]; struct fscrypt_ce_key lease;
            int r = fscrypt_acquire_ce_key(saved.master_key_descriptor, "f2fs:", &lease);
            CHECK(r == (errors[i] == -ENOKEY ? 0 : errors[i]));
            CHECK(lookups == (errors[i] == -ENOKEY ? 2 : 1));
            if (!r) { CHECK(lease.alternate_prefix && lease.key == &alternate); fscrypt_release_ce_key(&lease); }
            balanced();
        }
        /* request_key collapses absence/negative/search-skipped expiry to
         * ENOKEY; this policy deliberately treats them alike, not true miss. */
        for (int provenance=0; provenance<3; provenance++) {
            setup(32); primary_error=-ENOKEY; struct fscrypt_ce_key lease;
            CHECK(!fscrypt_acquire_ce_key(saved.master_key_descriptor,"f2fs:",&lease));
            fscrypt_release_ce_key(&lease); balanced();
        }
        setup(32); ukp.datalen--; struct fscrypt_ce_key lease;
        CHECK(fscrypt_acquire_ce_key(saved.master_key_descriptor,"f2fs:",&lease) == -EINVAL);
        CHECK(lookups==1);
    } else if (!strcmp(c, "lookup-errors")) {
        struct fscrypt_ce_key lease;
        primary_error=-ENOKEY; alternate_error=-EACCES;
        CHECK(fscrypt_acquire_ce_key(saved.master_key_descriptor,"f2fs:",&lease)==-EACCES);
        CHECK(lookups==2);
        setup(32); key.type=NULL;
        CHECK(fscrypt_acquire_ce_key(saved.master_key_descriptor,"f2fs:",&lease)==-EKEYREJECTED);
        CHECK(lookups==1); balanced();
        setup(32); key.validation_error=-EKEYREVOKED;
        CHECK(fscrypt_acquire_ce_key(saved.master_key_descriptor,"f2fs:",&lease)==-EKEYREVOKED);
        CHECK(lookups==1);
        setup(32); key.validation_error=-ENOKEY; /* invalidated after lookup */
        CHECK(fscrypt_acquire_ce_key(saved.master_key_descriptor,"f2fs:",&lease)==-ENOKEY);
        CHECK(lookups==1); /* a valid alternate must not be tried */
        balanced(); setup(32); primary_error=-ENOKEY; revoke_on_lock=true;
        CHECK(fscrypt_acquire_ce_key(saved.master_key_descriptor,"f2fs:",&lease)==-EKEYREVOKED);
        CHECK(lookups==2);
    } else if (!strcmp(c, "sizes")) {
        unsigned sizes[]={0,1,31,33,63,65,UINT32_MAX};
        for(unsigned i=0;i<sizeof(sizes)/sizeof(sizes[0]);i++) {
            setup(sizes[i]); struct fscrypt_ce_key lease;
            CHECK(fscrypt_acquire_ce_key(saved.master_key_descriptor,NULL,&lease)==-EINVAL); balanced();
        }
    } else if (!strcmp(c, "errors")) {
        for (int f=0;f<4;f++) {
            setup(32); CHECK(!create_encryption_context_from_policy(&ino,&policy));
            if(f==0) fail_alloc=1;
            if(f==1) fail_setkey=1;
            if(f==2) fail_unwrap=1;
            if(f==3) fail_request=1;
            struct fscrypt_info ci={0}; u8 raw[64];
            CHECK(find_and_derive_key(&ino,&ci,&saved,raw,64)<0);
            CHECK(!ci.ci_gtfm); balanced();
        }
    } else if (!strcmp(c, "policy-errors")) {
        for(int f=0;f<4;f++) {
            setup(64); if(f==0) fail_alloc=1; if(f==1) fail_setkey=1; if(f==2) fail_request=1; if(f==3) context_error=-EIO;
            CHECK(create_encryption_context_from_policy(&ino,&policy)<0); balanced();
        }
    } else if (!strcmp(c, "f2fs-ce")) {
        u8 plain[80]={1},cipher[80]={0},out[80]={0},iv[16]={0},desc[8]={0};
        CHECK(!f2fs_do_get_fek(&ino,desc,cipher,plain,iv,1,0));
        CHECK(!f2fs_do_get_fek(&ino,desc,cipher,out,iv,0,0)); CHECK(!memcmp(out,plain,64));
        CHECK(((struct fscrypt_key *)ukp.data)->size==64);
        sdp(FSCRYPT_SDP_ECE_CLASS,32,0);
        CHECK(f2fs_do_get_fek(&ino,desc,cipher,out,iv,0,0)==-EINVAL);
    } else if (!strcmp(c, "f2fs-errors")) {
        u8 plain[80]={0},cipher[80]={0},out[80]={0},iv[16]={0},desc[8]={0};
        for(int f=0;f<6;f++) {
            setup(32); CHECK(!f2fs_do_get_fek(&ino,desc,cipher,plain,iv,1,0));
            if(f==0) fail_alloc=1; if(f==1) fail_setkey=1;
            if(f==2) fail_request=1; if(f==3) fail_unwrap=1;
            if(f==4) revoke_on_lock=true; if(f==5) primary_error=-EACCES;
            CHECK(f2fs_do_get_fek(&ino,desc,cipher,out,iv,0,0)<0); balanced();
        }
    } else if (!strcmp(c, "sece-callers")) {
        struct f2fs_sdp_fscrypt_context ctx={0};
        u8 plain[80]={1}, decoded[80]={0};
	int res;

        for(unsigned private_size=0; private_size<=32; private_size+=32) {
            setup(32); sdp(FSCRYPT_SDP_SECE_CLASS,private_size,64);
            struct fscrypt_sdp_key *sk=(void *)ukp.data;
            memset(sk->raw,0xa3,sizeof(sk->raw)); memset(sk->pubkey,0xb4,sizeof(sk->pubkey));
            ecc_file=ctx.file_pub_key; ecc_create_calls=ecc_unwrap_calls=ecc_error=0;
			CHECK(!host_get_sece_fek(&ctx, plain, 0));
            CHECK(ecc_create_calls==1 && ecc_unwrap_calls==0); balanced();
			if (!private_size) {
				res = host_get_sece_fek(&ctx, decoded, 1);
				CHECK(res == -EINVAL);
				CHECK(ecc_unwrap_calls == 0); balanced();
			} else {
				CHECK(!host_get_sece_fek(&ctx, decoded, 1));
				CHECK(ecc_unwrap_calls == 1 &&
				      !memcmp(plain, decoded, 64));
				balanced();
				ecc_error = -EIO;
				res = host_get_sece_fek(&ctx, decoded, 1);
				CHECK(res == -EIO);
				balanced();
				res = host_get_sece_fek(&ctx, plain, 0);
				CHECK(res == -EIO);
				balanced();
			}
        }
    } else if (!strcmp(c, "sdp-bounds")) {
        u8 raw[96],desc[8]={0}; int size;
        unsigned invalid[]={1,31,33,64,UINT32_MAX};
	int res;

        for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++) {
            sdp(FSCRYPT_SDP_SECE_CLASS,invalid[i],64);
            memset(raw,0x5a,sizeof(raw));
			res = host_get_keyring_payload(desc, raw, sizeof(raw),
						       &size, false,
						       FSCRYPT_SDP_SECE_CLASS);
			CHECK(res < 0);
            CHECK(size==0); for(unsigned j=0;j<sizeof(raw);j++) CHECK(raw[j]==0x5a);
        }
        sdp(FSCRYPT_SDP_SECE_CLASS,32,64);
#ifndef CONFIG_SCSI_UFS_ENHANCED_INLINE_CRYPTO_V3
		CHECK(host_get_keyring_payload(desc, raw, 64, &size, false,
					       FSCRYPT_SDP_SECE_CLASS) ==
		      -EOVERFLOW);
		CHECK(!host_get_keyring_payload(desc, raw, 96, &size, true,
						FSCRYPT_SDP_SECE_CLASS) &&
		      size == 96);
        sdp(FSCRYPT_SDP_SECE_CLASS,0,64);
		CHECK(!host_get_keyring_payload(desc, raw, 64, &size, false,
						FSCRYPT_SDP_SECE_CLASS) &&
		      size == 64);
		CHECK(host_get_keyring_payload(desc, raw, 96, &size, true,
					       FSCRYPT_SDP_SECE_CLASS) ==
		      -EINVAL);
#else
		CHECK(!host_get_keyring_payload(desc, raw, 32, &size, false,
						FSCRYPT_SDP_SECE_CLASS) &&
		      size == 32);
#endif
        sdp(FSCRYPT_SDP_ECE_CLASS,32,0);
		CHECK(host_get_keyring_payload(desc, raw, 96, &size, false,
					       FSCRYPT_SDP_SECE_CLASS) ==
		      -EINVAL);
		CHECK(host_get_keyring_payload(desc, raw, 31, &size, false,
					       FSCRYPT_SDP_ECE_CLASS) ==
		      -EOVERFLOW);
		CHECK(!host_get_keyring_payload(desc, raw, 32, &size, false,
						FSCRYPT_SDP_ECE_CLASS));
    } else CHECK(false);
    balanced(); return 0;
}
