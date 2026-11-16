// SPDX-License-Identifier: GPL-2.0
// Actual vold control flow with the existing sequential ownership model.
static KeyBuffer model_key() {
    KeyBuffer key(64); for (size_t i=0;i<key.size();i++) key[i]=i;
    return key;
}
static EncryptionPolicy model_install() {
    auto p=policy(); CHECK(installKey("/synthetic",p.options,model_key(),&p));
    CHECK(p.key_raw_ref.size()==8); return p;
}
static void model_owner(unsigned i) {
    CHECK(model_begin(i)==0); CHECK(model_publish(i,i)==0);
}
static void model_removed() {
    auto s=model_get_stats();
    CHECK(!s.present && s.managed && s.secret_zero);
    CHECK(model_lookup()==-ENOKEY); // A valid legacy duplicate must not win.
}
static void model_balanced() {
    auto s=model_get_stats();
    CHECK(!s.owners && !s.readers && !s.refs);
    CHECK(s.acquired==s.released+s.transferred);
    balanced();
}
static void run_model(const std::string& name) {
    reset(); use_model=true; check_spec=false; model_reset();
    std::memset(&model_spec,0,sizeof(model_spec));
    auto p=model_install(); CHECK(model_status()==FSCRYPT_KEY_STATUS_PRESENT);
    if (name=="managed-clean") {
        CHECK(evictKey("/synthetic",p)); CHECK(jobs.empty()); model_removed();
        CHECK(model_status()==FSCRYPT_KEY_STATUS_ABSENT);
    } else if (name=="managed-busy-retry") {
        model_owner(0); model_inode_flags(0,1,1);
        CHECK(evictKey("/synthetic",p)); model_removed();
        CHECK(model_access(0)==0 && model_wrap_allowed(0)==-ENOKEY);
        CHECK(model_inode_drop(0)==-EBUSY);
        on_sleep=[](size_t n) {
            if(n==2) { model_inode_flags(0,0,0); CHECK(model_inode_drop(0)==0); }
        };
        worker(); CHECK(sleeps==std::vector<long>({3200,6400}));
        CHECK(model_status()==FSCRYPT_KEY_STATUS_ABSENT && calls.size()==5);
    } else if (name=="managed-readd") {
        model_owner(0); const auto old=model_get_stats().generation;
        CHECK(evictKey("/synthetic",p)); model_removed();
        on_sleep=[&](size_t n) {
            CHECK(n==1); auto again=model_install(); CHECK(again.key_raw_ref==p.key_raw_ref);
            CHECK(model_get_stats().generation==old+1);
            CHECK(model_wrap_allowed(0)==-ENOKEY && model_access(0)==0);
            model_owner(1); CHECK(model_wrap_allowed(1)==0);
        };
        worker(); CHECK(calls.size()==4 && sleeps.size()==1);
        CHECK(model_status()==FSCRYPT_KEY_STATUS_PRESENT && model_get_stats().owners==2);
        on_sleep={}; CHECK(model_inode_drop(0)==0); CHECK(model_get_stats().owners==1);
        CHECK(evictKey("/synthetic",p)); model_removed();
        CHECK(model_inode_drop(1)==0); worker(); CHECK(model_status()==FSCRYPT_KEY_STATUS_ABSENT);
    } else if (name=="managed-admission") {
        CHECK(model_begin(0)==0); CHECK(model_get_stats().readers==1);
        CHECK(!evictKey("/synthetic",p) && errno==EAGAIN); // Model lock contention, not kernel ABI.
        CHECK(jobs.empty() && model_status()==FSCRYPT_KEY_STATUS_PRESENT);
        CHECK(model_abort(0)==0); CHECK(evictKey("/synthetic",p)); model_removed();
    } else if (name=="managed-publication") {
        CHECK(model_begin(0)==0 && model_begin(1)==0);
        CHECK(model_publish(0,0)==0 && model_publish(1,0)==-EEXIST);
        CHECK(model_get_stats().owners==1 && !model_get_stats().readers);
        CHECK(evictKey("/synthetic",p)); CHECK(model_inode_drop(0)==0); worker();
    } else if (name=="managed-errors") {
        for (unsigned f=1;f<=4;f++) {
            model_failure(f); CHECK(model_begin(0)<0);
            CHECK(!model_get_stats().readers && !model_get_stats().refs);
        }
        model_failure(0); CHECK(evictKey("/synthetic",p)); model_removed();
    } else if (name=="managed-inheritance") {
        model_owner(0); CHECK(model_inherit_begin(0)==0);
        CHECK(!evictKey("/synthetic",p) && errno==EAGAIN);
        CHECK(model_inherit_end()==0 && !model_get_stats().readers);
        CHECK(evictKey("/synthetic",p)); CHECK(model_inherit_begin(0)==-ENOKEY);
        on_sleep=[](size_t n) {
            CHECK(n==1); (void)model_install();
            CHECK(model_inherit_begin(0)==-ENOKEY); // Old cached master stays retired.
            model_owner(1); CHECK(model_inherit_begin(1)==0 && model_inherit_end()==0);
        };
        worker(); on_sleep={}; CHECK(model_inode_drop(0)==0 && model_inode_drop(1)==0);
        CHECK(evictKey("/synthetic",p)); model_removed();
    } else if (name=="managed-duplicate-add") {
        model_owner(0); auto before=model_get_stats(); (void)model_install();
        auto after=model_get_stats(); CHECK(before.generation==after.generation && after.owners==1);
        CHECK(model_wrap_allowed(0)==0); CHECK(model_inode_drop(0)==0);
        CHECK(evictKey("/synthetic",p));
    } else if (name=="managed-scope") {
        auto other=p; other.options.version=2;
        CHECK(!installKey("/synthetic",other.options,model_key(),&other) && errno==EOPNOTSUPP);
        other=p; other.options.key_type=KeyType::kHwWrapped;
        CHECK(!installKey("/synthetic",other.options,model_key(),&other) && errno==EOPNOTSUPP);
        CHECK(model_status()==FSCRYPT_KEY_STATUS_PRESENT);
        CHECK(evictKey("/synthetic",p));
    } else if (name=="managed-dirty-only" || name=="managed-busy-only") {
        model_owner(0);
        model_inode_flags(0,name=="managed-busy-only",name=="managed-dirty-only");
        CHECK(evictKey("/synthetic",p)); model_removed();
        auto before=model_get_stats();
        CHECK(model_inode_drop(0)==-EBUSY);
        auto after=model_get_stats();
        CHECK(after.owners==1 && after.owners==before.owners &&
              after.refs==before.refs && after.readers==before.readers);
        CHECK(model_access(0)==0 && model_status()==FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED);
        on_sleep=[](size_t n) {
            CHECK(n==1); model_inode_flags(0,0,0); CHECK(model_inode_drop(0)==0);
        };
        worker(); CHECK(calls.size()==3 && model_status()==FSCRYPT_KEY_STATUS_ABSENT);
    } else CHECK(false);
    model_balanced(); std::cout<<name<<": PASS\n";
}
