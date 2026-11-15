// SPDX-License-Identifier: GPL-2.0
// Host-only consumer fixture. Every fd/ioctl/thread/sleep below is synthetic.
#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <functional>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>
#include <openssl/sha.h>
#include "selected-fscrypt-uapi.h"
#include <fscrypt/fscrypt.h>
using android::fscrypt::EncryptionOptions;
using android::fscrypt::EncryptionPolicy;
using android::fscrypt::KeyType;
using KeyBuffer = std::vector<char>; // Synthetic bytes, not vold's secure allocator.
using namespace std::string_literals;
#define CHECK(x) do { if (!(x)) { std::cerr << __LINE__ << ": " << #x << '\n'; std::abort(); } } while (0)
struct Reply { unsigned long request; int error = 0; unsigned value = 0; };
static std::deque<Reply> replies;
static std::deque<std::function<void()>> jobs;
static std::vector<long> sleeps;
static std::vector<unsigned long> calls;
static std::vector<std::string> messages;
static std::function<void(size_t)> on_sleep;
static int opens, closes, live_fds, failed_opens;
static bool fail_open;
static fscrypt_key_specifier expected_spec;
static bool check_spec;
static fscrypt_add_key_arg last_add;
static std::vector<unsigned char> last_raw;
static std::mutex fscrypt_keyring_mutex;
struct Log {
    std::ostringstream stream;
    template<class T> Log& operator<<(const T& value) { stream << value; return *this; }
    ~Log() { messages.push_back(stream.str()); }
};
#define LOG(level) Log()
#define PLOG(level) Log()
static bool zeros(const void* ptr, size_t n) {
    const auto* p = static_cast<const unsigned char*>(ptr);
    return std::all_of(p, p+n, [](auto v) { return v == 0; });
}
static int host_open(const char* path, int flags) {
    CHECK(std::string(path) == "/synthetic");
    CHECK(flags == (O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    opens++;
    if (fail_open) { failed_opens++; errno=EACCES; return -1; }
    live_fds++; return 123;
}
namespace android::base {
class unique_fd {
    int value;
public:
    explicit unique_fd(int fd):value(fd) {}
    ~unique_fd() { if (value >= 0) { CHECK(live_fds > 0); live_fds--; closes++; } }
    operator int() const { return value; }
};
std::vector<std::string> Split(const std::string& s, const std::string& delim) {
    CHECK(delim.size()==1); std::vector<std::string> out; size_t pos=0;
    for (;;) { auto next=s.find(delim,pos); out.push_back(s.substr(pos,next-pos));
        if(next==std::string::npos) break; pos=next+1; }
    return out;
}
}
static void validate_spec(const fscrypt_key_specifier& spec) {
    CHECK(spec.__reserved==0);
    CHECK(spec.type==FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR ||
          spec.type==FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER);
    size_t used=spec.type==FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR ?
        FSCRYPT_KEY_DESCRIPTOR_SIZE : FSCRYPT_KEY_IDENTIFIER_SIZE;
    CHECK(zeros(spec.u.__reserved+used,sizeof(spec.u.__reserved)-used));
    if (check_spec) CHECK(std::memcmp(&spec,&expected_spec,sizeof(spec))==0);
}
static int host_ioctl(int fd, unsigned long request, void* arg) {
    CHECK(fd==123 && live_fds>0); CHECK(!replies.empty());
    auto reply=replies.front(); replies.pop_front(); CHECK(reply.request==request);
    calls.push_back(request);
    if (request==FS_IOC_REMOVE_ENCRYPTION_KEY) {
        auto* a=static_cast<fscrypt_remove_key_arg*>(arg); validate_spec(a->key_spec);
        CHECK(a->removal_status_flags==0 && zeros(a->__reserved,sizeof(a->__reserved)));
        if (!reply.error) a->removal_status_flags=reply.value;
    } else if (request==FS_IOC_GET_ENCRYPTION_KEY_STATUS) {
        auto* a=static_cast<fscrypt_get_key_status_arg*>(arg); validate_spec(a->key_spec);
        CHECK(zeros(a->__reserved,sizeof(a->__reserved)) && a->status==0 &&
              a->status_flags==0 && a->user_count==0 && zeros(a->__out_reserved,sizeof(a->__out_reserved)));
        if (!reply.error) a->status=reply.value;
    } else if (request==FS_IOC_ADD_ENCRYPTION_KEY) {
        auto* a=static_cast<fscrypt_add_key_arg*>(arg); validate_spec(a->key_spec);
        CHECK(a->key_id==0 && zeros(a->__reserved,sizeof(a->__reserved)));
        CHECK(a->raw_size<=128); last_add=*a; last_raw.assign(a->raw,a->raw+a->raw_size);
        if (!reply.error && a->key_spec.type==FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER)
            std::memset(a->key_spec.u.identifier,0x49,FSCRYPT_KEY_IDENTIFIER_SIZE);
    } else CHECK(false);
    if (reply.error) { errno=reply.error; return -1; }
    return 0;
}
struct QueuedThread {
    std::function<void()> body;
    template<class F, class... A> QueuedThread(F f,A... a):body(std::bind(f,a...)) {}
    void detach() { jobs.push_back(std::move(body)); }
};
namespace fixture_std {
using std::string;
using std::mutex;
template<class T> using lock_guard=std::lock_guard<T>;
namespace chrono=std::chrono;
using thread=QueuedThread;
namespace this_thread {
void sleep_for(std::chrono::milliseconds time) {
    CHECK(sleeps.size()<6); sleeps.push_back(time.count());
    if (on_sleep) on_sleep(sleeps.size());
}
}
}
static std::string keyrefstring(const std::string& raw) { return std::to_string(raw.size()); }
#define __ANDROID_API_Q__ 29
#define FSCRYPT_MODE_AES_256_HEH 126
#define FSCRYPT_MODE_PRIVATE 127
namespace android::fscrypt {
#include "selected-options.h"
}
using android::fscrypt::expected_full_ref;
using android::fscrypt::expected_half_ref;
// Remap only external host boundaries; included function text is unchanged.
#define open host_open
#define ioctl host_ioctl
#define std fixture_std
#include "selected-keyutil.h"
#undef std
#undef ioctl
#undef open
static_assert(sizeof(fscrypt_key_specifier)==40);
static_assert(sizeof(fscrypt_add_key_arg)==80);
static_assert(sizeof(fscrypt_remove_key_arg)==64);
static_assert(sizeof(fscrypt_get_key_status_arg)==128);
static EncryptionPolicy policy() {
    EncryptionPolicy p; p.options.version=1; p.options.key_type=KeyType::kRaw;
    p.key_raw_ref=std::string(8,'D'); return p;
}
static void reset() {
    CHECK(live_fds==0 && jobs.empty()); replies.clear(); calls.clear(); sleeps.clear(); messages.clear();
    opens=closes=failed_opens=0; fail_open=false; on_sleep={}; check_spec=true;
    std::memset(&expected_spec,0,sizeof(expected_spec));
    // Independent oracle: do not use the subject to construct its expectation.
    expected_spec.type=FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR;
    std::memset(expected_spec.u.descriptor,'D',FSCRYPT_KEY_DESCRIPTOR_SIZE);
    last_raw.clear(); std::memset(&last_add,0,sizeof(last_add));
}
static void worker() { CHECK(jobs.size()==1); auto job=std::move(jobs.front()); jobs.pop_front(); job(); }
static void balanced() { CHECK(replies.empty() && jobs.empty() && live_fds==0 && opens==closes+failed_opens); }
static void busy() {
    replies.push_back({FS_IOC_REMOVE_ENCRYPTION_KEY,0,FSCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY});
    CHECK(evictKey("/synthetic",policy())); CHECK(jobs.size()==1 && live_fds==0);
}
static void run(const std::string& name) {
    reset();
    if (name=="options") {
        EncryptionOptions o; CHECK(ParseOptionsForApiLevel(26,"aes-256-xts:aes-256-cts",&o));
        CHECK(o.version==1 && o.key_type==KeyType::kRaw && o.flags==0 && !o.dusize_4k);
        CHECK(ParseOptionsForApiLevel(30,"aes-256-xts:aes-256-cts",&o) && o.version==2);
        CHECK(!ParseOptionsForApiLevel(26,"aes-256-xts:aes-256-cts:wrong",&o));
    } else if (name=="add-shapes") {
        check_spec=false; KeyBuffer key(64); for(size_t i=0;i<key.size();i++) key[i]=i;
        for(auto type:{KeyType::kRaw,KeyType::kHwWrappedV0,KeyType::kHwWrapped}) {
            auto p=policy(); p.options.key_type=type; replies.push_back({FS_IOC_ADD_ENCRYPTION_KEY});
            CHECK(installKey("/synthetic",p.options,key,&p));
            CHECK(last_add.raw_size==64 && last_raw==std::vector<unsigned char>(key.begin(),key.end()));
            CHECK(last_add.key_spec.type==FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR && p.key_raw_ref.size()==8);
            CHECK(last_add.flags==(type==KeyType::kHwWrapped ? 1U:0U));
            CHECK(last_add.__flags==(type==KeyType::kHwWrappedV0 ? 1U:0U));
            const auto& expected=type==KeyType::kHwWrappedV0 ? expected_half_ref : expected_full_ref;
            CHECK(std::memcmp(last_add.key_spec.u.descriptor,expected.data(),8)==0);
        }
        auto p=policy(); p.options.version=2; replies.push_back({FS_IOC_ADD_ENCRYPTION_KEY});
        CHECK(installKey("/synthetic",p.options,key,&p));
        CHECK(last_add.key_spec.type==FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER &&
              zeros(last_add.key_spec.u.identifier,16) && p.key_raw_ref==std::string(16,'I'));
    } else if (name=="remove-clean") {
        replies.push_back({FS_IOC_REMOVE_ENCRYPTION_KEY}); CHECK(evictKey("/synthetic",policy()));
        CHECK(jobs.empty() && calls.size()==1);
    } else if (name=="busy-cleanup") {
        busy(); replies.push_back({FS_IOC_GET_ENCRYPTION_KEY_STATUS,0,FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED});
        replies.push_back({FS_IOC_REMOVE_ENCRYPTION_KEY}); worker(); CHECK(sleeps==std::vector<long>{3200});
    } else if (name=="busy-retry") {
        busy(); for(unsigned flags:{1U,0U}) {
            replies.push_back({FS_IOC_GET_ENCRYPTION_KEY_STATUS,0,FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED});
            replies.push_back({FS_IOC_REMOVE_ENCRYPTION_KEY,0,flags}); }
        worker(); CHECK(sleeps==std::vector<long>({3200,6400}));
    } else if (name=="readd-present" || name=="already-absent") {
        busy(); replies.push_back({FS_IOC_GET_ENCRYPTION_KEY_STATUS,0,static_cast<unsigned>(name=="readd-present" ? FSCRYPT_KEY_STATUS_PRESENT:FSCRYPT_KEY_STATUS_ABSENT)});
        worker(); CHECK(calls.size()==2 && sleeps.size()==1);
    } else if (name=="readd-during-wait") {
        busy(); on_sleep=[](size_t n) { CHECK(n==1); CHECK(fscrypt_keyring_mutex.try_lock());
            fscrypt_keyring_mutex.unlock(); replies.push_back({FS_IOC_GET_ENCRYPTION_KEY_STATUS,0,FSCRYPT_KEY_STATUS_PRESENT}); };
        worker(); CHECK(calls.size()==2);
    } else if (name=="status-error") {
        busy(); replies.push_back({FS_IOC_GET_ENCRYPTION_KEY_STATUS,EIO}); worker(); CHECK(calls.size()==2);
    } else if (name=="retry-remove-error") {
        busy(); replies.push_back({FS_IOC_GET_ENCRYPTION_KEY_STATUS,0,FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED});
        replies.push_back({FS_IOC_REMOVE_ENCRYPTION_KEY,EIO}); worker(); CHECK(calls.size()==3);
    } else if (name=="initial-remove-error") {
        replies.push_back({FS_IOC_REMOVE_ENCRYPTION_KEY,EIO}); CHECK(!evictKey("/synthetic",policy())); CHECK(jobs.empty());
    } else if (name=="other-users") {
        replies.push_back({FS_IOC_REMOVE_ENCRYPTION_KEY,0,3}); CHECK(evictKey("/synthetic",policy()));
        CHECK(jobs.empty()); CHECK(std::any_of(messages.begin(),messages.end(),[](auto s){return s.find("other users")!=std::string::npos;}));
    } else if (name=="worker-other-users") {
        busy(); replies.push_back({FS_IOC_GET_ENCRYPTION_KEY_STATUS,0,FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED});
        replies.push_back({FS_IOC_REMOVE_ENCRYPTION_KEY,0,FSCRYPT_KEY_REMOVAL_STATUS_FLAG_OTHER_USERS});
        replies.push_back({FS_IOC_GET_ENCRYPTION_KEY_STATUS,0,FSCRYPT_KEY_STATUS_PRESENT}); worker();
        CHECK(sleeps==std::vector<long>({3200,6400}));
    } else if (name=="exhaustion") {
        busy(); for(int i=0;i<5;i++) { replies.push_back({FS_IOC_GET_ENCRYPTION_KEY_STATUS,0,FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED}); replies.push_back({FS_IOC_REMOVE_ENCRYPTION_KEY,0,1}); }
        worker(); CHECK(sleeps==std::vector<long>({3200,6400,12800,25600,51200})); CHECK(calls.size()==11);
    } else if (name=="invalid-spec") {
        auto p=policy(); p.key_raw_ref.resize(7); CHECK(!evictKey("/synthetic",p)); CHECK(calls.empty());
        p.options.version=2;p.key_raw_ref.resize(8);CHECK(!evictKey("/synthetic",p));
        p.options.version=99;CHECK(!evictKey("/synthetic",p));CHECK(calls.empty());
    } else if (name=="open-errors") {
        fail_open=true; CHECK(!evictKey("/synthetic",policy())); CHECK(opens==1 && closes==0);
        fail_open=false; busy(); fail_open=true; worker(); CHECK(opens==3 && closes==1);
    } else if (name=="add-error") {
        check_spec=false; auto p=policy(); KeyBuffer key(64,1); replies.push_back({FS_IOC_ADD_ENCRYPTION_KEY,EIO});
        CHECK(!installKey("/synthetic",p.options,key,&p));
    } else CHECK(false);
    balanced(); std::cout<<name<<": PASS\n";
}
int main(int argc,char**argv) { CHECK(argc==2);run(argv[1]); }
