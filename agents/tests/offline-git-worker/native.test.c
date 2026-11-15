// REAL disposable FD/filesystem primitives; no kernel-isolation PASS claim.
#define OGW_TEST 1
#include "../../offline-git-worker/native/supervisor.c"
#include <assert.h>
// Compile-time-only fault seams. Production custody has no injected callbacks.
static unsigned fault;
static int mutate_fd=-1;
static ssize_t fault_write(int fd,const void *bytes,size_t n){
 if(fault==1U)return write(fd,bytes,n>1U?1U:n);
 if(fault==2U)return 0;
 if(fault==3U){errno=ENOSPC;return -1;}
 if(fault==5U&&mutate_fd>=0){assert(pwrite(mutate_fd,"z",1,0)==1);mutate_fd=-1;}
 return write(fd,bytes,n);
}
static int fault_fsync(int fd){if(fault==4U){errno=EIO;return -1;}return fsync(fd);}
#define write fault_write
#define fsync fault_fsync
#include "../../offline-git-worker/native/custody.c"
#undef write
#undef fsync
static void digest_vector(const char *text,const char *expected){ogw_sha256 h;uint8_t digest[32];char encoded[65];ogw_hash_init(&h);ogw_hash_update(&h,text,strlen(text));ogw_hash_final(&h,digest);hex32(digest,encoded);assert(!strcmp(encoded,expected));}
static void primitives(void){
 char temporary[]="/tmp/ogw-native-XXXXXX";assert(mkdtemp(temporary));int root=open(temporary,O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(root>=0);
 assert(mkdirat(root,"a",0700)==0);assert(mkdirat(root,"b",0700)==0);
 int a=ogw_open_beneath(root,"a",O_RDONLY|O_DIRECTORY),b=ogw_open_beneath(root,"b",O_RDONLY|O_DIRECTORY);assert(a>=0&&b>=0);
 const char *name="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
 const char *other="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
 assert(mkdirat(a,name,0700)==0);assert(mkdirat(b,other,0700)==0);
 assert(!ogw_adopt(a,name,b,other));struct stat s;assert(!fstatat(a,name,&s,AT_SYMLINK_NOFOLLOW));
 assert(!unlinkat(b,other,AT_REMOVEDIR));assert(ogw_adopt(a,name,b,other));assert(fstatat(a,name,&s,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT);
 assert(symlinkat("/etc/passwd",root,"link")==0);assert(ogw_open_beneath(root,"link",O_RDONLY)<0);
 assert(mkfifoat(root,"fifo",0600)==0);int fifo=ogw_open_beneath(root,"fifo",O_RDONLY);assert(fifo>=0);assert(!ogw_regular(fifo,getuid(),s.st_dev,100));assert(close(fifo)==0);
 assert(ogw_open_beneath(root,"../",O_RDONLY|O_DIRECTORY)<0);
 int input=openat(root,"input",O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0600),copy=openat(root,"copy",O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0600);assert(input>=0&&copy>=0);assert(ogw_write_all(input,"abc",3));
 uint8_t digest[32];assert(ogw_hash_fd(input,3,digest));assert(ogw_copy_seal(input,copy,digest));assert(!ogw_copy_seal(input,copy,digest));assert(linkat(root,"input",root,"hard",0)==0);assert(!ogw_hash_fd(input,3,digest));
 assert(unlinkat(root,"hard",0)==0);
 for(fault=1U;fault<=5U;fault++){
  assert(ftruncate(input,0)==0&&pwrite(input,"abc",3,0)==3&&ftruncate(copy,0)==0&&lseek(copy,0,SEEK_SET)==0);assert(ogw_hash_fd(input,3,digest));
  if(fault==5U)mutate_fd=input;
  bool result=ogw_copy_seal(input,copy,digest);assert(result==(fault==1U));
 }
 fault=0;
 assert(close(input)==0&&close(copy)==0);assert(unlinkat(root,"input",0)==0&&unlinkat(root,"copy",0)==0&&unlinkat(root,"fifo",0)==0&&unlinkat(root,"link",0)==0);
 assert(unlinkat(b,other,AT_REMOVEDIR)==0);
 // REAL two-process no-replace race with distinct sources and one destination.
 const char *target="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
 assert(mkdirat(a,name,0700)==0&&mkdirat(a,other,0700)==0);pid_t racers[2];
 for(unsigned i=0;i<2U;i++){racers[i]=fork();assert(racers[i]>=0);if(racers[i]==0)_exit(ogw_adopt(a,i==0U?name:other,b,target)?0:1);}
 unsigned successes=0;for(unsigned i=0;i<2U;i++){int status;assert(waitpid(racers[i],&status,0)==racers[i]&&WIFEXITED(status));if(WEXITSTATUS(status)==0)successes++;else assert(WEXITSTATUS(status)==1);}assert(successes==1U);
 if(fstatat(a,name,&s,AT_SYMLINK_NOFOLLOW)==0)assert(unlinkat(a,name,AT_REMOVEDIR)==0);
 if(fstatat(a,other,&s,AT_SYMLINK_NOFOLLOW)==0)assert(unlinkat(a,other,AT_REMOVEDIR)==0);
 assert(unlinkat(b,target,AT_REMOVEDIR)==0);assert(close(a)==0&&close(b)==0);assert(unlinkat(root,"a",AT_REMOVEDIR)==0&&unlinkat(root,"b",AT_REMOVEDIR)==0);assert(close(root)==0&&rmdir(temporary)==0);
}
int main(void){
 // Keep the production entry reachable to the compiler without running root code.
 (void)supervise;
 digest_vector("","e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
 digest_vector("abc","ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
 primitives();puts("REAL FD/no-follow/no-replace/hash primitives; NOT host acceptance");return 0;
}
