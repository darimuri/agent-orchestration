// Host-side primitives. No path or repair API is exposed to an agent/worker.
#include "custody.h"
#include <sys/syscall.h>
#include <linux/openat2.h>
#include <linux/stat.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>
#include <limits.h>
static uint32_t rotate(uint32_t x,unsigned n){return (x>>n)|(x<<(32U-n));}
static void compress(ogw_sha256 *s){
 static const uint32_t k[64]={0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U};
 uint32_t w[64];for(unsigned i=0;i<16U;i++)w[i]=(uint32_t)ogw_get(s->block+i*4U,4);
 for(unsigned i=16U;i<64U;i++){uint32_t a=w[i-15U],b=w[i-2U];w[i]=w[i-16U]+(rotate(a,7)^rotate(a,18)^(a>>3))+w[i-7U]+(rotate(b,17)^rotate(b,19)^(b>>10));}
 uint32_t a=s->h[0],b=s->h[1],c=s->h[2],d=s->h[3],e=s->h[4],f=s->h[5],g=s->h[6],h=s->h[7];
 for(unsigned i=0;i<64U;i++){uint32_t t=h+(rotate(e,6)^rotate(e,11)^rotate(e,25))+((e&f)^(~e&g))+k[i]+w[i];uint32_t u=(rotate(a,2)^rotate(a,13)^rotate(a,22))+((a&b)^(a&c)^(b&c));h=g;g=f;f=e;e=d+t;d=c;c=b;b=a;a=t+u;}
 s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;
}
void ogw_hash_init(ogw_sha256 *s){const uint32_t h[8]={0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U};memset(s,0,sizeof(*s));memcpy(s->h,h,sizeof(h));}
void ogw_hash_update(ogw_sha256 *s,const void *data,size_t n){const uint8_t *p=data;s->length+=(uint64_t)n;while(n){size_t take=64U-s->used;if(take>n)take=n;memcpy(s->block+s->used,p,take);s->used+=take;p+=take;n-=take;if(s->used==64U){compress(s);s->used=0;}}}
void ogw_hash_final(ogw_sha256 *s,uint8_t out[32]){uint64_t bits=s->length*8U;s->block[s->used++]=0x80U;if(s->used>56U){memset(s->block+s->used,0,64U-s->used);compress(s);s->used=0;}memset(s->block+s->used,0,56U-s->used);ogw_put(s->block+56,bits,8);compress(s);for(unsigned i=0;i<8U;i++)ogw_put(out+4U*i,s->h[i],4);}
bool ogw_same(const struct stat *a,const struct stat *b){return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_mode==b->st_mode&&a->st_nlink==b->st_nlink&&a->st_size==b->st_size&&a->st_mtim.tv_sec==b->st_mtim.tv_sec&&a->st_mtim.tv_nsec==b->st_mtim.tv_nsec&&a->st_ctim.tv_sec==b->st_ctim.tv_sec&&a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;}
bool ogw_hash_fd(int fd,uint64_t limit,uint8_t out[32]){
 struct stat a,b;if(fstat(fd,&a)||!S_ISREG(a.st_mode)||a.st_size<0||(uint64_t)a.st_size>limit||a.st_nlink!=1)return false;
 uint8_t bytes[65536];ogw_sha256 h;ogw_hash_init(&h);uint64_t offset=0;
 for(;;){ssize_t n=pread(fd,bytes,sizeof(bytes),(off_t)offset);if(n<0&&errno==EINTR)continue;if(n<0)return false;if(!n)break;if((uint64_t)n>limit-offset)return false;ogw_hash_update(&h,bytes,(size_t)n);offset+=(uint64_t)n;}
 if(offset!=(uint64_t)a.st_size||fstat(fd,&b)||!ogw_same(&a,&b))return false;ogw_hash_final(&h,out);return true;
}
bool ogw_write_all(int fd,const void *bytes,size_t n){const uint8_t *p=bytes;while(n){ssize_t r=write(fd,p,n);if(r<0&&errno==EINTR)continue;if(r<=0||(size_t)r>n)return false;p+=(size_t)r;n-=(size_t)r;}return true;}
int ogw_open_beneath(int dir,const char *name,int flags){
 if(!name||!*name||*name=='/'){errno=EINVAL;return -1;}
 struct open_how how={.flags=(uint64_t)(unsigned)(flags|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK),.mode=0,.resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV};
 return (int)syscall(SYS_openat2,dir,name,&how,sizeof(how));
}
bool ogw_mount_id(int fd,uint64_t *id){struct statx s;memset(&s,0,sizeof(s));if(syscall(SYS_statx,fd,"",AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW,STATX_MNT_ID,&s)||(s.stx_mask&STATX_MNT_ID)==0U)return false;*id=s.stx_mnt_id;return true;}
bool ogw_directory(int fd,uid_t uid,dev_t device){struct stat s;return !fstat(fd,&s)&&S_ISDIR(s.st_mode)&&s.st_uid==uid&&s.st_dev==device&&(s.st_mode&07777U)==0700U;}
bool ogw_regular(int fd,uid_t uid,dev_t device,uint64_t limit){struct stat s;return !fstat(fd,&s)&&S_ISREG(s.st_mode)&&s.st_uid==uid&&s.st_dev==device&&(s.st_mode&07777U)==0600U&&s.st_nlink==1&&s.st_size>=0&&(uint64_t)s.st_size<=limit;}
bool ogw_copy_seal(int source,int destination,const uint8_t digest[32]){
 struct stat a,b,d;if(fstat(source,&a)||fstat(destination,&d)||!S_ISREG(a.st_mode)||a.st_nlink!=1||a.st_size<1||(uint64_t)a.st_size>OGW_BUNDLE||!S_ISREG(d.st_mode)||d.st_nlink!=1||d.st_size!=0||a.st_dev!=d.st_dev||a.st_ino==d.st_ino)return false;
 uint8_t bytes[65536],got[32];uint64_t at=0;ogw_sha256 h;ogw_hash_init(&h);
 while(at<(uint64_t)a.st_size){size_t want=sizeof(bytes);if((uint64_t)want>(uint64_t)a.st_size-at)want=(size_t)((uint64_t)a.st_size-at);ssize_t n=pread(source,bytes,want,(off_t)at);if(n<0&&errno==EINTR)continue;if(n<=0||!ogw_write_all(destination,bytes,(size_t)n))return false;ogw_hash_update(&h,bytes,(size_t)n);at+=(uint64_t)n;}
 ogw_hash_final(&h,got);
 if(memcmp(got,digest,32)||fstat(source,&b)||!ogw_same(&a,&b)||fsync(destination))return false;
 // Metadata can be indistinguishable after a same-size mutation. Rehash the
 // held SOURCE after copying, bracketed by the original identity, as well as
 // rereading the sealed destination. Any mismatch remains UNKNOWN.
 if(!ogw_hash_fd(source,OGW_BUNDLE,got)||memcmp(got,digest,32)||fstat(source,&b)||!ogw_same(&a,&b))return false;
 if(!ogw_hash_fd(destination,OGW_BUNDLE,got)||memcmp(got,digest,32)||fstat(source,&b)||!ogw_same(&a,&b))return false;
 return true;
}
bool ogw_hex_name(const char *name,size_t n){if(strlen(name)!=n)return false;for(size_t i=0;i<n;i++)if(!((name[i]>='0'&&name[i]<='9')||(name[i]>='a'&&name[i]<='f')))return false;return true;}
static int order(const struct dirent **a,const struct dirent **b){return strcmp((*a)->d_name,(*b)->d_name);}
bool ogw_sync_tree(int dir,dev_t device,unsigned depth,unsigned *count,uint64_t *bytes,ogw_sha256 *inventory){
 if(depth>32U)return false;struct stat anchor,after;if(fstat(dir,&anchor)||!S_ISDIR(anchor.st_mode)||anchor.st_dev!=device||anchor.st_uid!=OGW_HOST_UID||(anchor.st_mode&07777U)!=0700U)return false;
 // scandirat works relative to a held descriptor; sorted bounded inventory. The
 // directory is no longer worker-writable; host identity is checked again below.
 struct dirent **names=NULL;int total=scandirat(dir,".",&names,NULL,order);if(total<0)return false;
 bool ok=(unsigned)total<=OGW_INODES;uint64_t mount;if(!ogw_mount_id(dir,&mount))ok=false;
 uint64_t children=0;for(int i=0;i<total;i++)if(strcmp(names[i]->d_name,".")&&strcmp(names[i]->d_name,".."))children++;
 uint8_t child_count[8];ogw_put(child_count,children,8);ogw_hash_update(inventory,"[",1);ogw_hash_update(inventory,child_count,8);
 for(int i=0;i<total;i++){const char *name=names[i]->d_name;if(ok&&strcmp(name,".")&&strcmp(name,"..")){
  if(++*count>OGW_INODES||strlen(name)>255U)ok=false;
  int fd=ok?ogw_open_beneath(dir,name,O_RDONLY):-1;struct stat s;uint64_t m=0;
  if(fd<0||fstat(fd,&s)||s.st_dev!=device||s.st_uid!=OGW_HOST_UID||!ogw_mount_id(fd,&m)||m!=mount)ok=false;
  if(ok){uint8_t length[8];size_t n=strlen(name);ogw_put(length,n,8);ogw_hash_update(inventory,length,8);ogw_hash_update(inventory,name,n);
   if(S_ISDIR(s.st_mode)){ogw_hash_update(inventory,"D",1);ok=ogw_sync_tree(fd,device,depth+1U,count,bytes,inventory);}
   else if(S_ISREG(s.st_mode)&&s.st_nlink==1&&(s.st_mode&07777U)==0600U&&s.st_size>=0&&(uint64_t)s.st_size<=OGW_SCRATCH-*bytes){uint8_t digest[32];*bytes+=(uint64_t)s.st_size;ogw_hash_update(inventory,"F",1);ogw_put(length,(uint64_t)s.st_size,8);ogw_hash_update(inventory,length,8);ok=fsync(fd)==0&&ogw_hash_fd(fd,OGW_SCRATCH,digest);if(ok)ogw_hash_update(inventory,digest,32);}
   else ok=false;
  }
  if(fd>=0&&close(fd))ok=false;
 }free(names[i]);}
 free(names);ogw_hash_update(inventory,"]",1);return ok&&!fstat(dir,&after)&&ogw_same(&anchor,&after)&&fsync(dir)==0;
}
bool ogw_adopt(int from,const char *name,int to,const char *destination){
 if(!ogw_hex_name(name,64U)||!ogw_hex_name(destination,64U))return false;
 struct stat a,b;uint64_t am,bm;if(fstat(from,&a)||fstat(to,&b)||!S_ISDIR(a.st_mode)||!S_ISDIR(b.st_mode)||a.st_dev!=b.st_dev||!ogw_mount_id(from,&am)||!ogw_mount_id(to,&bm)||am!=bm)return false;
 // No fallback: failed/uncertain effects remain retained UNKNOWN to the caller.
 if(syscall(SYS_renameat2,from,name,to,destination,RENAME_NOREPLACE))return false;
 return fsync(from)==0&&fsync(to)==0;
}
