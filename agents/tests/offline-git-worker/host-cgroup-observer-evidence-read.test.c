// NONROOT compile-time IO simulation only. No production reader or cgroup access.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <linux/stat.h>
static int t_root(void),t_open(int,const char *,int,bool),t_stat(int,struct stat *),t_statx(int,struct statx *),t_fs(int,struct statfs *),t_flags(int),t_close(int);
static ssize_t t_read(int,void *,size_t),t_write(int,const void *,size_t);
static long t_dents(int,void *,size_t);
#define EVIDENCE_FIXTURE 1
#define IO_ROOT t_root
#define IO_OPEN t_open
#define IO_STAT t_stat
#define IO_STATX t_statx
#define IO_FS t_fs
#define IO_CLOSE t_close
#define IO_READ t_read
#define IO_WRITE t_write
#define IO_DENTS t_dents
#define IO_FLAGS t_flags
#include "host-cgroup-observer-evidence-read.c"
#define FD_CAP 256U
// Literal independent scope/oracle, not generated from production path arrays.
static const char *const paths[]={"/","/var","/var/lib","/var/lib/age30-qualification","/var/lib/age30-qualification/evidence","/var/lib/age30-qualification/evidence/age30-8bbc3a9d-r1-cgroup-observe-v1","/var/lib/age30-qualification/evidence/age30-8bbc3a9d-r1-cgroup-observe-v1/start.json","/var/lib/age30-qualification/evidence/age30-8bbc3a9d-r1-cgroup-observe-v1/observations.json","/var/lib/age30-qualification/evidence/age30-8bbc3a9d-r1-cgroup-observe-v1/result.json","/var/lib/age30-qualification/bin","/var/lib/age30-qualification/bin/cgroup-observe-v1","/sys","/sys/fs","/sys/fs/cgroup","/sys/fs/cgroup/cgroup.controllers","/sys/fs/cgroup/cgroup.subtree_control","/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1","/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup.type","/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup.controllers","/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup.subtree_control","/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup.procs","/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup.events","/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1","/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/cgroup.type","/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/cgroup.events","/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/cgroup.procs","/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/cpu.max","/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/cpu.max.burst","/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/memory.max","/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/memory.swap.max","/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/memory.oom.group","/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/pids.max","/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/cpu.stat","/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/memory.current","/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/memory.events","/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/pids.current"};
static const char golden[]="open:/\nopen:/var\nopen:/var/lib\nopen:/var/lib/age30-qualification\nopen:/var/lib/age30-qualification/evidence\nopen:/var/lib/age30-qualification/evidence/age30-8bbc3a9d-r1-cgroup-observe-v1\nopen:/var/lib/age30-qualification/evidence/age30-8bbc3a9d-r1-cgroup-observe-v1/start.json\nread:/var/lib/age30-qualification/evidence/age30-8bbc3a9d-r1-cgroup-observe-v1/start.json\nopen:/var/lib/age30-qualification/evidence/age30-8bbc3a9d-r1-cgroup-observe-v1/observations.json\nread:/var/lib/age30-qualification/evidence/age30-8bbc3a9d-r1-cgroup-observe-v1/observations.json\nopen:/var/lib/age30-qualification/evidence/age30-8bbc3a9d-r1-cgroup-observe-v1/result.json\nread:/var/lib/age30-qualification/evidence/age30-8bbc3a9d-r1-cgroup-observe-v1/result.json\nopen:/var/lib/age30-qualification/bin\nopen:/var/lib/age30-qualification/bin/cgroup-observe-v1\nread:/var/lib/age30-qualification/bin/cgroup-observe-v1\nopen:/sys\nopen:/sys/fs\nopen:/sys/fs/cgroup\nopen:/sys/fs/cgroup/cgroup.controllers\nread:/sys/fs/cgroup/cgroup.controllers\nopen:/sys/fs/cgroup/cgroup.subtree_control\nread:/sys/fs/cgroup/cgroup.subtree_control\nopen:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1\nopen:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup.type\nread:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup.type\nopen:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup.controllers\nread:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup.controllers\nopen:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup.subtree_control\nread:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup.subtree_control\nopen:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup.procs\nread:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup.procs\nopen:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup.events\nread:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup.events\ndents:fixed-parent\nopen:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1\nopen:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/cgroup.type\nread:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/cgroup.type\nopen:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/cgroup.events\nread:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/cgroup.events\nopen:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/cgroup.procs\nread:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/cgroup.procs\nopen:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/cpu.max\nread:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/cpu.max\nopen:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/cpu.max.burst\nread:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/cpu.max.burst\nopen:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/memory.max\nread:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/memory.max\nopen:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/memory.swap.max\nread:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/memory.swap.max\nopen:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/memory.oom.group\nread:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/memory.oom.group\nopen:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/pids.max\nread:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/pids.max\nopen:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/cpu.stat\nread:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/cpu.stat\nopen:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/memory.current\nread:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/memory.current\nopen:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/memory.events\nread:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/memory.events\nopen:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/pids.current\nread:/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/cgroup-observe-v1/pids.current\ndents:fixed-leaf\n";
static bool named_bad[FD_CAP];static unsigned opened[256],open_count;static int which[FD_CAP];static size_t cursor[FD_CAP];static bool seen[36],read_seen[36],failed,emitting,mutated;
static unsigned event,fail_at,scenario,writes,reads;static int missing=-1,target=6;
static char trace[16384],captured[OUTPUT_BOUND+1U];static size_t trace_len,captured_len,custom_size;
static bool tick(void){assert(!emitting);assert(!failed);event++;if(event==fail_at){failed=true;errno=EIO;return false;}return true;}
static void note(const char *kind,const char *name){int n=snprintf(trace+trace_len,sizeof(trace)-trace_len,"%s:%s\n",kind,name);assert(n>0&&(size_t)n<sizeof(trace)-trace_len);trace_len+=(size_t)n;}
static bool dir_index(int p){return p==0||p==1||p==2||p==3||p==4||p==5||p==9||p==11||p==12||p==13||p==16||p==22;}
static int handle(int p){int fd=open("/dev/null",O_RDONLY|O_CLOEXEC);assert(fd>=3&&(unsigned)fd<FD_CAP);assert(open_count<256U);opened[open_count++]=(unsigned)p;which[fd]=p;cursor[fd]=0;named_bad[fd]=seen[p];if(!seen[p]){seen[p]=true;note("open",paths[p]);}return fd;}
static int t_close(int fd){int result=close(fd);assert(result==0);if(failed)return 0;return tick()?0:-1;}
static int t_root(void){if(!tick())return -1;return handle(0);}
static int t_open(int parent,const char *name,int f,bool cross){
 if(!tick())return -1;assert(!(f&(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC)));assert((f&(O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC))==(O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));
 char full[256];int n=snprintf(full,sizeof(full),"%s%s%s",paths[which[parent]],which[parent]?"/":"",name);assert(n>0&&(size_t)n<sizeof(full));int p=-1;for(unsigned i=1;i<36U;i++)if(!strcmp(full,paths[i]))p=(int)i;assert(p>=0);assert(cross==(p==1||p==2||p==11||p==12||p==13));if(p<13)assert(f&O_NOATIME);
 if(p==missing){errno=ENOENT;return -1;}if(p==target&&scenario==10U){errno=ELOOP;return -1;}if(p==target&&scenario==11U){errno=ENOSYS;return -1;}return handle(p);
}
static size_t data(int p,unsigned char *b,size_t cap){
 const char *v=p==17||p==23?"domain\n":p==20||p==25?"":p==21||p==24?"populated 0\nfrozen 0\n":p>=13?"cpu memory pids\n":"{bad json\n";
 if(p==target&&(scenario==20U||scenario==37U))v="threaded\n";if(p==target&&(scenario==21U||scenario==38U))v="123\n";if(p==target&&(scenario==22U||scenario==39U))v="populated 1\nfrozen 1\n";
 size_t n=strlen(v);if(p==10&&!(p==target&&custom_size)){n=BINARY_BOUND;if(b&&cap>=n){memset(b,0,n);b[0]=255;}return n;}
 if(p==target&&custom_size){n=custom_size;if(b&&cap>=n)memset(b,'X',n);return n;}
 if(p==target&&scenario==23U)n=0;if(b&&cap>=n)memcpy(b,v,n);return n;
}
static int t_stat(int fd,struct stat *st){
 if(!tick())return -1;memset(st,0,sizeof(*st));if(fd==1){st->st_mode=scenario==1U?S_IFREG|0600:S_IFIFO|0600;st->st_uid=getuid();return 0;}
 int p=which[fd];st->st_mode=dir_index(p)?S_IFDIR|(p==3||p==4||p==5||p==9||p==16||p==22?0700:0755):S_IFREG|(p==10?0500:0600);st->st_nlink=dir_index(p)?2:1;st->st_dev=p>=13?2:1;st->st_ino=(ino_t)(100+p);st->st_uid=0;st->st_gid=0;st->st_size=dir_index(p)?0:(off_t)data(p,NULL,0);st->st_mtim.tv_sec=1;st->st_ctim.tv_sec=1;
 if(p==target){if(scenario==2U)st->st_uid=10001;if(scenario==3U)st->st_mode|=0020;if(scenario==4U)st->st_nlink=2;if(scenario==5U)st->st_mode=S_IFIFO|0600;if(scenario==6U)st->st_dev++;if(scenario==7U&&mutated)st->st_ino++;if(scenario==8U&&mutated)st->st_size++;if(scenario==9U&&mutated)st->st_mtim.tv_sec++;if(scenario==24U)st->st_mode=S_IFSOCK|0600;if(scenario==25U)st->st_mode=S_IFCHR|0600;if(scenario==31U&&named_bad[fd])st->st_ino++;if(scenario==32U&&mutated)st->st_ctim.tv_sec++;if(scenario==33U)st->st_mode=S_IFREG|0400;}
 return 0;
}
static int t_statx(int fd,struct statx *x){if(!tick())return -1;memset(x,0,sizeof(*x));x->stx_mask=STATX_MNT_ID;x->stx_mnt_id=which[fd]>=13?2U:1U;if(which[fd]==target){if(scenario==12U)x->stx_mask=0;if(scenario==13U)x->stx_mnt_id++;if(scenario==14U&&mutated)x->stx_mnt_id++;}return 0;}
static int t_fs(int fd,struct statfs *f){if(!tick())return -1;memset(f,0,sizeof(*f));f->f_type=fd==1?0x50495045:CGROUP2_SUPER_MAGIC;if(scenario==26U&&fd!=1)f->f_type=TMPFS_MAGIC;return 0;}
static int t_flags(int fd){assert(fd==1);if(!tick())return -1;return scenario==27U?O_RDONLY:O_WRONLY;}
static ssize_t t_read(int fd,void *out,size_t n){
 if(!tick())return -1;reads++;int p=which[fd];assert(!dir_index(p));if(!read_seen[p]){read_seen[p]=true;note("read",paths[p]);}
 if(p==target&&scenario==15U){failed=true;errno=EINTR;return -1;}
 static unsigned char bytes[BINARY_BOUND+2U];size_t length=data(p,bytes,sizeof(bytes));size_t left=cursor[fd]<length?length-cursor[fd]:0;size_t take=n<left?n:left;
 if(p==target&&scenario==16U&&take>1U)take=1;
 memcpy(out,bytes+cursor[fd],take);cursor[fd]+=take;if(p==target)mutated=true;return (ssize_t)take;
}
// Like filldir64: write named fields/name/NUL, never record alignment padding.
static void kernel_record(void *out,unsigned short length,unsigned char type,const char *name){
 struct dent *d=out;d->ino=1;d->off=0;d->len=length;d->type=type;memcpy(d->name,name,strlen(name)+1U);
}
static long t_dents(int fd,void *out,size_t n){
 if(!tick())return -1;reads++;assert((which[fd]==16||which[fd]==22)&&n==VALUE_BOUND);for(size_t i=0;i<n;i++)assert(((unsigned char *)out)[i]==0U);if(cursor[fd]++)return scenario==18U?1:0;note("dents",which[fd]==16?"fixed-parent":"fixed-leaf");
 if(scenario==19U)return (long)VALUE_BOUND+1L;
 if(scenario==35U&&which[fd]==16){kernel_record(out,40U,DT_DIR,"cgroup-observe-v1");return 40;}
 if(scenario==36U){kernel_record(out,0U,DT_REG,"bad");return 32;}
 kernel_record(out,(unsigned short)(scenario==34U?4096U:32U),scenario==17U?DT_DIR:DT_REG,scenario==17U?"unexpected":"cgroup.type");return scenario==34U?4096:32;
}
static ssize_t t_write(int fd,const void *b,size_t n){assert(fd==1&&n<=4096U);emitting=true;writes++;assert(writes<=128U);if(scenario==28U){errno=EPIPE;return -1;}if(scenario==29U){errno=EINTR;return -1;}if(scenario==30U)return (ssize_t)n-1;assert(captured_len+n<=OUTPUT_BOUND);memcpy(captured+captured_len,b,n);captured_len+=n;captured[captured_len]=0;return (ssize_t)n;}
static void reset(unsigned kind){scenario=kind;open_count=0;event=fail_at=writes=reads=0;failed=emitting=mutated=false;missing=-1;target=6;custom_size=0;trace_len=captured_len=0;trace[0]=captured[0]=0;memset(seen,0,sizeof(seen));memset(read_seen,0,sizeof(read_seen));memset(which,0,sizeof(which));memset(cursor,0,sizeof(cursor));}
static bool complete(void){return strstr(captured,"\"collectionComplete\":true")!=NULL;}
// Decode the actual exported parent.entries, independently of production base64().
static void exported_padding_one(const char *name,bool parent){
 if(!captured_len)return;const char *object=strstr(captured,name);assert(object);
 const char *encoded=strstr(object,"\"base64\":\"");assert(encoded);encoded+=10U;
 const char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";unsigned char decoded[4098];size_t used=0;
 while(*encoded!='"'){
  unsigned v=0;for(unsigned j=0;j<4U;j++){const char *digit=encoded[j]=='='?NULL:strchr(alphabet,encoded[j]);assert(encoded[j]=='='||(digit&&encoded[j]));v=(v<<6U)|(digit?(unsigned)(digit-alphabet):0U);}
  assert(used+3U<=sizeof(decoded));decoded[used++]=(unsigned char)(v>>16U);if(encoded[2]!='=')decoded[used++]=(unsigned char)(v>>8U);if(encoded[3]!='=')decoded[used++]=(unsigned char)v;encoded+=4U;
 }
 if(!used||scenario==36U)return;if(scenario==35U&&parent){assert(used==40U);for(size_t i=37;i<used;i++)assert(decoded[i]==0);return;}assert(used==(scenario==34U?4096U:32U));
 // Linux x86_64 name offset19; cgroup.type+NUL ends at31, unexpected+NUL at30.
 for(size_t i=scenario==17U?30U:31U;i<used;i++)assert(decoded[i]==0U);
}
static void exported_padding(void){exported_padding_one("\"name\":\"parent.entries\"",true);exported_padding_one("\"name\":\"leaf.entries\"",false);}
int main(int argc,char **argv){
 if(argc==2&&!strcmp(argv[1],"--export-simulated")){assert(getuid()!=0&&geteuid()!=0);reset(0);assert(collect()==2&&complete());assert(fwrite(captured,1,captured_len,stdout)==captured_len);return 0;}assert(argc==1);
 assert(getuid()!=0&&geteuid()!=0);assert(eligible(1,true,0,0,0,0)&&!eligible(2,true,0,0,0,0)&&!eligible(1,false,0,0,0,0)&&!eligible(1,true,1,0,0,0));
 // Prove the shim preserves caller poison in padding and beyond the record.
 _Alignas(uint64_t) unsigned char poison[64];memset(poison,0xa5,sizeof(poison));kernel_record(poison,32U,DT_REG,"cgroup.type");
 for(size_t i=31U;i<sizeof(poison);i++)assert(poison[i]==0xa5U);
 reset(0);assert(collect()==2&&complete());exported_padding();unsigned boundaries=event;assert(boundaries>100U);if(strcmp(trace,golden))fprintf(stderr,"TRACE:\n%sEXPECTED:\n%s",trace,golden);assert(!strcmp(trace,golden));assert(strstr(captured,"/wAA")&&strstr(captured,"\"status\":\"UNKNOWN\"")&&!strstr(captured,"\"qualified\":true"));
 for(unsigned at=1;at<=boundaries;at++){reset(0);fail_at=at;assert(collect()==2&&failed&&!complete());exported_padding();}
 for(int p=1;p<36;p++){reset(0);missing=p;assert(collect()==2&&complete()&&strstr(captured,"\"status\":\"missing\""));}
 for(unsigned kind=1;kind<=39U;kind++){
  reset(kind);if(kind>=20U&&kind<=22U)target=kind==20U?17:kind==21U?20:21;if(kind>=37U)target=kind==37U?23:kind==38U?25:24;assert(collect()==2);
  if((kind>=20U&&kind<=23U)||kind==17U||kind==34U||kind==35U||kind>=37U)assert(complete());else assert(!complete());
  exported_padding();if(kind>=28U&&kind<=30U)assert(writes==1U);if(kind==17U)assert(strstr(captured,"unexpected_entries"));
 }
 const struct {int path;size_t bound;} limits[]={{6,16384U},{10,34528U},{14,4096U}};
 for(unsigned i=0;i<3U;i++)for(unsigned plus=0;plus<2U;plus++){reset(0);target=limits[i].path;custom_size=limits[i].bound+plus;assert(collect()==2);assert(complete()==(plus==0U));if(plus)assert(strstr(captured,"read_bound"));}
 // Conservative simultaneous maxima, including metadata wider than admitted custody.
 struct state worst;memset(&worst,0,sizeof(worst));struct identity maximum;memset(&maximum,0,sizeof(maximum));
 maximum.st.st_dev=(dev_t)UINT64_MAX;maximum.st.st_ino=(ino_t)UINT64_MAX;maximum.mount=UINT64_MAX;maximum.st.st_mode=07777U;
 maximum.st.st_uid=UINT_MAX;maximum.st.st_gid=UINT_MAX;maximum.st.st_nlink=(nlink_t)UINT64_MAX;maximum.st.st_size=INT64_MIN;
 maximum.st.st_mtim.tv_sec=INT64_MIN;maximum.st.st_mtim.tv_nsec=999999999;maximum.st.st_ctim=maximum.st.st_mtim;worst.nodes[0].before=maximum;
 for(unsigned i=0;i<OBJECTS;i++){worst.objects[i].name="leaf.memory.oom.group";worst.objects[i].status="unexpected_entries";worst.objects[i].node=0;worst.objects[i].after=maximum;worst.objects[i].after_valid=true;worst.objects[i].bytes=storage;worst.objects[i].length=i<3U?RECEIPT_BOUND:i==3U?BINARY_BOUND:VALUE_BOUND;}
 size_t maximum_size;assert(render(&worst,&maximum_size)&&maximum_size<OUTPUT_BOUND&&maximum_size>230000U);
 struct state error;memset(&error,0,sizeof(error));assert(!fail(&error,"first",EIO)&&!fail(&error,"second",ENOENT)&&!strcmp(error.error,"first")&&error.number==EIO);
 printf("SIMULATED read-only evidence fixture: %u IO boundaries, golden/missing/bounds/faults; UNKNOWN\n",boundaries);return 0;
}
