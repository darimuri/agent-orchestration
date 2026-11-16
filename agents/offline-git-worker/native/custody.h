#ifndef OGW_CUSTODY_H
#define OGW_CUSTODY_H
#include "protocol.h"
#include <sys/stat.h>
typedef struct { uint32_t h[8];uint64_t length;size_t used;uint8_t block[64]; } ogw_sha256;
void ogw_hash_init(ogw_sha256 *s);
void ogw_hash_update(ogw_sha256 *s,const void *data,size_t n);
void ogw_hash_final(ogw_sha256 *s,uint8_t out[32]);
bool ogw_hash_fd(int fd,uint64_t limit,uint8_t out[32]);
bool ogw_same(const struct stat *a,const struct stat *b);
bool ogw_write_all(int fd,const void *bytes,size_t n);
int ogw_open_beneath(int dir,const char *name,int flags);
bool ogw_mount_id(int fd,uint64_t *id);
bool ogw_directory(int fd,uid_t uid,dev_t device);
bool ogw_regular(int fd,uid_t uid,dev_t device,uint64_t limit);
bool ogw_copy_seal(int source,int destination,const uint8_t digest[32]);
bool ogw_sync_tree(int dir,dev_t device,unsigned depth,unsigned *count,uint64_t *bytes,ogw_sha256 *inventory);
bool ogw_adopt(int from,const char *name,int to,const char *destination);
bool ogw_hex_name(const char *name,size_t n);
#endif
