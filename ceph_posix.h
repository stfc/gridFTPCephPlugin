/*
 * This interface provides wrapper methods for using ceph through a POSIX API.
 */

#ifndef _CEPH_POSIX_H
#define _CEPH_POSIX_H

#include <sys/types.h>
#include <stdarg.h>
#include <dirent.h>

#ifdef __cplusplus
extern "C" {
#endif
  char *ceph_posix_get_checksum(const char* pathname);
  const char *getdebug();
  void ceph_posix_set_defaults(const char* value);
  void ceph_posix_disconnect_all();
  void ceph_posix_set_logfunc(void (*logfunc) (char *, va_list argp));
  int ceph_posix_open(const char *pathname, int flags, mode_t mode);
  int ceph_posix_close(int fd);
  off64_t ceph_posix_lseek64(int fd, off64_t offset, int whence);
  ssize_t ceph_posix_write(int fd, const void *buf, size_t count);
  ssize_t ceph_posix_read(int fd, void *buf, size_t count);
  int ceph_posix_stat64(const char *pathname, struct stat64 *buf);
  ssize_t ceph_posix_fgetxattr(int fd, const char* name, void* value, size_t size);
  int ceph_posix_fsetxattr(int fd, const char* name, const void* value, size_t size, int flags);
  char *ceph_posix_get_new_format_checksum_fd(const int fd);
  char *ceph_posix_get_new_format_checksum(const char* pathname);
  
  char *ceph_posix_get_old_format_checksum_fd(const int fd);
  char *ceph_posix_get_old_format_checksum(const char* pathname);

#ifdef __cplusplus
}
#endif

#endif
