/*
 * This interface provides wrapper methods for using the XrdAcc Authorization framework
 */

#ifndef _CEPH_AUTHZ_H
#define _CEPH_AUTHZ_H

#include <sys/types.h>
#include <stdarg.h>
#include <dirent.h>

#ifdef __cplusplus
extern "C" {
#endif

  int ceph_authz_init(const char* username);
  int ceph_authz_allow(const char* path, const char* operation);

#ifdef __cplusplus
}
#endif

#endif
