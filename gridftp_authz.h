/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   gridftp_authz.h
 * Author: ijj
 *
 * Created on June 24, 2016, 1:16 PM
 */

#ifndef GRIDFTP_AUTHZ_H
#define GRIDFTP_AUTHZ_H

#ifdef __cplusplus
extern "C" {
#endif
    
typedef struct  ppelem {
  struct ppelem* next;

  const char* path;
  const char* priv;

} ppelem_t;

typedef struct {
  const char* user;
  ppelem_t * pp;
} authdbentry;

int checkallowed(const char *user, const char* operation, const char* path, authdbentry* rec);

#ifdef __cplusplus
}
#endif

#endif /* GRIDFTP_AUTHZ_H */

