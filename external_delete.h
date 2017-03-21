/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   gridftp_checkaccess.h
 * Author: ijj
 *
 * Created on August 2, 2016, 1:14 PM
 */

#ifndef GRIDFTP_CHECKACCESS_H
#define GRIDFTP_CHECKACCESS_H

#ifdef __cplusplus
extern "C" {
#endif

int checkAccess(const char* authdbprog, const char* authdbfile, 
        const char* user, const char* operation, const char* path);
  


#ifdef __cplusplus
}
#endif

#endif /* GRIDFTP_CHECKACCESS_H */

