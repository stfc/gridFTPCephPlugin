/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   external_delete.h
 * Author: ijj
 *
 * Created on August 2, 2016, 1:14 PM
 */

#ifndef EXTERNAL_DELETE_H
#define EXTERNAL_DELETE_H

#ifdef __cplusplus
extern "C" {
#endif

   int external_delete(const char* deleteprog, const char* conf, const char* pathname/* , const char* chunksize */);

#ifdef __cplusplus
}
#endif

#endif /* EXTERNAL_DELETE_H */

