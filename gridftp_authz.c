#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "gridftp_authz.h"

authdbentry* tokenize(char* line) {
  
  const char* delim = "   ";  // Space and tab - but tabs are not removed from individual tokens
  
  authdbentry* rec = (authdbentry *)malloc(sizeof(authdbentry));
  (void)strtok(line, delim);
  
  rec->user = strdup(strtok(NULL, delim));
  rec->path = strdup(strtok(NULL, delim));
  rec->priv = strdup(strtok(NULL, delim));
  
  if (rec->user == NULL || rec->path == NULL || rec->priv == NULL) {
    rec = NULL;
  }

  return rec;
  
}

int checkallowed(const char *user, const char* operation, const char* path, authdbentry* rec) {

  int isallowed = 0;

  if (!strcmp(user, rec->user) && strstr(path, rec->path) == path )  { 
    // path starts with rec->path at position 0, 
    // (and the path relates to the user we have just matched)  
    
#define WRITE(operation) !strcmp("wr", operation)
#define READONLY(priv) !strcmp("r", priv)
         
    if ( ! (WRITE(operation) && READONLY(rec->priv)) )  {     
      // If we're not trying to write where we only have read access, allow this operation
      isallowed = 1;      
    } 

  }
  return isallowed;
}

int checkaccess(const char* authdb, const int bufsize,
        const char* user, const char* operation, const char* path) {
  
  FILE *fp = fopen(authdb, "r");
  if (fp == NULL) {
    return 0;
  }
  char* buf = (char*)malloc(bufsize * sizeof(char));
  
  int isallowed = 0;
  
  while (!isallowed && fgets(buf, bufsize, fp)) {
    
    if (buf[0] == '#' || isspace(buf[0])) {
      continue;
    }

    buf[strlen(buf)-1] = '\0';
    
    authdbentry *rec = tokenize(buf);
    
    if (rec == NULL) { // Something went wrong with tokenizing
      
      fclose(fp);
      break;
      
    }
    
    isallowed = checkallowed(user, operation, path, rec);
  
  }
  fclose(fp);
  return isallowed;
  
}