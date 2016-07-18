#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>

#include "gridftp_authz.h"

extern int errno;

authdbentry* tokenize(char* line) {
   
  const char* delim = "   ";  // Space and tab - but tabs are not removed from individual tokens
  
  authdbentry* rec = (authdbentry *)malloc(sizeof(authdbentry));
  (void)strtok(line, delim); // Throw away the first token, the idtype 'u'
  
  const char * user = strtok(NULL, delim);
  
  if (user == NULL) {
    free(rec);
    return NULL;
  } else {
    rec->user = strdup(user);
  }
  
  ppelem_t *last = NULL;
  int ppcount = 0;

  do {
    
    const char * path = strtok(NULL, delim); 
    const char * priv = strtok(NULL, delim);

    if (path == NULL || priv == NULL) { // No more tokens (path/priv pairs)
      if (rec->pp == NULL) {
       // fprintf(stderr, "Found no path/priv pairs after user %s\n\n", user);
        free((void *)rec->user); // Cast to avoid warning about qualifiers for target
        free(rec);
        rec = NULL;
      } else {
       // fprintf(stdout, "found %d path/priv pairs after user '%s'\n\n", ppcount, user);
      }
      break;    // Get out of the do loop - or could set a variable to be checked by the 'while' test

    } else {
      ++ppcount;     
     // fprintf(stdout, "found path priv pair #%d - '%s' '%s'\n", ppcount, path, priv);

      ppelem_t * pp = (ppelem_t *) malloc(sizeof (ppelem_t *));
      pp->path = strdup(path);
      pp->priv = strdup(priv);

      if (last == NULL) { // First element we've seen
        rec->pp = pp;     // Put head of list in authdbentry        
      } else {
        last->next = pp;
      }
      last = pp;
      pp->next = NULL;
      
    }

  } while (1);
  
  return rec;
  
}

int checkallowed(const char *user, const char* operation, const char* path, authdbentry* rec) {

  int isallowed = 0;

  if (!strcmp(user, rec->user)) {

    ppelem_t * pp = rec->pp;
    while (pp != NULL) {

      if (strstr(path, pp->path) == path) {  // Testing that 'path' starts with 'rec->path' 

#define WRITE(operation) !strcmp("wr", operation)
#define READONLY(priv) !strcmp("r", priv)

        if (! (WRITE(operation) && READONLY(pp->priv))) {
          // If we're not trying to write where we only have read access, allow this operation
          isallowed = 1;
          break;
        }
      }  
      pp = pp->next; // On, on, and on to the next one  
      
    } // end while
  } // end if user matches
  return isallowed;

}


int checkaccess(const char* authdb, const int bufsize,
        const char* user, const char* operation, const char* path) {
  
  FILE *fp = fopen(authdb, "r");
  if (fp == NULL) {
    errno = 2;
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
      break;     
    }
    
    isallowed = checkallowed(user, operation, path, rec);
  
  }
  fclose(fp);
  return isallowed;
  
}