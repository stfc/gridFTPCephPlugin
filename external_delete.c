#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

//#include <rados/librados.h>

#include <wait.h>

//#ifdef EXTERNAL_DELETE_MAIN
//extern char** splitInTwo(const char* input, const char* sep);

char** splitInTwo(const char *input, const char* sep) {
  char* copy = strdup(input);
  char** elts = (char**) malloc(2 * sizeof (char *));

  elts[0] = strsep(&copy, sep);
  elts[1] = strsep(&copy, sep);
  free(copy);
  return elts;
}

//#endif 

#include "external_delete.h"

  int external_delete(const char* deleteprog, const char* conf, const char* pathname) {
  
  int status = -1;
  pid_t pid;
  
  char** poolAndObject = splitInTwo(pathname, ":");
  
//  fprintf(stdout, "pool=%s, objname=%s\n", poolAndObject[0], poolAndObject[1]);
  
  switch (pid = fork()) {
    
    case -1:
      break;
      
    case 0:
      /*
       * We don't want any output from the execl'ed program, so close stdout and stderr fds
       */
      
      close(1); close(2);

      char** poolAndObject = splitInTwo(pathname, ":");
      execl(deleteprog, deleteprog, conf, poolAndObject[0], poolAndObject[1], NULL);
      _exit(EXIT_FAILURE);
      
    default: 
      
//      fprintf(stdout, "prog=%s, conf=%s, pathname=%s.\n", deleteprog, conf, pathname);
      if (waitpid(pid, &status, 0) == pid && WIFEXITED(status)) {
        status = WEXITSTATUS(status);
      } 
        
  }
  return status;  // Map 0 from process to 1 for C TRUE
}

#ifdef EXTERNAL_DELETE_MAIN
int main(int argc, char **argv) {
  
  char* deleteprog;
  char* conf;
  char* pathname;
//  char* oid;
//  char* chunksize;
  
  
  if (argc != 4) {
    
    fprintf(stderr, "Usage: external_delete deletionscript conf pathname\n"); //  chunksize\n");                                                    
    exit(-1);

  }
  
  deleteprog = argv[1];
  conf = argv[2];
  
  pathname = argv[3];
  
//  pool = argv[3];
//  oid = argv[4];
//  chunksize = argv[5];
  
  exit(external_delete(deleteprog, conf, pathname /* oid  , chunksize */));
  
}
#endif