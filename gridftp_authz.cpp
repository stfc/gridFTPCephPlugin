#include <cstdlib>
#include <list>
#include <iostream>     // std::cerr
#include <fstream>      // std::ifstream
#include <ctype.h>
#include <string.h>
#include <exception>

using namespace std;

typedef struct pathAndPrivilege {
  std::string* path;
  std::string* priv;

} pathAndPrivilege_t, *pathAndPrivilege_p;

typedef struct authdbentry {
  std::string* user;
  std::list<pathAndPrivilege_p> pp;

} authdbentry_t, *authdbentry_p;

std::list<pathAndPrivilege_p>& getPathsAndPrivs(const char* delim) throw (exception) {

  std::list<pathAndPrivilege_p> *pAndPlist = new std::list<pathAndPrivilege_p>;

  do {

    const char* path = strtok(NULL, delim);
    const char* priv = strtok(NULL, delim);

    if (path == NULL || priv == NULL) { // No more tokens (path/priv pairs)

      break; // Stop looking for path/priv pairs...

    } else {

      pathAndPrivilege_p pAndPListItem = new pathAndPrivilege;

      pAndPListItem->path = new std::string(path);
      pAndPListItem->priv = new std::string(priv);

      pAndPlist->push_back(pAndPListItem);

    }

  } while (1);

  return *pAndPlist;

}

authdbentry_p tokenize(std::string line) throw (exception) {

  authdbentry_p rec = new authdbentry;

  const char* delim = " \t";
  char*cline = (char*) line.c_str();

  (void) strtok(cline, delim); // Throw away the first token, the idtype 'u'  

  const char* user = strtok(NULL, delim);

  if (user == NULL) {
    free(rec);
    throw "Can't find user with strtok()";
  } else {
    rec->user = new std::string(user);
  }

  std::list<pathAndPrivilege_p> theList;
  try {
    theList = getPathsAndPrivs(delim);
  } catch (exception& e) {
    throw "Can't get list of paths and privileges";
  }

  rec->pp = theList;
  return rec;

}

void printAuthdbEntry(std::ostream& out, authdbentry_p authdbline) {

  out << " User: " << *(authdbline->user) << "\t";
  std::list<pathAndPrivilege_p> theList = authdbline->pp;
  for (std::list<pathAndPrivilege_p>::iterator list_iter = theList.begin();
          list_iter != theList.end();
          list_iter++) {
    out << *((*list_iter)->path) << '\t' << *((*list_iter)->priv) << '\t';
  }

  out << endl;

}

int checkListItem(const char* operation, const char* path, std::list<pathAndPrivilege_p>::iterator list_iter) {

  int isAllowed = 0;
  const char* candidatePath = ((*list_iter)->path)->c_str();
  const char* candidatePriv = ((*list_iter)->priv)->c_str();
        
  if (strstr(path, candidatePath) == path) { // Test that request path starts with path from AuthDB 

#define READ(operation) !strcmp("rd", operation)
#define ALLACCESS(priv) !strcmp("a", priv)

    isAllowed = READ(operation) or ALLACCESS(candidatePriv);
  }

  return isAllowed;

}

int checkAllowed(const char* operation, const char* path, std::list<pathAndPrivilege_p> pp) {

  int isAllowed = 0;

  for (std::list<pathAndPrivilege_p>::iterator
    list_iter = pp.begin();
    list_iter != pp.end();
    list_iter++) {

    if (isAllowed = checkListItem(operation, path, list_iter)) {
      break;
    }

  }

  return isAllowed;

}

extern "C" {

  int checkAccess(const char* authdbfilename, const char* user, const char* operation, const char* path) {

    ifstream authdbfile(authdbfilename);

    if (!authdbfile.is_open()) {
      return 0;
    }

    int isAllowed = 0;

    try {
      
      std::string line;

      while (getline(authdbfile, line) && !isAllowed) {

#define IGNORE(str) (str[0] == '#' or str[0] == '\0' or isspace(str[0]))

        if (IGNORE(line)) {
          continue;
        } else {

          authdbentry * authdbline = tokenize(line);

          if (!authdbline->user->compare(user)) { // User in AuthDB matches user in request
            isAllowed = checkAllowed(operation, path, authdbline->pp);
          }

        }
      } // while

    } catch (exception& e) { // Could log the error message from the exception here

    }

    authdbfile.close();
    return isAllowed;

  }

}