/******************************************************************************
 * A thin layer around the XRootD XrdAcc Authorization framework
 * 
 * @author Ian Johnson, ian.johnson@stfc.ac.uk
 *****************************************************************************/


#include "XrdVersion.hh"

#include <XrdSec/XrdSecEntity.hh>

#include "XrdAcc/XrdAccAuthorize.hh"

#include "XrdSys/XrdSysHeaders.hh"
#include "XrdSys/XrdSysLogger.hh"

#include "gftp_authz.h"

#include <string.h>

std::string saved_authz_userId; // should this be static?


/// global variable for the log function
static void (*g_logfunc) (char *, va_list argp) = 0;

static void logwrapper(char* format, ...) {
  if (0 == g_logfunc) return;
  va_list arg;
  va_start(arg, format);
  (*g_logfunc)(format, arg);
  va_end(arg);
}

void gftp_authz_set_logfunc(void (*logfunc) (char *, va_list argp)) {
  g_logfunc = logfunc;
};

  
/******************************************************************************/
/*                       O p e r a t i o n   T a b l e                        */

/******************************************************************************/
typedef struct {
  const char *opname;
  Access_Operation oper;
} optab_t;
optab_t optab[] ={
  {"?", AOP_Any},
  {"cm", AOP_Chmod},
  {"co", AOP_Chown},
  {"cr", AOP_Create},
  {"rm", AOP_Delete},
  {"lk", AOP_Lock},
  {"mk", AOP_Mkdir},
  {"mv", AOP_Rename},
  {"rd", AOP_Read},
  {"ls", AOP_Readdir},
  {"st", AOP_Stat},
  {"wr", AOP_Update}};

int opcnt = sizeof (optab) / sizeof (optab[0]);

/******************************************************************************/
/*                                c m d 2 o p                                 */

/******************************************************************************/

int cmd2op(const char *opname) {
  int retval = -1;
  for (int i = 0; i < opcnt; i++) {
    
    if (!strcmp(opname, optab[i].opname)) {
      retval = optab[i].oper;
    }
    
  }
  cerr << "testaccess: Invalid operation - " << opname << endl;
  //   exit(1);
  return retval;
}





extern char* getdebug();






extern "C" {
  
    void gftp_authz_set_username(const char* username) {
    
      if (!strcmp(getdebug(), "9")) {
        logwrapper((char*) "%s : %s\n", __FUNCTION__, username);
      }
      saved_authz_userId.assign(username);
    }
  int gftp_authz_allow(const char* username, const char* path, const char* operation) {

  
    
XrdSecEntity Entity("");

XrdAccAuthorize *Authorize;

XrdSysLogger myLogger;
XrdSysError eroute(&myLogger, "ceph_authz_");

  logwrapper((char*)"%s : params = %s, %s, %s\n", __FUNCTION__, username, path, operation);

    int retval = 0;
    


    /*
     * Register the version number
     */

    static XrdVERSIONINFODEF(myVer, XrdAccTest, XrdVNUMBER, XrdVERSION);
    extern XrdAccAuthorize * XrdAccDefaultAuthorizeObject(XrdSysLogger *lp,
            const char *cfn,
            const char *parm,
            XrdVersionInfo & myVer);

   
    /*
     * Create the XrdSecEntity object with the given user principal and a placeolder for host 
     * We don't use host principals
     */

#define PROT "krb4"
    
    strncpy(Entity.prot, PROT, strlen(PROT));   // prot is a char[], host and name are char*]
    Entity.host = (char *)"nohost";    
    Entity.name = (char *)username;

    
    logwrapper((char*)"%s : Entity.name = %s\n", __FUNCTION__, Entity.name);

//    return 1;
    
    //
    // Don't need to specify a config file
    // XrdServer library AuthDB file defaults to /opt/xrd/etc/Authfile
    //

    const char *emptyFilename = "/opt/xrd/etc/empty.cf";

    /*
     * Create the authZ object 
     */
    logwrapper((char*)"%s : About to create XrdAccDefaulatAuthorizeObject\n", __FUNCTION__);

    if (!(Authorize = XrdAccDefaultAuthorizeObject(&myLogger, emptyFilename, 0, myVer))) {
//      cerr << "acc authz_init: Initialization failed." << endl;
      return 0;
    } else {
//      retval = 1;
    }

 
    int optype = cmd2op(operation);

    if (optype != -1) {
    logwrapper((char*)"%s : About to call Authorize->Access\n", __FUNCTION__);

      XrdAccPrivs auth = Authorize->Access(
              (const XrdSecEntity *) &Entity, (const char *) path, (Access_Operation)optype);
      retval = auth;

    }

    return retval;

  }


} // extern "C"

