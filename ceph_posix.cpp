/******************************************************************************
 * posix layer around the CEPH radosstriper interface
 *
 * @author Sebastien Ponce, sebastien.ponce@cern.ch
 * @author Ian Johnson, ian.johnson@stfc.ac.uk
 *****************************************************************************/

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <radosstriper/libradosstriper.hpp>
#include <map>
#include <stdexcept>
#include <string>
#include <sstream>
#include <sys/xattr.h>
#include <time.h>
#include <limits>
#include <ceph_posix.h>

#define  CA_MAXCKSUMLEN 32
#define  CA_MAXCKSUMNAMELEN 15

#define LOWLEVELTRACE
std::string saved_ceph_userId; // should this be static?
//std::string saved_ceph_pool;

const char *getdebug() {
    char *debug = getenv("DEBUG");
    if (NULL == debug  || "" == debug) {
        debug = (char *)"0";
    }
    return debug;
}
/// small structs to store file metadata
struct CephFile {
  std::string name;
  std::string pool;
  std::string userId;
  unsigned int nbStripes;
  unsigned long long stripeUnit;
  unsigned long long objectSize;
};

struct CephFileRef : CephFile {
  int flags;
  mode_t mode;
  unsigned long long offset;
};


/// global variables holding stripers and ioCtxs for each ceph pool plus the cluster object
std::map<std::string, libradosstriper::RadosStriper*> g_radosStripers;
std::map<std::string, librados::IoCtx*> g_ioCtx;
librados::Rados* g_cluster = 0;
/// global variable holding a map of file descriptor to file reference
std::map<unsigned int, CephFileRef> g_fds;
/// global variable holding a list of files currently opened for write
std::multiset<std::string> g_filesOpenForWrite;
/// global variable remembering the next available file descriptor
unsigned int g_nextCephFd = 0;
/// global variable containing defaults for CephFiles
CephFile g_defaultParams = { "",
                             "default",        // default pool
                             "xrootd",          // default user
                             1,                // default nbStripes
                             4 * 1024 * 1024,  // default stripeUnit : 4 MB
                             4 * 1024 * 1024}; // default objectSize : 4 MB

//std::string g_defaultUserId = "xrootd";
//std::string g_defaultPool = "default";

/// global variable for the log function
static void (*g_logfunc) (char *, va_list argp) = 0;

static void logwrapper(char* format, ...) {
  if (0 == g_logfunc) return;
  va_list arg;
  va_start(arg, format);
  (*g_logfunc)(format, arg);
  va_end(arg);
}

/// simple integer parsing, to be replaced by std::stoll when C++11 can be used
static unsigned long long int stoull(const std::string &s) {
  char* end;
  errno = 0;
  unsigned long long int res = strtoull(s.c_str(), &end, 10);
  if (0 != *end) {
    throw std::invalid_argument(s);
  }
  if (ERANGE == errno) {
    throw std::out_of_range(s);
  }
  return res;
}

/// simple integer parsing, to be replaced by std::stoi when C++11 can be used
static unsigned int stoui(const std::string &s) {
  char* end;
  errno = 0;
  unsigned long int res = strtoul(s.c_str(), &end, 10);
  if (0 != *end) {
    throw std::invalid_argument(s);
  }
  if (ERANGE == errno || res > std::numeric_limits<unsigned int>::max()) {
    throw std::out_of_range(s);
  }
  return (unsigned int)res;
}

/// fills the userId of a ceph file struct from the userId from the grid-mapfile
/// returns position of first character after the userId
static int getCephUserId(const std::string &params) {
    
  if (!strcmp(getdebug(), "9")) {
    logwrapper((char*)"%s : params = %s\n", __FUNCTION__, params.c_str());
  }   

  size_t atPos = params.find('@');
 
  if (std::string::npos != atPos) {  
    return atPos+1;
  } else {
    return 0;
  }
}

/// fills the pool of a ceph file struct from a string
/// returns position of first character after the pool
static int getCephPool(const std::string &params, unsigned int offset, std::string &pool) {
    
  if (!strcmp(getdebug(), "9")) {
    logwrapper((char*)"%s: params='%s', using %s\n", __FUNCTION__,
          params.c_str(), params.substr(offset).c_str());  // This duplicates info from stat() in the calling code)
    }
  // default
  // parsing
  size_t comPos = params.find(',', offset);
  if (std::string::npos == comPos) {      
    if (params.size() != offset) {
      int   colonPos = params.find(':');
      pool = params.substr(offset, colonPos-offset);
      if (!strcmp(getdebug(), "9")) {
        logwrapper((char*)"%s : No comma, pool = %s, returning %d\n",  
                __FUNCTION__, pool.c_str(), params.size()); 
      }      
    }
    return params.size();
  } else {
    pool = params.substr(offset, comPos-offset);


    if (!strcmp(getdebug(), "9")) {
      logwrapper((char*)"%s : Found comma, pool = %s, return %d\n",  
              __FUNCTION__, pool.c_str(), comPos+1);  
    }    
    return comPos+1;
  }
}

/// fills the nbStriped of a ceph file struct from a string
/// returns position of first character after the nbStripes
// this may raise std::invalid_argument and std::out_of_range
static int getCephNbStripes(const std::string &params, unsigned int offset, unsigned int* nbStripes) {
    if (!strcmp(getdebug(), "9")) {
      logwrapper((char*)"%s : params = '%s', params.size() = %d, offset = %d\n", 
              __FUNCTION__,  params.c_str(), params.size(), offset);
    }      
  // default
  // parsing
  size_t comPos = params.find(',', offset);
  if (std::string::npos == comPos) {   
    if (params.size() != offset) {
      if (!strcmp(getdebug(), "9")) {
        logwrapper((char*)"%s : params.size() != offset\n", __FUNCTION__);
      }     
         
      size_t colonPos = params.find(':');
      std::string remainder = params.substr(offset, colonPos-offset);
         
      if (remainder.size() > 0) {
      
        if (!strcmp(getdebug(), "9")) {
          logwrapper((char*)"%s : remainder = %s\n", __FUNCTION__, remainder.c_str());
         }       
        
        *nbStripes = stoui(params.substr(offset));
        if (!strcmp(getdebug(), "9")) {
          logwrapper((char*)"%s : setting nbStripes to %d\n", __FUNCTION__, *nbStripes);
        }
      }
    } else {
      *nbStripes = g_defaultParams.nbStripes;
      if (!strcmp(getdebug(), "9")) {
        logwrapper((char*)"%s : setting nbStripes to default, = %d\n", __FUNCTION__, *nbStripes);
      }      
      return params.size();
    }
  } else {
    *nbStripes = stoui(params.substr(offset, comPos-offset));
    if (!strcmp(getdebug(), "9")) {
      logwrapper((char*)"%s : nbStripes = %d\n", __FUNCTION__,  *nbStripes);
    }    
    return comPos+1;
  }
}

/// fills the stripeUnit of a ceph file struct from a string
/// returns position of first character after the stripeUnit
// this may raise std::invalid_argument and std::out_of_range
static int getCephStripeUnit(const std::string &params, unsigned int offset, unsigned long long* stripeUnit) {
    
  if (!strcmp("9", getdebug())) {
    logwrapper((char*)"%s : params+offset = '%s'\n", __FUNCTION__, params.substr(offset).c_str());
  }    
  // default
  // parsing
  size_t comPos = params.find(',', offset);
  if (std::string::npos == comPos) {
    if (params.size() != offset) {
      *stripeUnit = stoull(params.substr(offset));
        if (!strcmp(getdebug(), "9")) {
          logwrapper((char*)"%s : params.size() != offset, stripeUnit = %d\n", __FUNCTION__, *stripeUnit);
        }
    } else {
      *stripeUnit = g_defaultParams.stripeUnit;
      
      if (!strcmp("9", getdebug())) {
        logwrapper((char*)"%s : stripeUnit = %u, returning %d\n",
              __FUNCTION__, *stripeUnit, params.size());
      }      
    }
    return params.size();
  } else {
    std::string stripeUnitStr = params.substr(offset, comPos-offset);
    if (!strcmp("9", getdebug())) {
      logwrapper((char*)"%s : stripeUnit to convert = %s, offset = %d\n", __FUNCTION__, stripeUnitStr.c_str());
    }     
    *stripeUnit = stoull(stripeUnitStr); // /* params.substr(offset, comPos-offset) */);
    if (!strcmp("9", getdebug())) {
      logwrapper((char*)"%s : stripeUnit = %u, returning %d\n",
              __FUNCTION__, *stripeUnit, comPos+1);
    }
    return comPos+1;
  }
}

/// fills the objectSize of a ceph file struct from a string
/// returns position of first character after the objectSize
// this may raise std::invalid_argument and std::out_of_range
static void getCephObjectSize(const std::string &params, unsigned int offset, unsigned long long *objectSize) {
    
  if (!strcmp("9", getdebug())) {
    logwrapper((char*)"%s : params = '%s', using '%s', params.size() - %d, offset = %d\n", 
            __FUNCTION__, params.c_str(), params.substr(offset).c_str(),
            params.size(), offset);
  }   
    // default
  // parsing
  if (params.size() != offset) {
    size_t colonPos = params.find(':', offset);
      
    if (std::string::npos == colonPos) {
      if (!strcmp("9", getdebug())) {
        logwrapper((char*)"%s : No colon found\n", __FUNCTION__);
      } 
      *objectSize = stoull(params.substr(offset));
    } else {
      std::string objectSizeStr = params.substr(offset, colonPos-offset);
      if (!strcmp("9", getdebug())) {
        logwrapper((char*)"%s : String objectSize = %s\n", __FUNCTION__, objectSizeStr.c_str());
      }
      *objectSize = stoull(objectSizeStr);
    }
    if (!strcmp("9", getdebug())) {
      logwrapper((char*)"%s : objectSize = %d\n", __FUNCTION__, *objectSize);
    }   
  } else {
    *objectSize = g_defaultParams.objectSize;
  }
  if (!strcmp("9", getdebug())) {
    logwrapper((char*)"%s : objectSize = %d\n", __FUNCTION__, *objectSize);
  }  
}



/// fills the userId of a ceph file struct from a string
/// returns position of first character after the userId
static int fillCephUserId(const std::string &params, CephFile &file) {
    
  if (!strcmp(getdebug(), "9")) {
    logwrapper((char*)"%s : params = %s\n", __FUNCTION__, params.c_str());
  }   
  // default
  file.userId = g_defaultParams.userId;
  // parsing
  size_t atPos = params.find('@');
  if (std::string::npos != atPos) {
    file.userId = params.substr(0, atPos);
    
    if (!strcmp(getdebug(), "1")) {
      logwrapper((char*)"%s : userId = %s\n", __FUNCTION__, file.userId.c_str());
    }   
    return atPos+1;
  } else {
    return 0;
  }
}

/// fills the pool of a ceph file struct from a string
/// returns position of first character after the pool
static int fillCephPool(const std::string &params, unsigned int offset, CephFile &file) {
    
  if (!strcmp(getdebug(), "9")) {
    logwrapper((char*)"%s: params='%s', using %s\n", __FUNCTION__,
          params.c_str(), params.substr(offset).c_str());  // This duplicates info from stat() in the calling code)
    }
  // default
  file.pool = g_defaultParams.pool;
  // parsing
  size_t comPos = params.find(',', offset);
  if (std::string::npos == comPos) {      
    if (params.size() != offset) {
      int   colonPos = params.find(':');
      file.pool = params.substr(offset, colonPos-offset);
      if (!strcmp(getdebug(), "9")) {
        logwrapper((char*)"%s : No comma, pool = %s, returning %d\n",  
                __FUNCTION__, file.pool.c_str(), params.size()); 
      }      
    }
    return params.size();
  } else {
    std::string pool = params.substr(offset, comPos-offset);

    file.pool = pool;
    if (!strcmp(getdebug(), "9")) {
      logwrapper((char*)"%s : Found comma, pool = %s, return %d\n",  
              __FUNCTION__, file.pool.c_str(), comPos+1);  
    }    
    return comPos+1;
  }
}

/// fills the nbStriped of a ceph file struct from a string
/// returns position of first character after the nbStripes
// this may raise std::invalid_argument and std::out_of_range
static int fillCephNbStripes(const std::string &params, unsigned int offset, CephFile &file) {
    if (!strcmp(getdebug(), "9")) {
      logwrapper((char*)"%s : params = '%s', params.size() = %d, offset = %d\n", 
              __FUNCTION__,  params.c_str(), params.size(), offset);
    }      
  // default
  file.nbStripes = g_defaultParams.nbStripes;
  // parsing
  size_t comPos = params.find(',', offset);
  if (std::string::npos == comPos) {
    
    if (params.size() != offset) {
      if (!strcmp(getdebug(), "9")) {
        logwrapper((char*)"%s : params.size() != offset\n", __FUNCTION__);
      }     
         
      size_t colonPos = params.find(':');
      std::string remainder = params.substr(offset, colonPos-offset);
         
      if (remainder.size() > 0) {
      
        if (!strcmp(getdebug(), "9")) {
          logwrapper((char*)"%s : remainder = %s\n", __FUNCTION__, remainder.c_str());
        }       
        
        file.nbStripes = stoui(params.substr(offset));
        if (!strcmp(getdebug(), "9")) {
          logwrapper((char*)"%s : nbStripes = %d\n", __FUNCTION__,  file.nbStripes);
        }
      }
    }
    
     
    return params.size();
  } else {
    file.nbStripes = stoui(params.substr(offset, comPos-offset));
    if (!strcmp(getdebug(), "9")) {
      logwrapper((char*)"%s : nbStripes = %d\n", __FUNCTION__,  file.nbStripes);
    }    
    return comPos+1;
  }
}

/// fills the stripeUnit of a ceph file struct from a string
/// returns position of first character after the stripeUnit
// this may raise std::invalid_argument and std::out_of_range
static int fillCephStripeUnit(const std::string &params, unsigned int offset, CephFile &file) {
    if (!strcmp("9", getdebug())) {
      logwrapper((char*)"%s : params+offset = '%s'\n", __FUNCTION__, params.substr(offset).c_str());
    }    
  // default
  file.stripeUnit = g_defaultParams.stripeUnit;
  // parsing
  size_t comPos = params.find(',', offset);
  if (std::string::npos == comPos) {
    if (params.size() != offset) {
      file.stripeUnit = stoull(params.substr(offset));
        if (!strcmp(getdebug(), "9")) {
          logwrapper((char*)"%s : params.size() != offset, stripeUnit = %d\n", __FUNCTION__, file.stripeUnit);
        }
    }
    return params.size();
  } else {
    std::string stripeUnit = params.substr(offset, comPos-offset);
    if (!strcmp("9", getdebug())) {
      logwrapper((char*)"%s : stripeUnit to convert = %s, offset = %d\n", __FUNCTION__, stripeUnit.c_str());
    }     
    file.stripeUnit = stoull(stripeUnit /* params.substr(offset, comPos-offset) */);
    if (!strcmp("9", getdebug())) {
      logwrapper((char*)"%s : stripeUnit = %u, returning %d\n",
              __FUNCTION__, file.stripeUnit, comPos+1);
    }
    return comPos+1;
  }
}

/// fills the objectSize of a ceph file struct from a string
/// returns position of first character after the objectSize
// this may raise std::invalid_argument and std::out_of_range
static void fillCephObjectSize(const std::string &params, unsigned int offset, CephFile &file) {
    if (!strcmp("9", getdebug())) {
      logwrapper((char*)"%s : params = '%s', using '%s', params.size = %d, offset = %d\n", __FUNCTION__, params.c_str(), 
              params.substr(offset).c_str(), params.size(), offset);
    }   
    // default
  file.objectSize = g_defaultParams.objectSize;
  // parsing
  if (params.size() != offset) {
    size_t colonPos = params.find(':', offset);
      
    if (std::string::npos == colonPos) {
      if (!strcmp("9", getdebug())) {
        logwrapper((char*)"%s : No colon found\n", __FUNCTION__);
      } 
      file.objectSize = stoull(params.substr(offset));
    } else {
        std::string objectSize = params.substr(offset, colonPos-offset);
      if (!strcmp("9", getdebug())) {
        logwrapper((char*)"%s : String objectSize = %s\n", __FUNCTION__, objectSize.c_str());
      }
      file.objectSize = stoull(objectSize.c_str());
    }
    if (!strcmp("9", getdebug())) {
      logwrapper((char*)"%s : objectSize = %d\n", __FUNCTION__, file.objectSize);
    }   
  }
}

/// fill the parameters of a ceph file struct (all but name) from a string
/// see fillCephFile for the detailed syntax
void fillCephFileParams(const std::string &params, CephFile &file) {    
  // parse the params one by one
    
//  std::string pool;
//  unsigned int nbStripes;
//  unsigned long long stripeUnit, objectSize;
  
  unsigned int afterUser = getCephUserId(params); // We don't assign userId from params
  unsigned int afterPool = getCephPool(params, afterUser, file.pool); 
  unsigned int afterNbStripes = getCephNbStripes(params, afterPool, &file.nbStripes);
  unsigned int afterStripeUnit = getCephStripeUnit(params, afterNbStripes, &file.stripeUnit);
  getCephObjectSize(params, afterStripeUnit, &file.objectSize);
    
  if (file.pool.empty()) { // E.g. Calls from FTS after initial MLST will generally not
                      // not provide the pool name, so we need to pick up the pool
                      // from the value we stored before
    if (!strcmp("1", getdebug())) {      
      logwrapper((char*)"%s : Ceph pool is empty - OK for 'MKD /'\n", 
            __FUNCTION__);  
    }
  } 

  file.userId.assign(saved_ceph_userId);
  
//
//  file.pool = pool;
//  file.nbStripes = nbStripes;
//  file.stripeUnit = stripeUnit;
//  file.objectSize = objectSize;
 
  if (!strcmp("1", getdebug())) {
    logwrapper((char*)"%s : saved_userID = %s, user= %s, pool= %s, nbStripes= %d, stripeUnit= %d, objectSize= %d\n", 
            __FUNCTION__, 
            saved_ceph_userId.c_str(), file.userId.c_str(), file.pool.c_str(), file.nbStripes, file.stripeUnit, file.objectSize);
  }   
  
}


/// fill the parameters of a ceph file struct (all but name) from a string
/// see fillCephFile for the detailed syntax
//void old_fillCephFileParams(const std::string &params, CephFile &file) {    
//  // parse the params one by one
//  unsigned int afterUser = fillCephUserId(params, file);
//  unsigned int afterPool = fillCephPool(params, afterUser, file);
//  unsigned int afterNbStripes = fillCephNbStripes(params, afterPool, file);
//  unsigned int afterStripeUnit = fillCephStripeUnit(params, afterNbStripes, file);
//  fillCephObjectSize(params, afterStripeUnit, file);     
//}

/// sets the default userId, pool and file layout
/// syntax is [user@]pool[,nbStripes[,stripeUnit[,objectSize]]]
/// may throw std::invalid_argument or std::out_of_range in case of error
//void ceph_posix_set_defaults(const char* value) {
//  if (!strcmp("1", getdebug())) {
//    logwrapper((char*)"%s : value = %s\n", __FUNCTION__, value);
//  }
//  if (value) {
//    CephFile newdefault;
//    fillCephFileParams(value, newdefault);
//    g_defaultParams = newdefault;
//  }
//}

/// fill a ceph file struct from a path
void fillCephFile(const char *path, CephFile &file) {
       
  if (!strcmp("9", getdebug())) {
    logwrapper((char*) "\n\n%s : path is '%s'\n", __FUNCTION__, path);
  }
  // Syntax of the given path is :
  //   [/]pool[,nbStripes[,stripeUnit[,objectSize]]]:]<object name>
  // for the missing parts, defaults are applied. These defaults are
  // initially set to 'admin', 'default', 1, 4MB and 4MB
  // but can be changed via a call to ceph_posix_set_defaults
  std::string spath = path;
  size_t colonPos = spath.find(':');
  if (std::string::npos == colonPos) {   // No colon?
    file.name = spath;
    if (!strcmp("1", getdebug())) {
      logwrapper((char*) "\n%s : about to call fillCephFileParams with empty string\n", __FUNCTION__);
    }   
    fillCephFileParams("", file);
  } else {
      
    if (0 == spath.find('/')) {
        spath = spath.substr(1); // Remove slash before username in params
//    }
//    if (!strcmp("1", getdebug())) {
//      logwrapper((char*) "\n%s : path is now '%s'\n", __FUNCTION__, spath.c_str());
    }
    if (!strcmp("1", getdebug())) {
     logwrapper((char*) "\n\n%s : path is '%s'\n", __FUNCTION__, path);
    }   
    colonPos = spath.find(':'); // Argh! When the leading slash isn't present, colonPos is off by one!
    file.name = spath.substr(colonPos+1); 
    
    if (!strcmp("1", getdebug())) {
      logwrapper((char*) "\n\t%s : file.name = '%s'\n", "fillCephFile", file.name.c_str());

    }
    std::string nparams = spath.substr(0, colonPos);
    if (!strcmp("1", getdebug())) {
      logwrapper((char*) "\n%s : about to call fillCephFileParams with '%s'\n", __FUNCTION__, nparams.c_str());
    } 
    fillCephFileParams(nparams, file); // Don't pass the separating colon
  }
}

static CephFile getCephFile(const char *path) {     
  CephFile file;   
  fillCephFile(path, file);
  return file;
}

static CephFileRef getCephFileRef(const char *path, int flags,mode_t mode,unsigned long long offset) {
  CephFileRef fr;
  fillCephFile(path, fr);
  fr.flags = flags;
  fr.mode = mode;
  fr.offset = 0;
  return fr;
}
/*
 * Get the parameters. Inject the userId here.
 *
 */
std::string getUserAtPool(const CephFile& file){
    
  std::stringstream ss;
  
  ss << file.userId << '@' << file.pool << ',' << file.nbStripes << ','
     << file.stripeUnit << ',' << file.objectSize;
    
  return ss.str();
}
static libradosstriper::RadosStriper* getRadosStriper(const CephFile& file) {

  std::string userAtPool = getUserAtPool(file);
  
  if (!strcmp("1", getdebug())) {
    logwrapper((char*) "%s : userId = %s, pool = %s, name = %s\n",
    __FUNCTION__, file.userId.c_str(), file.pool.c_str(), file.name.c_str());
        logwrapper((char*) "\n%s : userAtPool = %s\n", __FUNCTION__, userAtPool.c_str());
  }  
  
  std::map<std::string, libradosstriper::RadosStriper*>::iterator it =
    g_radosStripers.find(userAtPool);
  if (!strcmp("9", getdebug())) {  
    logwrapper((char*) "\n%s : back from radosStripers.find\n", __FUNCTION__);
  }
  if (it == g_radosStripers.end()) {
    if (!strcmp("9", getdebug())) {  
      logwrapper((char*) "\n%s : need to create a new radosStriper.\n", __FUNCTION__);
    }      
    // we need to create a new radosStriper
    // Do we already have a cluster
    if (0 == g_cluster) {
      // create connection to cluster
      g_cluster = new librados::Rados;
      if (!strcmp("9", getdebug())) {  
        logwrapper((char*) "\n%s : back from creating librados::Rados\n", __FUNCTION__);
      }      
      if (0 == g_cluster) {
        if ( !strcmp("9", getdebug()) ) {
          logwrapper((char*)"%s : cluster from new librados::Rados = 0\n", __FUNCTION__);
        }
        return 0;
      } else {
        if (!strcmp("9", getdebug())) {  
          logwrapper((char*) "\n%s : g_cluster is non-zero\n", __FUNCTION__);
        }
      }
      if ( !strcmp("9", getdebug()) ) {
        logwrapper((char*)"%s : About to g_cluster->init\n", __FUNCTION__);
      }      
      int rc = g_cluster->init(file.userId.c_str());
      if (rc) {
        if ( !strcmp("1", getdebug()) ) {
          logwrapper((char*)"%s : cannot g_cluster->init('%s')\n", __FUNCTION__, file.userId.c_str());
        }
        delete g_cluster;
        g_cluster = 0;
        return 0;
      }
      rc = g_cluster->conf_read_file(NULL);
      if (rc) {
        if ( !strcmp("1", getdebug()) ) {
          logwrapper((char*)"%s : cannot cluster->conf_read_file(NULL)\n", __FUNCTION__);
        }
        g_cluster->shutdown();
        delete g_cluster;
        g_cluster = 0;
        return 0;
      }
      g_cluster->conf_parse_env(NULL);
      rc = g_cluster->connect();
      if (rc) {
        if ( !strcmp("1", getdebug()) ) {
          logwrapper((char*)"%s : cannot g_cluster->connect() - rc = %d\n", __FUNCTION__, rc);
        }
        g_cluster->shutdown();
        delete g_cluster;
        g_cluster = 0;
        return 0;
      }
    }
    // create IoCtx for our pool
    librados::IoCtx *ioctx = new librados::IoCtx;
    if (0 == ioctx) {
      if ( !strcmp("1", getdebug()) ) {
        logwrapper((char*)"%s : ioCtx from new is NULL\n", __FUNCTION__);
      }
      g_cluster->shutdown();
      delete g_cluster;
      return 0;
    }
    int rc = g_cluster->ioctx_create(file.pool.c_str(), *ioctx);
    if (rc != 0) {
      if ( !strcmp("1", getdebug()) ) {
        logwrapper((char*)"%s : cannot ioctcx_create(%s)\n", __FUNCTION__, file.pool.c_str());
      }
      g_cluster->shutdown();
      delete g_cluster;
      g_cluster = 0;
      delete ioctx;
      return 0;
    }
    // create RadosStriper connection
    libradosstriper::RadosStriper *striper = new libradosstriper::RadosStriper;
    if (0 == striper) {
      if ( !strcmp("1", getdebug()) ) {
        logwrapper((char*)"%s : cannot create new RadosStriper\n", __FUNCTION__);
      }
      delete ioctx;
      g_cluster->shutdown();
      delete g_cluster;
      g_cluster = 0;
      return 0;
    }
    rc = libradosstriper::RadosStriper::striper_create(*ioctx, striper);
    if (rc != 0) {
      if ( !strcmp("1", getdebug()) ) {
        logwrapper((char*)"%s : cannot RadosStriper::striper_create\n", __FUNCTION__);
      }
      delete striper;
      delete ioctx;
      g_cluster->shutdown();
      delete g_cluster;
      g_cluster = 0;
      return 0;
    }
    // setup layout
    rc = striper->set_object_layout_stripe_count(file.nbStripes);
    if (rc != 0) {
      logwrapper((char*)"getRadosStriper : invalid nbStripes %d\n", file.nbStripes);
      delete striper;
      delete ioctx;
      g_cluster->shutdown();
      delete g_cluster;
      g_cluster = 0;
      return 0;
    }
    rc = striper->set_object_layout_stripe_unit(file.stripeUnit);
    if (rc != 0) {
      logwrapper((char*)"getRadosStriper : invalid stripeUnit %d (must be non0, multiple of 64K)\n", file.stripeUnit);
      delete striper;
      delete ioctx;
      g_cluster->shutdown();
      delete g_cluster;
      g_cluster = 0;
      return 0;
    }
    rc = striper->set_object_layout_object_size(file.objectSize);
    if (rc != 0) {
      logwrapper((char*)"getRadosStriper : invalid objectSize %d (must be non 0, multiple of stripe_unit)\n", file.objectSize);
      delete striper;
      delete ioctx;
      g_cluster->shutdown();
      delete g_cluster;
      g_cluster = 0;
      return 0;
    }
    g_ioCtx.insert(std::pair<std::string, librados::IoCtx*>(userAtPool, ioctx));    
    it = g_radosStripers.insert(std::pair<std::string, libradosstriper::RadosStriper*>
                                (userAtPool, striper)).first;
  } else {
    if (!strcmp("9", getdebug())) {  
      logwrapper((char*) "\n%s : Not at end of g_stripers, already have a radosStriper.\n", __FUNCTION__);
    }    
  }
  if (!strcmp("0", getdebug())) {  
    logwrapper((char*) "\n%s : returning a radosStriper for %s.\n", __FUNCTION__, it->first.c_str());
  }  
  return it->second;
}

static librados::IoCtx* getIoCtx(const CephFile& file) {
  libradosstriper::RadosStriper *striper = getRadosStriper(file);
  if (0 == striper) {
    return 0;
  }
  return g_ioCtx[file.pool];
}

void ceph_posix_disconnect_all() {
  for (std::map<std::string, libradosstriper::RadosStriper*>::iterator it =
         g_radosStripers.begin();
       it != g_radosStripers.end();
       it++) {
    delete it->second;
  }
  g_radosStripers.clear();
  for (std::map<std::string, librados::IoCtx*>::iterator it = g_ioCtx.begin();
       it != g_ioCtx.end();
       it++) {
    delete it->second;
  }
  g_ioCtx.clear();
  delete g_cluster;
}

  
extern "C" {
    
    void ceph_posix_set_username(const char* username) {
    
      if (!strcmp(getdebug(), "9")) {
        logwrapper((char*) "%s : %s\n", __FUNCTION__, username);
      }
      saved_ceph_userId.assign(username);
    }
    
int ceph_posix_delete(const char *pathname) {
    errno = 0;
    if (!strcmp(getdebug(), "1")) {
      logwrapper((char*) "%s : %s\n", __FUNCTION__, pathname);
    }
    CephFileRef fr = getCephFileRef(pathname, 0, (mode_t) 0, 0); // flags, mode, 0);
    libradosstriper::RadosStriper *striper = getRadosStriper(fr);
    if (NULL == striper) {
      logwrapper((char*) "%s : Can't get striper\n", __FUNCTION__);
      errno = ENOENT;
      return -ENOENT;
    }
    if (!strcmp(getdebug(), "9")) {
      logwrapper((char*) "%s : fr.name = %s\n", __FUNCTION__, fr.name.c_str());
    }
    int rc = striper->remove(fr.name);
    if (rc != 0) {
      logwrapper((char*) "%s : Can't delete %s, rc = %d\n", __FUNCTION__, fr.name.c_str(), rc);
      //errno = ENOENT;
      return rc;
    } else {
      logwrapper((char*) "%s : delete OK for %s\n", __FUNCTION__, fr.name.c_str(), rc);

    }
    return rc;
  }
        


  void ceph_posix_set_logfunc(void (*logfunc) (char *, va_list argp)) {
    g_logfunc = logfunc;
  };

  int ceph_posix_open(const char *pathname, int flags, mode_t mode) {
    logwrapper((char*)"ceph_posix_open : fd %d associated to %s\n", g_nextCephFd, pathname);
    CephFileRef fr = getCephFileRef(pathname, flags, mode, 0);
    g_fds[g_nextCephFd] = fr;
    g_nextCephFd++;
    if (flags & O_WRONLY) {
      g_filesOpenForWrite.insert(fr.name);
    }
    return g_nextCephFd-1;
  }

  int ceph_posix_close(int fd) {
    std::map<unsigned int, CephFileRef>::iterator it = g_fds.find(fd);
    if (it != g_fds.end()) {
      logwrapper((char*)"ceph_close: closed fd %d\n", fd);
      if (it->second.flags & O_WRONLY) {
        g_filesOpenForWrite.erase(g_filesOpenForWrite.find(it->second.name));
      }
      g_fds.erase(it);
      return 0;
    } else {
      return -EBADF;
    }
  }

  static off64_t lseek_compute_offset(CephFileRef &fr, off64_t offset, int whence) {
    switch (whence) {
    case SEEK_SET:
      fr.offset = offset;
      break;
    case SEEK_CUR:
      fr.offset += offset;
      break;
    default:
      return -EINVAL;
    }
    return fr.offset;
  }

  off64_t ceph_posix_lseek64(int fd, off64_t offset, int whence) {
    std::map<unsigned int, CephFileRef>::iterator it = g_fds.find(fd);
    if (it != g_fds.end()) {
      CephFileRef &fr = it->second;
#ifdef VERYLOWLEVELTRACE     
      logwrapper((char*)"ceph_lseek64: for fd %d, offset=%lld, whence=%d\n", fd, offset, whence);
#endif
      return lseek_compute_offset(fr, offset, whence);
    } else {
      return -EBADF;
    }
  }
#define TRACE_WRITES
  ssize_t ceph_posix_write(int fd, const void *buf, size_t count) {
#ifdef TRACE_WRITES
    static int blocksize_reported = 0;
#endif    
    std::map<unsigned int, CephFileRef>::iterator it = g_fds.find(fd);
    if (it != g_fds.end()) {
      CephFileRef &fr = it->second;
#ifdef WIBBLERS      
      logwrapper((char*)"%s: for fd %d, count=%d\n", __FUNCTION__, fd, count);
#endif
      if ((fr.flags & O_WRONLY) == 0) {
        return -EBADF;
      }
      libradosstriper::RadosStriper *striper = getRadosStriper(fr);
      if (0 == striper) {
        return -EINVAL;
      }
      ceph::bufferlist bl;
      bl.append((const char*)buf, count);      
      int rc = striper->write(fr.name, bl, count, fr.offset);
#ifdef TRACE_WRITES    
      if (!blocksize_reported) {
        logwrapper((char*)"%s : \n\t\t\tstriper->write(%s:%s, %d, offset= %lld) = %d\n",
              __FUNCTION__, fr.pool.c_str(), fr.name.c_str(), count, fr.offset, rc);
        blocksize_reported = 1;       
      }
#endif      
      if (rc != 0) 
          return rc;
      fr.offset += count;
      return count;
    } else {
      return -EBADF;
    }
  }

  ssize_t ceph_posix_read(int fd, void *buf, size_t count) {
    std::map<unsigned int, CephFileRef>::iterator it = g_fds.find(fd);
    static int reported_size = 0;
    
    if (it != g_fds.end()) {
      CephFileRef &fr = it->second;
#ifdef LOWLEVELTRACE  
      if (reported_size == 0) {
        logwrapper((char*)"%s: for fd %d, count=%d\n", __FUNCTION__, fd, count);
        reported_size = 1;
      }
#endif      
      if ((fr.flags & O_WRONLY) != 0) {
        return -EBADF;
      }
      libradosstriper::RadosStriper *striper = getRadosStriper(fr);
      if (0 == striper) {
        return -EINVAL;
      }
      ceph::bufferlist bl;
      int rc = striper->read(fr.name, &bl, count, fr.offset);
      if (rc < 0) return rc;
      bl.copy(0, rc, (char*)buf);
      fr.offset += rc;
      return rc;
    } else {
      return -EBADF;
    }
  }

  
  
  int ceph_posix_stat64(const char *pathname, struct stat64 *buf) {
      
    logwrapper((char*)"ceph_posix_stat64 : pathname = %s\n", pathname);  // This duplicates info from stat() in the calling code)
    // minimal stat : only size and times are filled
    // atime, mtime and ctime are set all to the same value
    // mode is set arbitrarily to 0666
//    char *inpath = strdup(pathname);
    CephFile cephFile = getCephFile(pathname);
        
    (void)cephFile.name.c_str();
    
    libradosstriper::RadosStriper *striper = getRadosStriper(cephFile);    
    if (0 == striper) {    
      errno = ENOENT;
      return -errno;
    }
    memset(buf, 0, sizeof(*buf));
            
//    int rc = searching_stat64(striper, &wanted, buf);
    

    int rc = striper->stat(cephFile.name.c_str(), 
            (uint64_t*)&(buf->st_size), &(buf->st_atime));
        
    if (rc != 0) {
      
      logwrapper((char*)"%s : striper->stat returned %d for '%s'%s\n", __FUNCTION__, 
              rc, cephFile.pool.c_str(), cephFile.name.c_str());

      // for non existing file. Check that we did not open it for write recently
      // in that case, we return 0 size and current time
      if (-ENOENT == rc) {
        if ( g_filesOpenForWrite.find(pathname) != g_filesOpenForWrite.end()) { // Need pathname as it includes pool
          logwrapper((char*)"%s : Found file %s in g_filesOpenForWrite\n", __FUNCTION__, pathname);
          buf->st_size = 0;
          buf->st_atime = time(NULL);
          return rc; // Otherwise, we fall out, set the buf-> members, and return 0
        } else {
          logwrapper((char*)"%s : File %s doesn't exist and isn't in g_filesOpenForWrite\n", 
                  __FUNCTION__, pathname);
          errno = -rc; // because striper->stat is negative for errors
          return rc;
        }
      } else { // Some other error which (not ENOENT)
          logwrapper((char*)"%s : return code from striper->stat = %d\n", 
          __FUNCTION__, rc);
          errno = -rc; // because striper->stat is negative for errors
          return rc;
        
      }
    }
     

    logwrapper((char*)"%s : Found file %s OK\n", __FUNCTION__, cephFile.name.c_str());

    buf->st_mtime = buf->st_atime;
    buf->st_ctime = buf->st_atime;  
    buf->st_mode = 0666;
          
    return 0;
    
  }

  static ssize_t ceph_posix_internal_getxattr(const CephFile &file, const char* name,
                                              void* value, size_t size) {
    libradosstriper::RadosStriper *striper = getRadosStriper(file);
    if (0 == striper) {
      return -EINVAL;
    }
    ceph::bufferlist bl;
    int rc = striper->getxattr(file.name, name, bl);
    if (rc < 0) {
      return rc;
    }
    bl.copy(0, rc, (char*)value);
    return rc;
  }

  char *ceph_posix_get_checksum(const char* pathname) {

    char *checksum = NULL;
    int fd = ceph_posix_open(pathname, O_RDONLY, 0);
    char ckSumbufdisk[CA_MAXCKSUMLEN + 1];
    int xattr_len;
    /*
    char ckSumnamedisk[CA_MAXCKSUMNAMELEN + 1];
    xattr_len = ceph_posix_fgetxattr(fd, "user.checksum.type", ckSumnamedisk, CA_MAXCKSUMNAMELEN);
    if (xattr_len >= 0) { get user.checksum.value }
     *
     */
    xattr_len = ceph_posix_fgetxattr(fd, "user.checksum.value", ckSumbufdisk, CA_MAXCKSUMLEN);
    
    if (xattr_len >= 0) {
      ckSumbufdisk[xattr_len] = '\0';
      checksum = strdup(ckSumbufdisk);
    }
    ceph_posix_close(fd);
    return checksum;
    
  }
  
  ssize_t ceph_posix_fgetxattr(int fd, const char* name,
                               void* value, size_t size) {
    std::map<unsigned int, CephFileRef>::iterator it = g_fds.find(fd);
    if (it != g_fds.end()) {
      CephFileRef &fr = it->second;
      if (!strcmp(getdebug(), "9")) {
        logwrapper((char*)"%s: fd %d, attribute name=%s\n", __FUNCTION__, fd, name);
      }
      return ceph_posix_internal_getxattr(fr, name, value, size);
    } else {
      return -EBADF;
    }
  }

  static ssize_t ceph_posix_internal_setxattr(const CephFile &file, const char* name,
                                              const void* value, size_t size, int flags) {
    libradosstriper::RadosStriper *striper = getRadosStriper(file);
    if (0 == striper) {
      return -EINVAL;
    }
    ceph::bufferlist bl;
    bl.append((const char*)value, size);
    int rc = striper->setxattr(file.name, name, bl);
    if (rc) {
      return -rc;
    }
    return 0;
  }

  int ceph_posix_fsetxattr(int fd,
                           const char* name, const void* value,
                           size_t size, int flags)  {
    std::map<unsigned int, CephFileRef>::iterator it = g_fds.find(fd);
    if (it != g_fds.end()) {
      CephFileRef &fr = it->second;
      logwrapper((char*)"ceph_fsetxattr: fd %d name=%s value=%s\n", fd, name, value);
      return ceph_posix_internal_setxattr(fr, name, value, size, flags);
    } else {
      return -EBADF;
    }
  }

} // extern "C"
