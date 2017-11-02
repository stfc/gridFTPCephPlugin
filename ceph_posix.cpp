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


// Reserve space for the new XrdCks binary format
#define  CA_MAXCKSUMLEN 128
#define  CA_MAXCKSUMNAMELEN 15

#include <limits.h>
#include <sys/param.h>

#include "external_delete.h"

#include <xrootd/XrdCks/XrdCksAssist.hh>

#define LOWLEVELTRACE


/// global variable for the log function
static void (*g_logfunc) (char *, va_list argp) = 0;

static void logwrapper(char* format, ...) {
  if (0 == g_logfunc) return;
  va_list arg;
  va_start(arg, format);
  (*g_logfunc)(format, arg);
  va_end(arg);
}

const char *getdebug() {
    char *debug = getenv("DEBUG");
    if (NULL == debug  || "" == debug) {
        debug = (char *)"0";
    }
    return debug;
}
/// small structs to store file metadata
struct CephFile {
  std::string objectname;
  std::string pool;
  std::string radosUserId;
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
CephFile g_defaultParams = { "",                // object name
                             "",                // default pool
                             "",                // default user
                             1,                 // default nbStripes
                             4 * 1024 * 1024,  // default stripeUnit : 4 MB
                             4 * 1024 * 1024}; // default objectSize : 4 MB

std::string radosUserId;



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





/// fill the parameters of a ceph file struct (all but name) from a string
/// see fillCephFile for the detailed syntax
void fillCephFileParams(const std::string &params, CephFile &file) {    
  // parse the params one by one
    
  
//  logwrapper((char*)"%s: params = %s.\n", __FUNCTION__, params.c_str());
  
  file.pool = params;
  
  int numStripes;
  char *numStripesStr = getenv("STRIPER_NUM_STRIPES");
  if (numStripesStr == NULL) {
    numStripes = g_defaultParams.nbStripes;
  } else {
    numStripes = atoi(numStripesStr);  // Could use stoui from this file...
  }
  
  int stripeUnit;
  char *stripeUnitStr = getenv("STRIPER_STRIPE_UNIT");
  if (stripeUnitStr == NULL) {
    stripeUnit = g_defaultParams.stripeUnit;
  } else {
    stripeUnit = atoi(stripeUnitStr);
  }
  
  int objectSize;
  char *objectSizeStr = getenv("STRIPER_OBJECT_SIZE");
  if (objectSizeStr == NULL) {
    objectSize = g_defaultParams.objectSize;
  } else {
    objectSize = atoi(objectSizeStr);
  }

  file.nbStripes = numStripes;
  file.stripeUnit = stripeUnit;
  file.objectSize = objectSize;
  file.radosUserId.assign(radosUserId);
 
  if (!strcmp("1", getdebug())) {
    logwrapper((char*)"%s : radosUserID = %s, pool = %s, name = %s, nbStripes = %d, stripeUnit = %d, objectSize = %d\n", 
            __FUNCTION__, 
            file.radosUserId.c_str(), file.pool.c_str(), file.objectname.c_str(), file.nbStripes, file.stripeUnit, file.objectSize);
  }   
  
}


///// fill a ceph file struct from a path
void fillCephFile(const char *path, CephFile &file) {
       
  if (!strcmp("9", getdebug())) {
    logwrapper((char*) "%s : path is '%s'\n", __FUNCTION__, path);
  }
  // Syntax of the given path is :
  //   [/]pool@[,nbStripes[,stripeUnit[,objectSize]]]:]<object name>
  // for the missing parts, defaults are applied. These defaults are
  // initially set to 'admin', 'default', 1, 4MB and 4MB
  // but can be changed via a call to ceph_posix_set_defaults
  std::string spath = path;
  
  const char* keepSlash = getenv("GRIDFTP_CEPH_KEEP_SLASH");
  if (keepSlash == NULL) { // If not set, remove keeping slash
    spath = spath.substr(1);
  }
  size_t colonPos = spath.find(':');
  if (std::string::npos == colonPos) {   // No colon?
    file.objectname = spath;
    if (!strcmp("1", getdebug())) {
      logwrapper((char*) "%s : about to call fillCephFileParams with empty string\n", __FUNCTION__);
    }   
    fillCephFileParams("", file);
    
  } else {
      
    if (!strcmp("9", getdebug())) {
     logwrapper((char*) "%s : path was '%s', using spath = '%s'\n", __FUNCTION__, path, spath.c_str());
    }   
    colonPos = spath.find(':'); // Argh! When the leading slash isn't present, colonPos is off by one!
    file.objectname = spath.substr(colonPos+1); 
    
    if (!strcmp("9", getdebug())) {
      logwrapper((char*) "\n\t%s : file.name = '%s'\n", "fillCephFile", file.objectname.c_str());

    }
    std::string nparams = spath.substr(0, colonPos);
    if (!strcmp("9", getdebug())) {
      logwrapper((char*) "%s : about to call fillCephFileParams with '%s'\n", __FUNCTION__, nparams.c_str());
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
  
  ss << file.radosUserId << '@' << file.pool << ',' << file.nbStripes << ','
     << file.stripeUnit << ',' << file.objectSize;
    
  return ss.str();
}
static libradosstriper::RadosStriper* getRadosStriper(const CephFile& file) {
  
  static int parameters_reported = 0;

  std::string userAtPool = getUserAtPool(file);

  if (!strcmp("1", getdebug())) {

    if (!parameters_reported++) {
      logwrapper((char*) "%s : userId = %s, pool = %s, name = %s\n",
              __FUNCTION__, file.radosUserId.c_str(), file.pool.c_str(), file.objectname.c_str());
      logwrapper((char*) "%s : userAtPool = %s\n", __FUNCTION__, userAtPool.c_str());

    }
  }  
  
  std::map<std::string, libradosstriper::RadosStriper*>::iterator it =
    g_radosStripers.find(userAtPool);
  if (!strcmp("9", getdebug())) {  
    logwrapper((char*) "%s : back from radosStripers.find\n", __FUNCTION__);
  }
  if (it == g_radosStripers.end()) {
    if (!strcmp("9", getdebug())) {  
      logwrapper((char*) "%s : need to create a new radosStriper.\n", __FUNCTION__);
    }      
    // we need to create a new radosStriper
    // Do we already have a cluster
    if (0 == g_cluster) {
      // create connection to cluster
      g_cluster = new librados::Rados;
      if (!strcmp("9", getdebug())) {  
        logwrapper((char*) "%s : back from creating librados::Rados\n", __FUNCTION__);
      }      
      if (0 == g_cluster) {
        if ( !strcmp("9", getdebug()) ) {
          logwrapper((char*) "%s : cluster from new librados::Rados = 0\n", __FUNCTION__);
        }
        return 0;
      } else {
        if (!strcmp("9", getdebug())) {  
          logwrapper((char*) "%s : g_cluster is non-zero\n", __FUNCTION__);
        }
      }
      if ( !strcmp("9", getdebug()) ) {
        logwrapper((char*) "%s : About to g_cluster->init\n", __FUNCTION__);
      }      
      int rc = g_cluster->init(file.radosUserId.c_str());
      if (rc) {
        if ( !strcmp("1", getdebug()) ) {
          logwrapper((char*) "%s : cannot g_cluster->init('%s')\n", __FUNCTION__, file.radosUserId.c_str());
        }
        delete g_cluster;
        g_cluster = 0;
        return 0;
      }
      rc = g_cluster->conf_read_file(NULL);
      if (rc) {
        if ( !strcmp("1", getdebug()) ) {
          logwrapper((char*) "%s : cannot cluster->conf_read_file(NULL)\n", __FUNCTION__);
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
      logwrapper((char*) "%s : Not at end of g_stripers, already have a radosStriper.\n", __FUNCTION__);
    }    
  }
  if (!strcmp("0", getdebug())) {  
    logwrapper((char*) "%s : returning a radosStriper for %s.\n", __FUNCTION__, it->first.c_str());
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
    
    void ceph_posix_set_radosUserId(const char* radosUser) {
    
      if (!strcmp(getdebug(), "1")) {
        logwrapper((char*) "%s : %s\n", __FUNCTION__, radosUser);
      }
      radosUserId.assign(radosUser);
    }

    int ceph_posix_delete(const char *pathname) {
        errno = 0;
        if (!strcmp(getdebug(), "1")) {
            logwrapper((char*) "%s : %s\n", __FUNCTION__, pathname);
        }
        CephFileRef fr = getCephFileRef(pathname, 0, (mode_t) 0, 0); // flags, mode, 0);
        if (!strcmp(getdebug(), "1")) {
            logwrapper((char*) "%s : About to call getRadosStriper\n", __FUNCTION__, pathname);
        }
        libradosstriper::RadosStriper *striper = getRadosStriper(fr);
        if (NULL == striper) {
            logwrapper((char*) "%s : Can't get striper\n", __FUNCTION__);
            errno = ENOENT;
            return -ENOENT;
        }
        if (!strcmp(getdebug(), "9")) {
            logwrapper((char*) "%s : fr.name = %s\n", __FUNCTION__, fr.objectname.c_str());
        }

        alarm(60); // Increased from 10s because deletion can take around 20s, let's be a bit generous
        int rc = striper->remove(fr.objectname);
        alarm(0);

        if (rc != 0) {
            logwrapper((char*) "%s : Can't striper->remove %s, rc = %d\n", __FUNCTION__, fr.objectname.c_str(), rc);
            if (rc == -EBUSY) {
                                
                std::string pathname = fr.pool + ":" + fr.objectname;
                logwrapper((char*) "%s: About to external_delete %s.\n", __FUNCTION__, pathname.c_str());
                int rc2;                 
                rc2 = external_delete("/usr/bin/forcedelete.py", "/etc/ceph/ceph.conf", pathname.c_str());
                logwrapper((char*) "%s: Return from external_delete = %d.\n", __FUNCTION__, rc2);
                
                rc = rc2;
            }
            return rc;
        } else {
            logwrapper((char*) "%s : delete OK for %s\n", __FUNCTION__, fr.objectname.c_str(), rc);

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
      g_filesOpenForWrite.insert(fr.objectname);
    }
    return g_nextCephFd-1;
  }
  
  int ceph_posix_close(int fd) {
    std::map<unsigned int, CephFileRef>::iterator it = g_fds.find(fd);
    if (it != g_fds.end()) {
      logwrapper((char*)"ceph_close: closed fd %d\n", fd);
      if (it->second.flags & O_WRONLY) {
        g_filesOpenForWrite.erase(g_filesOpenForWrite.find(it->second.objectname));
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
//#define VERYLOWLEVELTRACE
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
    static int last_byte_count = -1;
#endif    
    std::map<unsigned int, CephFileRef>::iterator it = g_fds.find(fd);
    if (it != g_fds.end()) {
      CephFileRef &fr = it->second;

      if ((fr.flags & O_WRONLY) == 0) {
        return -EBADF;
      }
      libradosstriper::RadosStriper *striper = getRadosStriper(fr);
      if (0 == striper) {
        return -EINVAL;
      }
      ceph::bufferlist bl;
      bl.append((const char*)buf, count);      
      
      alarm(30);
      int rc = striper->write(fr.objectname, bl, count, fr.offset);
      alarm(0);
      
#ifdef TRACE_WRITES    

      if (count != last_byte_count) {

        logwrapper((char*) "%s: for fd %d, count=%d\n", __FUNCTION__, fd, count);
        last_byte_count = count;

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
    
    static ceph::bufferlist bl;
    
    std::map<unsigned int, CephFileRef>::iterator it = g_fds.find(fd);
    static int reported_size = 0;
    
    if (it != g_fds.end()) {
      CephFileRef &fr = it->second;
#ifdef LOWLEVELTRACE  
      if (!reported_size++) {
        logwrapper((char*)"%s: for fd %d, count=%d\n", __FUNCTION__, fd, count);
      }
#endif      
      if ((fr.flags & O_WRONLY) != 0) {
        return -EBADF;
      }
      libradosstriper::RadosStriper *striper = getRadosStriper(fr);
      if (0 == striper) {
        return -EINVAL;
      }
      //ceph::bufferlist bl;
      int rc = striper->read(fr.objectname, &bl, count, fr.offset);
      if (rc < 0) return rc;
      bl.copy(0, rc, (char*)buf);
      bl.clear();
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
        

    libradosstriper::RadosStriper *striper = getRadosStriper(cephFile);    
    if (0 == striper) {    
      errno = ENOENT;
      return -errno;
    }
    memset(buf, 0, sizeof(*buf));
                
    logwrapper((char*)"%s : about to striper->stat %s\n", __FUNCTION__, cephFile.objectname.c_str());
    
    alarm(10);   
    int rc = striper->stat(cephFile.objectname.c_str(), 
            (uint64_t*)&(buf->st_size), &(buf->st_atime));
    alarm(0);
           
    if (rc != 0) {
      
      logwrapper((char*)"%s : striper->stat returned %d for '%s'%s\n", __FUNCTION__, 
              rc, cephFile.pool.c_str(), cephFile.objectname.c_str());

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
     

    logwrapper((char*)"%s : Found file %s OK\n", __FUNCTION__, cephFile.objectname.c_str());

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
    int rc = striper->getxattr(file.objectname, name, bl);
    if (rc < 0) {
      return rc;
    }
    bl.copy(0, rc, (char*)value);
    return rc;
    }

  int ceph_posix_set_old_format_checksum(const int fd, const char* ckSumbuf) {

    int rc = -1;
    const char* ckSumalg = "adler32";

    if (ceph_posix_fsetxattr(fd, "user.checksum.type", ckSumalg, strlen(ckSumalg), 0) == 0 &&
      ceph_posix_fsetxattr(fd, "user.checksum.value", ckSumbuf, strlen(ckSumbuf), 0) == 0) {

      rc = 0;
    }
    return rc;
  }
  
  int ceph_posix_set_new_format_checksum_fd(const int fd, const char* cstype, const char* ckSumbuf) {
      
      int rc = -1;
      
      std::vector<char> attrData = XrdCksAttrData(cstype, ckSumbuf, time(0));
  
      rc = ceph_posix_fsetxattr(fd, XrdCksAttrName(cstype).c_str(), 
        attrData.data(), attrData.size(), 0); 
  
      return rc;
  }

  char* ceph_posix_get_new_format_checksum(const char* pathname) {

    char *checksum = NULL;
    const int fd = ceph_posix_open(pathname, O_RDONLY, 0);

    if (fd >= 0) {

      checksum = ceph_posix_get_new_format_checksum_fd(fd);
      ceph_posix_close(fd);

    }

    return checksum;

  }
  
/*
 * TO-DO: Pass desired checksum name as a parameter
 */
  
  char *ceph_posix_get_new_format_checksum_fd(const int fd) {

    char *checksum = NULL;

    char ckSumbufdisk[CA_MAXCKSUMLEN + 1];
    int xattr_len;

    std::string attrName = XrdCksAttrName("adler32");

    xattr_len = ceph_posix_fgetxattr(fd, attrName.c_str(), ckSumbufdisk, CA_MAXCKSUMLEN);

    if (xattr_len > 0) {

      std::string csVal = XrdCksAttrValue("adler32", ckSumbufdisk, xattr_len);
      checksum = strdup(csVal.c_str());

    } 

    return checksum;
  }
    
    
   char* ceph_posix_get_old_format_checksum(const char* pathname) {
      
        char *checksum = NULL;
        const int fd = ceph_posix_open(pathname, O_RDONLY, 0);

        if (fd >= 0) {

          checksum = ceph_posix_get_old_format_checksum_fd(fd);
          ceph_posix_close(fd);
        
        }
         
        return checksum;         
  } 
   
   
  char *ceph_posix_get_old_format_checksum_fd(const int fd) {

    char *checksum = NULL;
    char ckSumbufdisk[CA_MAXCKSUMLEN + 1];
    int xattr_len;

    /*
     * Try to get the old, GridFTP format checksum 
     */

    xattr_len = ceph_posix_fgetxattr(fd, "user.checksum.value", ckSumbufdisk, CA_MAXCKSUMLEN);

    if (xattr_len > 0) {
      ckSumbufdisk[xattr_len] = '\0'; // Make sure to zap string after desired content
      checksum = strdup(ckSumbufdisk);
    }

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
    int rc = striper->setxattr(file.objectname, name, bl);
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
      return ceph_posix_internal_setxattr(fr, name, value, size, flags);
    } else {
      return -EBADF;
    }
  }

} // extern "C"
