/******************************************************************************
 * GridFTP plugin for access to ceph object store
 *
 * @author Sebastien Ponce, sebastien.ponce@cern.ch
 *****************************************************************************/
#if defined(linux)
#define _LARGE_FILES
#define __USE_LARGEFILE64
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#endif

#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <zlib.h>
#include <sys/xattr.h>
#include <limits.h>
#include <stdlib.h>

#include "globus_gridftp_server.h"

#include "dsi_ceph.h"
#include "ceph_posix.h"

#include "gridftp_checkaccess.h"

#include "assert.h"

// Adler32 checksum length is 8 characters
#define  CA_MAXCKSUMLEN 8
#define  CA_MAXCKSUMNAMELEN 15

char* authdbFilename;
char* authdbProg;

char* pathname;


#define ERRORMSGSIZE 256 
char errorstr[ERRORMSGSIZE];

static
globus_version_t local_version = {
  0, /* major version number */
  1, /* minor version number */
  1157544130,
  0 /* branch ID */
};

void _GlobusGFSErrorGeneric(const char* reason) {
  GlobusGFSErrorGeneric(reason);
}
  
char *cleanup_pathname(char *instr) {
  
  char *out;
  
  if (instr[0] == '/') {  // Zap a leading forward slash
    instr++;
  }
  
  if (strchr(instr, '/') == NULL) { // If no other slashes, add one at end
    out = (char *)malloc(strlen(instr) + 2);
    strcpy(out, instr);
    strcat(out, "/");
  } else {
    out = (char *)malloc(strlen(instr)+1);
    strcpy(out, instr);
  }
  
  return out;
}

static char* VO_Role;
/*
 * Utility function to get an integer value from the environment
 */
static int getconfigint(const char *key) {
    
  char *intStr = getenv(key);
  if (NULL == intStr) {
     globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,"%s: Invalid integer value '%s'\n",
          "getconfigint", key); 
  }
  return NULL == intStr ? 0 : atoi(intStr);

}
/*
 *  utility function to make errors
 */

static globus_result_t globus_l_gfs_make_error(const char *msg) {
  char *err_str;
  globus_result_t result;
  GlobusGFSName(globus_l_gfs_make_error);
  err_str = globus_common_create_string("%s error: %s", msg,  strerror(errno));
  result = GlobusGFSErrorGeneric(err_str);
  globus_free(err_str);
  return result;
}

/* fill the statbuf into globus_gfs_stat_t */
static void fill_stat_array(globus_gfs_stat_t * filestat, struct stat64 statbuf, char *name) {
  filestat->mode = statbuf.st_mode;;
  filestat->nlink = statbuf.st_nlink;
  filestat->uid = statbuf.st_uid;
  filestat->gid = statbuf.st_gid;
  filestat->size = statbuf.st_size;

  filestat->mtime = statbuf.st_mtime;
  filestat->atime = statbuf.st_atime;
  filestat->ctime = statbuf.st_ctime;

  filestat->dev = statbuf.st_dev;
  filestat->ino = statbuf.st_ino;
  filestat->name = strdup(name);
}
/* free memory in stat_array from globus_gfs_stat_t->name */
static void free_stat_array(globus_gfs_stat_t * filestat,int count) {
  int i;
  for(i=0;i<count;i++) free(filestat[i].name);
}

/* free memory for the checksum list */
static void free_checksum_list(checksum_block_list_t *checksum_list) {
  checksum_block_list_t *checksum_list_p;
  checksum_block_list_t *checksum_list_pp;
  checksum_list_p=checksum_list;
  while(checksum_list_p->next!=NULL){
    checksum_list_pp=checksum_list_p->next;
    globus_free(checksum_list_p);
    checksum_list_p=checksum_list_pp;
  }
  globus_free(checksum_list_p);
}

// comparison of 2 checksum_block_list_t* on their offset for the use of qsort
static int offsetComparison(const void *first, const void *second) {
  checksum_block_list_t** f = (checksum_block_list_t**)first;
  checksum_block_list_t** s = (checksum_block_list_t**)second;
  long long int diff = (*f)->offset - (*s)->offset;
  // Note that we cannot simply return diff as this function should return
  // an int and the cast for values not fitting in 32 bits may screw things
  if (0 == diff) return 0;
  if (diff > 0) return 1;
  return -1;
}

/* a replacement for zlib adler32_combine for SLC4  */
#define BASE 65521UL    /* largest prime smaller than 65536 */
#define MOD(a) a %= BASE

static unsigned long adler32_combine_(unsigned int adler1,
                                       unsigned int adler2,
                                       globus_off_t len2) {
  unsigned int sum1;
  unsigned int sum2;
  unsigned int rem;
  /* the derivation of this formula is left as an exercise for the reader */
  rem = (unsigned int)(len2 % BASE);
  sum1 = adler1 & 0xffff;
  sum2 = rem * sum1;
  MOD(sum2);
  sum1 += (adler2 & 0xffff) + BASE - 1;
  sum2 += ((adler1 >> 16) & 0xffff) + ((adler2 >> 16) & 0xffff) + BASE - rem;
  if (sum1 >= BASE) sum1 -= BASE;
  if (sum1 >= BASE) sum1 -= BASE;
  if (sum2 >= (BASE << 1)) sum2 -= (BASE << 1);
  if (sum2 >= BASE) sum2 -= BASE;
  return sum1 | (sum2 << 16);
}

static unsigned long adler32_0chunks(unsigned int len) {
  return ((len%BASE) << 16) | 1;
}


static void ceph_logfunc_wrapper (char *format, va_list argp) {
  // do the printing ourselves as we cannot call the variadic globus_gfs_log_message
  int size = 1024;
  char* logstr = (char*)malloc(size);
  int written = vsnprintf(logstr, size, format, argp);
  while (written >= size) {
    size *=2;
    logstr = (char*)realloc(logstr, size);
    written = vsnprintf(logstr, size, format, argp);
  }
  // call log func with a single argument
  (*globus_gfs_log_message)(GLOBUS_GFS_LOG_DUMP, "%s", logstr);
  free(logstr);
}

/* a function to wrap all is needed to close a file */
static void globus_ceph_close(const char* func,
                              globus_l_gfs_ceph_handle_t* ceph_handle,
                              const char* error_msg) {
  char* errorBuf = NULL;
  ceph_handle->done = GLOBUS_TRUE;
  ceph_posix_close(ceph_handle->fd);
  if (error_msg) {
    ceph_handle->cached_res = globus_l_gfs_make_error(error_msg);
    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "ERROR %s: terminating transfer on error: %s\n", func, error_msg);
    errorBuf = strdup(error_msg);
  }
  else {
    ceph_handle->cached_res = GLOBUS_SUCCESS;
  }
}

int checkFileExists(const char* filename) {

  struct stat64 statbuf;

  return !stat64(filename, &statbuf);

}

char* checkFileFromConf(const char* confKey, const char* defaultVal) {
 
  char* returnVal = NULL;
  char *testVal;

  const char* confVal = getenv(confKey);
  if (confVal == NULL) {
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
      "INFO %s: Cannot find configuration - check setting of %s in /etc/gridftp.conf\n",
      __FUNCTION__, confKey);

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
      "INFO %s: Setting file location to default, %s\n",
      __FUNCTION__, defaultVal);
    testVal = (char *)defaultVal;

  } else {
    testVal = (char *)confVal;
  }
  
  if (!checkFileExists(testVal)) {
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
      "INFO %s: Problem accessing file %s: %s\n", __FUNCTION__, testVal, strerror(errno));
    
  }  else {
    returnVal = strdup(testVal);
  }
  
  return returnVal;
  
}

void set_finished_info(
  globus_gfs_finished_info_t* finished_info,
  globus_gfs_session_info_t *session_info,
  globus_l_gfs_ceph_handle_t* ceph_handle,
  globus_result_t result) {

  memset(finished_info, '\0', sizeof (globus_gfs_finished_info_t));
  finished_info->type = GLOBUS_GFS_OP_SESSION_START; // Always this value
  finished_info->result = result;
  finished_info->info.session.session_arg = ceph_handle;
  finished_info->info.session.username = session_info->username;
  finished_info->info.session.home_dir = NULL; /* if null we will go to HOME directory */

}

static assembly_t *create_assembly_buffer(
  globus_off_t *buffer_start,
  int buffer_start_val,
  globus_off_t *buffer_end,
  int buffer_end_val,
  int rebuff_size,
  int start_offset) {
    
  assembly_t * assembly_buff = (assembly_t *)malloc(sizeof(assembly_t));
  
  *buffer_start = buffer_start_val; //* ceph_handle->overflow_start */ = rebuff_size;
  *buffer_end = buffer_end_val; // ceph_handle->overflow_end = start_offset /* ceph_handle->overflow_start */ + rebuff_size-1;
  
  assembly_buff->buffer = (globus_byte_t *)malloc(rebuff_size * sizeof(globus_byte_t)); 
  assembly_buff->nbytes = 0;

  
  return assembly_buff; //  ceph_handle->overflow_buff =  obuff;
    
    
}

/*************************************************************************
 *  start
 *  -----
 *  This function is called when a new session is initialized, ie a user
 *  connectes to the server.  This hook gives the dsi an opportunity to
 *  set internal state that will be threaded through to all other
 *  function calls associated with this session.  And an oppertunity to
 *  reject the user.
 *
 *  finished_info.info.session.session_arg should be set to an DSI
 *  defined data structure.  This pointer will be passed as the void *
 *  user_arg parameter to all other interface functions.
 *
 *  NOTE: at nice wrapper function should exist that hides the details
 *        of the finished_info structure, but it currently does not.
 *        The DSI developer should jsut follow this template for now
 ************************************************************************/
static void globus_l_gfs_ceph_start(globus_gfs_operation_t op, globus_gfs_session_info_t *session_info) {
  
  globus_l_gfs_ceph_handle_t *ceph_handle;
  globus_gfs_finished_info_t finished_info;
  char *func = "globus_l_gfs_ceph_start";

  GlobusGFSName(globus_l_gfs_ceph_start);
  ceph_handle = (globus_l_gfs_ceph_handle_t *)globus_malloc(sizeof (globus_l_gfs_ceph_handle_t));
  globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "%s: started, uid: %u, gid: %u\n",
    func, getuid(), getgid());
  globus_mutex_init(&ceph_handle->mutex, NULL);

  globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "INFO %s: host_id = %s, mapped rolename = %s\n",
    func, session_info->host_id, session_info->username);
    
  authdbProg = checkFileFromConf("GRIDFTP_CEPH_AUTHDB_PROG", "/usr/bin/xrdacctest");
 
  if (authdbProg == NULL) {
    set_finished_info(&finished_info, session_info, ceph_handle, GLOBUS_FAILURE);
    globus_gridftp_server_operation_finished(op, GLOBUS_FAILURE, &finished_info);

    return;
  } 
  
  authdbFilename = checkFileFromConf("GRIDFTP_CEPH_AUTHDB_FILE", "/etc/grid-security/authdb");

  if (authdbFilename == NULL) {
    set_finished_info(&finished_info, session_info, ceph_handle, GLOBUS_FAILURE);
    globus_gridftp_server_operation_finished(op, GLOBUS_FAILURE, &finished_info);

    return;
  } else {
    
      globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "%s: GRIDFTP_CEPH_AUTHDB_FILE = %s\n",
      func, authdbFilename);
    
  }

  const char* radosUserKey = "GRIDFTP_CEPH_RADOS_USER";
  const char* radosUserId = getenv(radosUserKey);
  
  if (radosUserId == NULL) {

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
      "INFO %s: Cannot find configuration - check setting of %s in /etc/gridftp.conf\n",
      __FUNCTION__, radosUserKey);

    globus_gridftp_server_operation_finished(op, GLOBUS_FAILURE, &finished_info);

    return; 

  } else {
    
      globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "%s: RADOS USER ID = %s\n",
      func, radosUserId);    
    
  }
  
  ceph_posix_set_radosUserId(radosUserId);
 

  globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "INFO %s: session_info->username = %s\n",
      func, session_info->username); 

  
  VO_Role = strdup(session_info->username);

  globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "%s: VO_Role = %s\n",
      func, VO_Role); 
  
  set_finished_info(&finished_info, session_info, ceph_handle, GLOBUS_SUCCESS);
 
  ceph_handle->checksum_list = NULL;
  ceph_handle->checksum_list_p = NULL;
    
  globus_gridftp_server_operation_finished(op, GLOBUS_SUCCESS, &finished_info);
  globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,"%s: leaving.\n", func);  
  
}

/*************************************************************************
 *  destroy
 *  -------
 *  This is called when a session ends, ie client quits or disconnects.
 *  The dsi should clean up all memory they associated with the session
 *  here.
 ************************************************************************/
static void globus_l_gfs_ceph_destroy(void *user_arg) {
  globus_l_gfs_ceph_handle_t *ceph_handle;
  ceph_handle = (globus_l_gfs_ceph_handle_t *) user_arg;
  globus_mutex_destroy(&ceph_handle->mutex);
  globus_free(ceph_handle);
}

/*************************************************************************
 *  stat
 *  ----
 *  This interface function is called whenever the server needs
 *  information about a given file or resource.  It is called then an
 *  LIST is sent by the client, when the server needs to verify that
 *  a file exists and has the proper permissions, etc.
 ************************************************************************/
static void globus_l_gfs_ceph_stat(globus_gfs_operation_t op,
                                   globus_gfs_stat_info_t *stat_info,
                                   void *user_arg) {
  globus_gfs_stat_t *              stat_array;
  int                              stat_count;
  globus_l_gfs_ceph_handle_t *     ceph_handle;
  char *                           func="globus_l_gfs_ceph_stat";
  struct stat64                    statbuf;
  int                              status=0;
  globus_result_t                  result;
  
  GlobusGFSName(globus_l_gfs_ceph_stat);
  
  char* pathname_to_test = cleanup_pathname(stat_info->pathname);
  
  globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "%s: %s\n",
                         func, stat_info->pathname);
  
  
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,
          "%s: prog= %s, authdb= %s, VO_Role= %s, op= %s, pathname= %s\n",
      func, authdbProg, authdbFilename, VO_Role, "rd", pathname_to_test);  
  
  int allowed = checkAccess(authdbProg, authdbFilename, VO_Role, "rd", pathname_to_test);

  if (!allowed) {
    result = GlobusGFSErrorGeneric("globus_l_gfs_ceph_stat: authorization error: 'MLST' operation not allowed");
    globus_gridftp_server_finished_stat(op, result, NULL, 0);
    return;
  } else {
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
          "INFO %s: Authorization.success: 'MLST' operation allowed\n", func);
  }  
  
  

  if (!strcmp("/", stat_info->pathname))   {    // Make the root directory "/" - FTS needs some hand-holding
    
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
        "INFO %s: Looks like a stat on '/' for %s.\n", __FUNCTION__, stat_info->pathname);
    
    // Sometimes, the FTS client will send a 'MLST /' command when the target doesn't exist
    // Return some fake stat information
    //
    stat_count = 1;
    statbuf.st_uid = 0;
    statbuf.st_gid = 0;
    statbuf.st_mode = __S_IFDIR|0666;
    statbuf.st_size = 0;
    statbuf.st_atime = 0;
    statbuf.st_ctime = 0;
    statbuf.st_mtime = 0;
    stat_array = (globus_gfs_stat_t *) globus_calloc(1, sizeof (globus_gfs_stat_t));
    if (stat_array == NULL) {
      result = GlobusGFSErrorGeneric("error: memory allocation failed");
      globus_gridftp_server_finished_stat(op, result, NULL, 0);
      return;
    }
    stat_count = 1;
    fill_stat_array(&(stat_array[0]), statbuf, stat_info->pathname);
    globus_gridftp_server_finished_stat(op, GLOBUS_SUCCESS, stat_array, stat_count);
    free_stat_array(stat_array, stat_count);
    globus_free(stat_array);
    
  } else {     // It's a proper objectname
    
    status = ceph_posix_stat64(stat_info->pathname, &statbuf);

    if (status != 0) {
      globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
              "INFO %s: Return from stat64 = %d\n", __FUNCTION__, status);
      if (status == -EINVAL) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "ERROR %s: cannot get striper\n", __FUNCTION__);
      }
      result = globus_l_gfs_make_error("stat64");
      globus_gridftp_server_finished_stat(op, result, NULL, 0);

      return;
    }
    stat_array = (globus_gfs_stat_t *) globus_calloc(1, sizeof (globus_gfs_stat_t));
    if (stat_array == NULL) {
      result = GlobusGFSErrorGeneric("error: memory allocation failed");
      globus_gridftp_server_finished_stat(op, result, NULL, 0);
      return;
    }
    stat_count = 1;
    fill_stat_array(&(stat_array[0]), statbuf, stat_info->pathname);
    globus_gridftp_server_finished_stat(op, GLOBUS_SUCCESS, stat_array, stat_count);
    free_stat_array(stat_array, stat_count);
    globus_free(stat_array);

  }
  
  return;
}

/*************************************************************************
 *  command
 *  -------
 *  This interface function is called when the client sends a 'command'.
 *  commands are such things as mkdir, remdir, delete.  The complete
 *  enumeration is below.
 *
 *  To determine which command is being requested look at:
 *      cmd_info->command
 *
 *      GLOBUS_GFS_CMD_MKD = 1,
 *      GLOBUS_GFS_CMD_RMD,
 *      GLOBUS_GFS_CMD_DELE,
 *      GLOBUS_GFS_CMD_RNTO,
 *      GLOBUS_GFS_CMD_RNFR,
 *      GLOBUS_GFS_CMD_CKSM,
 *      GLOBUS_GFS_CMD_SITE_CHMOD,
 *      GLOBUS_GFS_CMD_SITE_DSI
 ************************************************************************/
static void globus_l_gfs_ceph_command(globus_gfs_operation_t op,
                                      globus_gfs_command_info_t *cmd_info,
                                      void *user_arg) {

  GlobusGFSName(globus_l_gfs_ceph_command);
  
  globus_result_t                     result;
  int allowed;
  char errormessage[ERRORMSGSIZE];

  char* pathname_to_test = cleanup_pathname(cmd_info->pathname);
  pathname = strdup(pathname_to_test);


  switch (cmd_info->command) {
      /* Support DELE for GridPP FTS when the target already exists*/
    case GLOBUS_GFS_CMD_DELE:
      
      globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
        "INFO %s: DELE %s\n", __FUNCTION__, cmd_info->pathname); 
      globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
      "INFO %s: checkAccess (VORole = %s, op = %s, pathname = %s\n", 
        __FUNCTION__, VO_Role, "wr", pathname_to_test);
      
      allowed = checkAccess(authdbProg, authdbFilename, VO_Role, "wr", pathname_to_test);

      if (!allowed) {
        
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,
          "ERROR %s: Authorization failure: cannot DELE %s\n", __FUNCTION__, cmd_info->pathname);   
        
        snprintf(errormessage, ERRORMSGSIZE, "Authorization error: DELE operation for role %s not allowed on %s", 
          VO_Role, cmd_info->pathname);

        result = GlobusGFSErrorGeneric(errormessage);
        errno = ENOENT; 
        globus_gridftp_server_finished_command(op, result, GLOBUS_NULL); 
      } else {

        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
          "INFO %s: Authorization success: DELE operation allowed\n", __FUNCTION__);

        int status = ceph_posix_delete(cmd_info->pathname);
        if (status != 0) {
          globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,
            "ERROR DELE return code is %d\n", status); // Log the actual failure reason... 
          //errno = -status; // Return error code to client
          snprintf(errormessage, ERRORMSGSIZE, "%s", strerror(-status));
          result = GlobusGFSErrorGeneric(errormessage);
             
          globus_gridftp_server_finished_command(op, result, errormessage /* GLOBUS_NULL */);
          
        } else {
          errno = 0;
          globus_gridftp_server_finished_command(op, GLOBUS_SUCCESS, GLOBUS_NULL);
        }
      }
      return;


      /*
       * Support MKD because GridPP FTS thinks it needs to make a *directory* '/' for a non-existent target
       * Target name sent as a Globus URL always contains a slash which tricks client into thinking it is
       * dealing with a hierarchical pathname, not a Ceph object name
       * We fool the FTS client (which isn't aware that the Ceph object store doesn't support directories)
       * into thinking that is has created the directory it wants to see, and can then continue with the rest of the
       * FTS transfer
       *  
       */
    case GLOBUS_GFS_CMD_MKD:

      /*
         *
         * Check if FTS responds sensibly when it tries to make a parent directory? Or should it have
         * already been denied 'wr' access?
         */
      globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
        "INFO %s: MKD %s\n", __FUNCTION__, cmd_info->pathname); 
      globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
      "INFO %s: checkAccess (VORole = %s, op = %s, pathname = %s\n", 
        __FUNCTION__, VO_Role, "wr", pathname_to_test);
      
      allowed = checkAccess(authdbProg, authdbFilename, VO_Role, "wr", pathname_to_test);

      if (!allowed) {
        snprintf(errormessage, ERRORMSGSIZE,
                "Authorization error: MKD operation for role %s not allowed on %s", 
          VO_Role, cmd_info->pathname);
        result = GlobusGFSErrorGeneric(errormessage);
        globus_gridftp_server_finished_command(op, result, errormessage);
        
      } else {

        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
          "INFO %s: acc.success: MKD operation allowed\n", __FUNCTION__);

        
       /*
       * The core of GrdiFTP will return a '257 MKD <pathname> Pathname: Created Successfully message'
        * We don't need to do anything server-side.
       */    
        ;
        
        globus_gridftp_server_finished_command(op, GLOBUS_SUCCESS, GLOBUS_NULL);

      }      
      return;

      /*
       * Support CKSM command. This DSI only stores checksums using the ADLER32 algorithm.
       * To-do: Check whether objects stored by XROOTD DSI have a checksum stored
       * 
       */

    case GLOBUS_GFS_CMD_CKSM:

      globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
        "INFO %s: CKSM %s\n", __FUNCTION__, cmd_info->pathname);
      globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
        "INFO %s: checkAccess (VORole = %s, op = %s, pathname = %s\n", 
        __FUNCTION__, VO_Role, "rd", pathname_to_test);
      
      allowed = checkAccess(authdbProg, authdbFilename, VO_Role, "rd", pathname_to_test);

      if (!allowed) {
        (void)snprintf(errormessage, ERRORMSGSIZE, 
          "Authorization error: CKSM operation for role %s on %s not allowed.", VO_Role, cmd_info->pathname);
        result = GlobusGFSErrorGeneric(errormessage);
        globus_gridftp_server_finished_command(op, GLOBUS_FAILURE, errormessage);
        
      } else {

          globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
          "INFO authz .success: CKSM operation allowed\n");


        //      cksm_alg = cmd_info->cksm_alg; // In case we support checksums other than ADLER32 in the future...
        //      /** offset for cksm command */
        //      cksm_offset = cmd_info->cksm_offset;
        //      /** length of data to read for cksm command   -1 means full file */
        //      cksm_length = cmd_info->cksm_length;
          
        struct stat64 statbuf;
        const int status = ceph_posix_stat64(cmd_info->pathname, &statbuf);

        if (status != 0) {
          globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
            "INFO %s: Return from stat64 for checksum = %d\n", __FUNCTION__, status);
          if (status == -EINVAL) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "ERROR %s: cannot get striper\n", __FUNCTION__);
          }
                   
          char errorBuf[ERRORMSGSIZE];
          (void)snprintf(errorBuf, ERRORMSGSIZE, "Object %s does not exist, cannot return a checksum", cmd_info->pathname);
          result = globus_l_gfs_make_error(errorBuf);
          globus_gridftp_server_finished_command(op, result, (char *)NULL); 

          return;
        }   


        char ckSumbufdisk[CA_MAXCKSUMLEN + 1];

        int upgradeChecksum = 0;
        char* storedChecksum = NULL;

        storedChecksum = ceph_posix_get_new_format_checksum(cmd_info->pathname);

        if (storedChecksum != NULL) {

//          strncpy(ckSumbufdisk, storedChecksum, CA_MAXCKSUMLEN);
//          ckSumbufdisk[CA_MAXCKSUMLEN] = '\0';
            storedChecksum[CA_MAXCKSUMLEN] = '\0';
          
          globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "INFO %s: Found new format checksum XrdCks.adler32 for %s.\n", __FUNCTION__, pathname);

        } else {

          storedChecksum = ceph_posix_get_old_format_checksum(cmd_info->pathname);

          if (storedChecksum != NULL) {

//            strncpy(ckSumbufdisk, storedChecksum, CA_MAXCKSUMLEN);
//            ckSumbufdisk[CA_MAXCKSUMLEN] = '\0';
//            storedChecksum[CA_MAXCKSUMLEN] = '\0';
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "INFO %s: Found old format checksum user.checksum.value for %s.\n", __FUNCTION__, pathname);
            upgradeChecksum = 1;

          }

        }



        globus_result_t result;
        if (storedChecksum == NULL) {
          errno = ENODATA;
          char errorBuf[ERRORMSGSIZE+1];
          (void) snprintf(errorBuf, ERRORMSGSIZE, "Cannot find checksum for %s", cmd_info->pathname);
          result = globus_l_gfs_make_error(errorBuf);
        } else {
          errno = 0;
          result = GLOBUS_SUCCESS;
        }
        globus_gridftp_server_finished_command(op, result, storedChecksum);

      }
      return;

    default:
      break;
  }
  /* Complain if command is neither CKSM, DELE, or MKD */
  globus_gridftp_server_finished_command(op,
          GlobusGFSErrorGeneric("error: commands other than CKSM, DELE, or MKD are denied"), GLOBUS_NULL);
  return;
}

unsigned long add_checksum_to_list(
  globus_l_gfs_ceph_handle_t *ceph_handle,
  globus_byte_t *buffer,
  globus_off_t offset,
  globus_size_t nbytes) {
  
  unsigned long adler;
  /* fill the checksum list  */
  /* we will have a lot of checksums blocks in the list */
  adler = adler32(0L, Z_NULL, 0);
  adler = adler32(adler, buffer, nbytes);

  ceph_handle->checksum_list_p->next =
    (checksum_block_list_t *) globus_malloc(sizeof (checksum_block_list_t));

  if (ceph_handle->checksum_list_p->next == NULL) {
    return GLOBUS_FALSE;
  }
  
  ceph_handle->checksum_list_p->next->next = NULL;
  ceph_handle->checksum_list_p->offset = offset;
  ceph_handle->checksum_list_p->size = nbytes;
  ceph_handle->checksum_list_p->csumvalue = adler;
  ceph_handle->checksum_list_p = ceph_handle->checksum_list_p->next;
  ceph_handle->number_of_blocks++;
  /* end of the checksum section */  
  return GLOBUS_TRUE;
}
const int ceph_handle_open(const char *path,
                     const int flags,
                     const int mode,
                     globus_l_gfs_ceph_handle_t *ceph_handle) {
  int       rc;
  char *    func="ceph_handle_open";

  globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,"%s: %s\n", func, path);
  
  rc = ceph_posix_open(path, flags, mode);
  ceph_handle->fileSize = 0;
  return rc;
}

/* combine checksums, while making sure that we deal with missing chunks */

unsigned long get_file_checksum(
  globus_l_gfs_ceph_handle_t *ceph_handle,
  checksum_block_list_t** checksum_array,
  globus_off_t chkOffset,
  unsigned long file_checksum) {

//  unsigned long file_checksum;
  unsigned long i;
  for (i = 1; i < ceph_handle->number_of_blocks; i++) {
    /* check the continuity with previous chunk */
    if (checksum_array[i]->offset != chkOffset) {
      // not continuous, either a chunk is missing or we have overlapping chunks
      if (checksum_array[i]->offset > chkOffset) {
        // a chunk is missing, consider it full of 0s
        globus_off_t doff = checksum_array[i]->offset - chkOffset;
        file_checksum = adler32_combine_(file_checksum, adler32_0chunks(doff), doff);
        chkOffset = checksum_array[i]->offset;
      } else {

        return 0; // Should have a break here instead - single return

      }
    }
    /* now handle the next chunk */
    file_checksum = adler32_combine_(file_checksum,
      checksum_array[i]->csumvalue,
      checksum_array[i]->size);
    chkOffset += checksum_array[i]->size;
  }
  return file_checksum;

}

checksum_block_list_t** checksum_list_to_array(
  globus_l_gfs_ceph_handle_t *ceph_handle) {
  
  checksum_block_list_t** checksum_array =(checksum_block_list_t**)
    globus_calloc(ceph_handle->number_of_blocks, sizeof(checksum_block_list_t*));

  if (checksum_array == NULL) {
    return NULL;
  }
  
  checksum_block_list_t *checksum_list_pp = ceph_handle->checksum_list;
  /* sorting of the list to the array */
  int index = 0;
  /* the latest block is always empty and has next pointer as NULL */
  while (checksum_list_pp->next != NULL) {
    checksum_array[index] = checksum_list_pp;
    checksum_list_pp = checksum_list_pp->next;
    index++;
  }
  qsort(checksum_array, index, sizeof (checksum_block_list_t*), offsetComparison);

  return checksum_array;
         
}


#define BUFFER_WRITE 1
#define BUFFER_CONTINUE 2
#define BUFFER_OUT_OF_RANGE 3

int build_buffer(
  globus_l_gfs_ceph_handle_t * ceph_handle,
  globus_byte_t *buffer, globus_off_t offset,
  globus_size_t nbytes, globus_bool_t eof) {

  if (offset < ceph_handle->active_start) {
    
    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "ERROR %s: Offset %lld < active_start of %lld \n", 
      __FUNCTION__, offset, ceph_handle->active_start );
    return BUFFER_OUT_OF_RANGE;
    
  }
  
  assembly_t *dest_buff;

  if (offset + nbytes - 1 <= ceph_handle->active_end) { // In ACTIVE range 

    dest_buff = ceph_handle->active_buff;    
    int index = offset - ceph_handle->active_start; 
    memcpy(dest_buff->buffer+index, buffer, nbytes);
    dest_buff->nbytes += nbytes;   
    ++ceph_handle->nblocks_in_range;

    if (dest_buff->nbytes == ceph_handle->rebuff_size || eof) {
        
      globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, 
              "%s: Returning BUFFER_WRITE (%lld, %lld), n_inrange = %d, n_overflow = %d\n", 
              __FUNCTION__, 
              ceph_handle->active_start, ceph_handle->active_end, 
              ceph_handle->nblocks_in_range, ceph_handle->nblocks_in_overflow);  
      return BUFFER_WRITE;
      
    } else {
        
      return BUFFER_CONTINUE;
      
    }

  } else if (offset >= ceph_handle->overflow_start) {

    if (offset + nbytes - 1 <= ceph_handle->overflow_end) { // in OVERFLOW range
        
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Overflow offset %lld\n", offset);

      dest_buff = ceph_handle->overflow_buff;
      
      int index = offset - ceph_handle->overflow_start; // dest_buff->offset;
      memcpy(dest_buff->buffer+index, buffer, nbytes);
      dest_buff->nbytes += nbytes;

      ++ceph_handle->nblocks_in_overflow;
      globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "ERROR %s: There are %lu blocks in overflow buffer.\n", __FUNCTION__, ceph_handle->nblocks_in_overflow);

      if (dest_buff->nbytes == ceph_handle->rebuff_size) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "ERROR %s: OVERFLOW BUFFER FULL!! SHOULD NOT HAPPEN! -- Returning BUFFER_WRITE\n", __FUNCTION__);
        return BUFFER_WRITE;
        
      } else {
          
        return BUFFER_CONTINUE;
        
      }

    } else { // Way past OVERFLOW end
      
      globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,
        "ERROR %s: Packet too early: Offset %lld + nbytes-1 %lld (%lld) > overflow_end of %lld \n",
        __FUNCTION__, offset, (nbytes - 1), (offset + nbytes - 1), ceph_handle->overflow_end);
      return BUFFER_OUT_OF_RANGE;
      
    }

  }
  
}

void flip_buffer(globus_l_gfs_ceph_handle_t * ceph_handle) {
  
  assembly_t * temp_buff = ceph_handle->active_buff;
  
  temp_buff->nbytes = 0;                        // We've just written data stored here
  
  ceph_handle->active_start = ceph_handle->overflow_start; 
  ceph_handle->active_end = ceph_handle->overflow_end; 
  
  ceph_handle->overflow_start += ceph_handle->rebuff_size;                                        
  ceph_handle->overflow_end += ceph_handle->rebuff_size;  
    
  ceph_handle->active_buff = ceph_handle->overflow_buff; // So we can start with the too-early blocks we've received
  ceph_handle->overflow_buff = temp_buff;
  
//   globus_gfs_log_message(GLOBUS_GFS_LOG_ALL, "%s: ACTIVE BUFFER: active_start = %lld, active_end =  %lld \n",
//  __FUNCTION__, ceph_handle->active_start, ceph_handle->active_end); 
//   
//   globus_gfs_log_message(GLOBUS_GFS_LOG_ALL, "%s: OVERFLOW BUFFER: overflow_start = %lld, overflow_end =  %lld \n",
//  __FUNCTION__, ceph_handle->overflow_start, ceph_handle->overflow_end); 

   assert(ceph_handle->active_end == ceph_handle->overflow_start-1);
   ceph_handle->nblocks_in_range = ceph_handle->nblocks_in_overflow;
   ceph_handle->nblocks_in_overflow = 0;
   
}


globus_byte_t *get_buffer(globus_l_gfs_ceph_handle_t * ceph_handle) {
  return ceph_handle->active_buff->buffer;
}

globus_size_t get_nbytes(globus_l_gfs_ceph_handle_t * ceph_handle) {
  return ceph_handle->active_buff->nbytes;
}

globus_off_t get_offset(globus_l_gfs_ceph_handle_t * ceph_handle) {
  return ceph_handle->active_start;
}


/* receive from client */
static void globus_l_gfs_ceph_net_read_cb(globus_gfs_operation_t op,
                                          globus_result_t result,
                                          globus_byte_t *buffer,
                                          globus_size_t nbytes,
                                          globus_off_t offset,
                                          globus_bool_t eof,
                                          void *user_arg) {
  globus_off_t                 start_offset;
  globus_l_gfs_ceph_handle_t * ceph_handle;
  ssize_t                      bytes_written;
  unsigned long                adler;
  checksum_block_list_t**      checksum_array;
//  checksum_block_list_t *      checksum_list_pp;
  unsigned long                index;
  unsigned long                i;
  unsigned long                file_checksum;
  char                         ckSumbuf[CA_MAXCKSUMLEN+1] = "0";
  char *                       ckSumalg = "ADLER32"; /* we only support Adler32 for gridftp */
  char *                       func = "globus_l_gfs_file_net_read_cb";
  
  static globus_size_t last_nbytes = 0;
  static int reported_nbytes = 0;

  if (!strcmp(getdebug(), "1")) {

//    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
//      "%s\n\tEOF = %s, offset = %lld, nbytes = %d\n", 
//      __FUNCTION__, eof ? "TRUE" : "FALSE", offset, nbytes);
    
    if (nbytes != last_nbytes) {
      globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "%s: nbytes: %d, was previously %d\n", __FUNCTION__, nbytes, last_nbytes);
      last_nbytes = nbytes;
    }

  }
  
  ceph_handle = (globus_l_gfs_ceph_handle_t *) user_arg;

  globus_mutex_lock(&ceph_handle->mutex);
  {
    if (eof) {
      ceph_handle->done = GLOBUS_TRUE;
    }
        
    ceph_handle->outstanding--;
        
    if (result != GLOBUS_SUCCESS) {
      
      ceph_handle->cached_res = result;
      ceph_handle->done = GLOBUS_TRUE;

    } else if (nbytes > 0 || get_nbytes(ceph_handle) > 0) {

      int action;
      
      if (nbytes == 0 && get_nbytes(ceph_handle) > 0) {
          
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, 
          "%s: \n\n\t0 bytes read, flushing data left in assembly buffer\n\n", __FUNCTION__);       
        action = BUFFER_WRITE;
        
      } 
      
      int buffering = GLOBUS_FALSE;
      globus_byte_t *a_buffer;
      globus_off_t a_offset;
      globus_size_t a_nbytes;
           
      if (nbytes > ceph_handle->rebuff_size) { // Can't fit incoming data into buffer
  
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, 
          "INFO %s: Buffer too large for re-assembly\n", __FUNCTION__);        
        action = BUFFER_WRITE;
        
      } else {

        if (nbytes > 0) {

          action = build_buffer(ceph_handle, buffer, offset, nbytes, eof);

        }

        if (action == BUFFER_OUT_OF_RANGE) {

          globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "ERROR %s: offset %lld out of range \n", __FUNCTION__, offset);
          ceph_handle->cached_res = GLOBUS_FAILURE; //globus_l_gfs_make_error("write"); // GLOBUS_FAILURE;
          ceph_handle->done = GLOBUS_TRUE;
          ceph_handle->fileSize = 0;
          globus_mutex_unlock(&ceph_handle->mutex);

          errno = ENOENT;
          result = globus_l_gfs_make_error("data stream overflows buffer");

          globus_gridftp_server_finished_transfer(op, result);

          return;

        }
        
        buffering = GLOBUS_TRUE;        
        globus_gridftp_server_update_bytes_written(op, offset, nbytes);
      
      }

      if (action == BUFFER_WRITE) {
        
        if (get_nbytes(ceph_handle) > 0) { // Use the re-assembled buffer
          
          a_buffer = get_buffer(ceph_handle);
          a_offset = get_offset(ceph_handle);
          a_nbytes = get_nbytes(ceph_handle);
          
        } else {
          
          a_buffer = buffer;
          a_offset = offset;
          a_nbytes = nbytes;
                
        }

        start_offset = ceph_posix_lseek64(ceph_handle->fd, a_offset, SEEK_SET);
        if (start_offset != a_offset) {
            
          ceph_handle->cached_res = globus_l_gfs_make_error("seek");
          ceph_handle->done = GLOBUS_TRUE;
          
        } else {

          bytes_written = ceph_posix_write(ceph_handle->fd, a_buffer, a_nbytes);

          if (bytes_written < 0) { // TO-DO: call transfer_finished here
            
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "ERROR %s: write error, return code %d \n", func, -bytes_written);
            ceph_handle->cached_res = GLOBUS_FAILURE; //globus_l_gfs_make_error("write"); // GLOBUS_FAILURE;
            ceph_handle->done = GLOBUS_TRUE;
            ceph_handle->fileSize = 0;
            globus_mutex_unlock(&ceph_handle->mutex);
            return;
            
          } else {

            int added_checksum = add_checksum_to_list(ceph_handle, a_buffer, a_offset, a_nbytes);
            if (added_checksum == GLOBUS_FALSE) {

              ceph_handle->cached_res = GLOBUS_FAILURE;
              globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "ERROR %s: malloc error \n", func);
              ceph_handle->done = GLOBUS_TRUE;
              globus_mutex_unlock(&ceph_handle->mutex);
              return;

            }

            if ((globus_size_t) bytes_written < a_nbytes) {

              errno = ENOSPC;
              ceph_handle->cached_res = globus_l_gfs_make_error("write");
              ceph_handle->done = GLOBUS_TRUE;
              free_checksum_list(ceph_handle->checksum_list);

            } else {

              ceph_handle->fileSize += bytes_written;
              
              if (buffering == GLOBUS_TRUE) {

                flip_buffer(ceph_handle);

              } else {
                
                globus_gridftp_server_update_bytes_written(op, a_offset, a_nbytes);
                               
              }
              
              

            } // bytes_written == nbytes

          } // bytes_written > 0

        } // offsets OK


      } // action == BUFFER_WRITE 
      
    } // nbytes > 0

    globus_free(buffer);
    /* if not done just register the next one */
    if (!ceph_handle->done) {
        
      globus_l_gfs_ceph_read_from_net(ceph_handle);
      
    }  else if (ceph_handle->outstanding == 0) { /* if done and there are no outstanding callbacks finish */
      
//      if (ceph_handle->alloc_size >0 && ceph_handle->alloc_size != ceph_handle->fileSize) {
// 
//          globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, 
//            "%s: Incomplete transfer - wrote %lld, expected %lld.\n", func, ceph_handle->fileSize, ceph_handle->alloc_size);
//          globus_ceph_close(func, ceph_handle, "Incomplete transfer");
//          globus_mutex_unlock(&ceph_handle->mutex);
//          globus_gridftp_server_finished_transfer(op, ceph_handle->cached_res);        
//        
//      }
      
      globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "%s: AFTER check outstanding == 0 \n", __FUNCTION__); 

      if (ceph_handle->number_of_blocks > 0) {

        checksum_array = checksum_list_to_array(ceph_handle);
        
        if (checksum_array == NULL) {
          free_checksum_list(ceph_handle->checksum_list);
          ceph_handle->fileSize = 0;
          globus_ceph_close(func, ceph_handle, "Internal error (malloc failed)");
          globus_mutex_unlock(&ceph_handle->mutex);
          return;
        }
        
        /* combine checksums, while making sure that we deal with missing chunks */
        globus_off_t chkOffset = 0;
        /* check whether first chunk is missing */
        if (checksum_array[0]->offset != 0) {
          /* first chunk is missing. Consider it full of 0s */
          chkOffset = checksum_array[0]->offset;
          file_checksum = 
            adler32_combine_(adler32_0chunks(chkOffset),
                                           checksum_array[0]->csumvalue,
                                           checksum_array[0]->size);
        } else {
          file_checksum = checksum_array[0]->csumvalue;
        }
        chkOffset += checksum_array[0]->size;
        
        file_checksum = get_file_checksum(ceph_handle, checksum_array, chkOffset, file_checksum);

        if (file_checksum == 0) {
          // overlapping chunks. This is not supported, fail the transfer
          free_checksum_list(ceph_handle->checksum_list);
          globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, 
            "ERROR %s: Overlapping chunks detected while handling 0x%x-0x%x. The overlap starts at 0x%x\n",
            func, checksum_array[i]->offset, checksum_array[i]->offset + checksum_array[i]->size,
            chkOffset);
          globus_ceph_close(func, ceph_handle, "overlapping chunks detected when computing checksum");
          globus_mutex_unlock(&ceph_handle->mutex);
          globus_gridftp_server_finished_transfer(op, ceph_handle->cached_res);
          return;
        }
        
        snprintf(ckSumbuf, CA_MAXCKSUMLEN+1, "%08lx", file_checksum);    // Keep leading zeroes
        
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "INFO %s: checksum for fd %d : AD %s\n",
                               func, ceph_handle->fd, ckSumbuf); // Log the checksum string we're storing
        globus_free(checksum_array);
        free_checksum_list(ceph_handle->checksum_list);
        
        /* set extended attributes */
        
        /*
         * To-DO: Set old format checksum attribute as well?
         */
        
        int rc = ceph_posix_set_new_format_checksum_fd(ceph_handle->fd, "adler32", ckSumbuf);
        
        if (rc != 0) {
          
          globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,"ERROR %s: unable to store new format checksum XrdCks.adler32 for %s\n", func, pathname);
       
        } else {
          
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,"ERROR %s: stored new format checksum XrdCks.adler32 for %s, value %s\n", func, pathname, ckSumbuf);
         
        }
//        
//        
//        if (ceph_posix_fsetxattr(ceph_handle->fd,"user.checksum.type",
//                                 ckSumalg, strlen(ckSumalg), 0) != 0) {
//          globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,"%s: unable to store checksum type as xattr\n", func);
//        }
//        else if (ceph_posix_fsetxattr(ceph_handle->fd,"user.checksum.value",
//                                      ckSumbuf, strlen(ckSumbuf), 0) != 0) {
//          globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,"%s: unable to store checksum value as xattr\n", func);
//        }
        
        
      } // ceph_handle->number_of_blocks > 0
      
      globus_ceph_close(func, ceph_handle, NULL);
      globus_gridftp_server_finished_transfer(op, ceph_handle->cached_res);
      
    } // outstanding == 0
    
  } // mutex block
  
  globus_mutex_unlock(&ceph_handle->mutex);
}

static unsigned long get_checksum_from_file(const char* path, globus_gfs_operation_t op) {

  unsigned long file_checksum = 0;

  globus_l_gfs_ceph_handle_t ch;
  globus_l_gfs_ceph_handle_t * const ceph_handle = &ch;
  
  globus_off_t                        read_length;
  globus_off_t                        nbread;
  globus_off_t                        start_offset;
  globus_byte_t *                     buffer;
  
  globus_result_t result = GLOBUS_FAILURE;

  
  ceph_handle->fd = ceph_handle_open(path, O_RDONLY, 0, ceph_handle);

  if (ceph_handle->fd < 0) {
    result = globus_l_gfs_make_error("open");
    globus_gridftp_server_finished_transfer(op, result);
    return;
  }

  /* reset all the needed variables in the handle */
  ceph_handle->cached_res = GLOBUS_SUCCESS;
  ceph_handle->outstanding = 0;
  ceph_handle->done = GLOBUS_FALSE;
  ceph_handle->blk_length = 0;
  ceph_handle->blk_offset = 0;
  ceph_handle->op = op;

//  globus_gridftp_server_get_optimal_concurrency(op, &ceph_handle->optimal_count);
//  globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "%s: optimal_concurrency: %u\n",
//    func, ceph_handle->optimal_count);

  globus_gridftp_server_get_block_size(op, &ceph_handle->block_size);

  int blksize = getconfigint("GRIDFTP_CEPH_READ_SIZE");
  if (blksize > 0) {
    ceph_handle->block_size = blksize;
  } else {
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "%s: Invalid %s block_size: %ld\n",
      __FUNCTION__, "GRIDFTP_CEPH_READ_SIZE", blksize);
  }
  globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "%s: block_size: %ld\n",
    __FUNCTION__, ceph_handle->block_size);

  /* here we will save all checksums for the file blocks        */
  /* malloc memory for the first element in the checksum list   */
  /* we should always have at least one block for a file        */
  ceph_handle->checksum_list =
    (checksum_block_list_t *) globus_malloc(sizeof (checksum_block_list_t));
  if (ceph_handle->checksum_list == NULL) {
    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "ERROR %s: malloc error \n", __FUNCTION__);
    globus_gridftp_server_finished_transfer(op, GLOBUS_FAILURE);
    return;
  }
  ceph_handle->checksum_list->next = NULL;
  ceph_handle->checksum_list_p = ceph_handle->checksum_list;
  ceph_handle->number_of_blocks = 0;  
  
  read_length = ceph_handle->block_size;
  
  nbread = -1;
  buffer = globus_malloc(read_length);
  
  while (nbread = ceph_posix_read(ceph_handle->fd, buffer, read_length)  != 0) {
    
    ceph_handle->blk_length += nbread; // Increase the offset
      start_offset = ceph_posix_lseek64(ceph_handle->fd,
                                    ceph_handle->blk_offset,
                                    SEEK_SET);
  /* verify that it worked */
  if (start_offset != ceph_handle->blk_offset) {
    globus_ceph_close(__FUNCTION__, ceph_handle, "failed to seek");
    if (ceph_handle->outstanding == 0) {
      globus_gridftp_server_finished_transfer(ceph_handle->op,
                                              ceph_handle->cached_res);
    }
    return ceph_handle->done;
  }

    
    
  }

  checksum_block_list_t** checksum_array;

  checksum_array = checksum_list_to_array(ceph_handle);

  if (checksum_array == NULL) {
    return file_checksum;
  }

  /* combine checksums, while making sure that we deal with missing chunks */
  globus_off_t chkOffset = 0;
  /* check whether first chunk is missing */
  if (checksum_array[0]->offset != 0) {
    /* first chunk is missing. Consider it full of 0s */
    chkOffset = checksum_array[0]->offset;
    file_checksum =
      adler32_combine_(adler32_0chunks(chkOffset),
      checksum_array[0]->csumvalue,
      checksum_array[0]->size);
  } else {
    file_checksum = checksum_array[0]->csumvalue;
  }
  chkOffset += checksum_array[0]->size;

  file_checksum = get_file_checksum(ceph_handle, checksum_array, chkOffset, file_checksum);

}

static void globus_l_gfs_ceph_read_from_net
(globus_l_gfs_ceph_handle_t *ceph_handle) {
  globus_byte_t *                     buffer;
  globus_result_t                     result;
  char *                     func="globus_l_gfs_ceph_read_from_net";
  
  static int reported_sizes = 0;
  static int reported_block_size = 0;
  static int current_opt_concur = 0;

  if(!strcmp(getdebug(), "1")) {
    
    if (reported_block_size == 0) {
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
                             "INFO %s: start, ceph_handle->block_size = %d\n",
                             func, ceph_handle->block_size);
    reported_block_size = 1;
    }
  }
  
  GlobusGFSName(globus_l_gfs_ceph_read_from_net);
  
  globus_gridftp_server_get_optimal_concurrency(ceph_handle->op,
                                                &ceph_handle->optimal_count);
  
  if (ceph_handle->optimal_count != current_opt_concur) { // Report any changes to optimal concurrency
                                                          // Calculated as 2 * no. of streams
   
    current_opt_concur = ceph_handle->optimal_count;
    
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "INFO %s: optimal_concurrency: %u\n",
      func, ceph_handle->optimal_count);
  
  }
  while(ceph_handle->outstanding < ceph_handle->optimal_count) {
    buffer=globus_malloc(ceph_handle->block_size);
    if (buffer == NULL) {
      if (ceph_handle->outstanding == 0) {
        globus_ceph_close(func, ceph_handle, "internal error (malloc failed)");
        globus_gridftp_server_finished_transfer(ceph_handle->op,
                                                ceph_handle->cached_res);
      }
      return;
    }

    if (!strcmp(getdebug(), "1")) {     
      if (reported_sizes == 0) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
                "INFO %s: just before register_read, ceph_handle->block_size = %d\n",
                func, ceph_handle->block_size);
//        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
//                "%s: just before register_read, ceph_handle->op->data_handle->info.blocksize = %d\n",
//                func, ceph_handle->op->data_handle->info.blocksize);   
        
        reported_sizes = 1;
      
      }
    }
            
    result= globus_gridftp_server_register_read(ceph_handle->op,
                                                buffer,
                                                ceph_handle->block_size,
                                                globus_l_gfs_ceph_net_read_cb,
                                                ceph_handle);

    if(result != GLOBUS_SUCCESS)  {
      globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,
                             "ERROR %s: register read has finished with a bad result\n",
                             func);
      globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,"%s:%d, on register read FAIL, GLOBUS_FREE %p\n", __FUNCTION__, __LINE__, buffer);     
      globus_free(buffer);
      ceph_handle->cached_res = result;
      if (ceph_handle->outstanding == 0) {
        globus_ceph_close(func, ceph_handle, "register read has finished with a bad result");
        globus_gridftp_server_finished_transfer(ceph_handle->op,
                                                ceph_handle->cached_res);
      }
      return;
    } else {
//      globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,
//                             "%s: register read OK\n",
//                             func);      
    }
    ceph_handle->outstanding++;
  }
}
    
//char* cleanup_pathname(char* in, const char* inital) {
//  
//  char *out;
//  if (!strncmp(in, inital, strlen(inital))) {
//    out = (char *)malloc(strlen(in));  
//    strcpy(out, in+1);
//  } else {
//    out = (char *)malloc(strlen(in) + 1);  
//    strcpy(out, in);
//  }
//  
//  return out;
//  
//}



/*************************************************************************
 *  recv
 *  ----
 *  This interface function is called when the client requests that a
 *  file be transfered to the server.
 *
 *  To receive a file the following functions will be used in roughly
 *  the presented order.  They are doced in more detail with the
 *  gridftp server documentation.
 *
 *      globus_gridftp_server_begin_transfer();
 *      globus_gridftp_server_register_read();
 *      globus_gridftp_server_finished_transfer();
 *
 * 
 * XRootD ACC logging be like :-
 * 
 * 160708 08:59:18 38648 acc_Audit: ijj87.3398491:26@lcgui04 grant gsi atlasuser@lcgui04.gridpp.rl.ac.uk stat /atlas:scratch/file-1G-via-xrdcp-02
 * 160708 08:59:18 38648 acc_Audit: ijj87.3398491:26@lcgui04 grant gsi atlasuser@lcgui04.gridpp.rl.ac.uk create /atlas:scratch/file-1G-via-xrdcp-02

 * 
 * 
 * 
 ************************************************************************/
static void globus_l_gfs_ceph_recv(globus_gfs_operation_t op,
                                      globus_gfs_transfer_info_t *transfer_info,
                                      void *user_arg) {
  globus_l_gfs_ceph_handle_t *     ceph_handle;

  globus_result_t                     result;
  char *                 func="globus_l_gfs_ceph_recv";
  char *                 _pathname;
  int                 flags;
  const char * operation = "STOR";
  
  GlobusGFSName(globus_l_gfs_ceph_recv);
  ceph_handle = (globus_l_gfs_ceph_handle_t *) user_arg;
  
//  if (transfer_info->alloc_size > 0) {
//      globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,
//          "%s: transfer size = %lu\n", func, transfer_info->alloc_size);
//      ceph_handle->alloc_size = transfer_info->alloc_size;
//  }
  
  const char* pathname_to_test = cleanup_pathname(transfer_info->pathname);
  pathname =  strdup(pathname_to_test);

  globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,
          "%s: started for %s\n", func, pathname_to_test);
  
  globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,
          "%s: rolename == %s, authdbfile = %s\n", func, VO_Role, authdbFilename);
  
  errno = 0;
  
  int allowed = checkAccess(authdbProg, authdbFilename, VO_Role, "wr", pathname_to_test);
   
  if (!allowed) {
    char *error = strerror(errno);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
          "INFO %s: Authorization failure: STOR operation fails: %s\n", func, error);  
    (void)snprintf(errorstr, ERRORMSGSIZE, 
            "Authorization error: operation %s not allowed for role %s on path %s", 
            operation, VO_Role, pathname_to_test);
    result = GlobusGFSErrorGeneric(errorstr);
    
    globus_gridftp_server_finished_transfer(op, result);
    return;
  } else {
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
          "INFO %s: acc.success: 'STOR' operation  allowed\n", func);
  }

  _pathname=strdup(transfer_info->pathname);
  if(_pathname==NULL) {
    result = GlobusGFSErrorGeneric("error: strdup failed");
    globus_gridftp_server_finished_transfer(op, result);
    return;
  }
 
  globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,"%s: pathname now: %s \n", func, _pathname);
//  globus_size_t block_size;
//  globus_gridftp_server_get_block_size(op, &block_size);

//  globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,
//          "%s: block_size from globus_gridftp_server_get_block_size: %d \n", func, block_size);
  
  struct stat64 sbuf;  
  int rc = ceph_posix_stat64(_pathname, &sbuf); // if we use pathname_to_test here, we will needlessly remove first char
  
  flags = O_WRONLY | O_CREAT;
  
  /*
   * The following should be a configuration option, or removed.
   */
  int allow_overwrite = 1;
  
  if (rc == 0) { // File exists
    
    if (allow_overwrite == 1) {
      globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "%s : File %s exists - about to delete\n", __FUNCTION__, _pathname);
      
      rc = ceph_posix_delete(_pathname); 

      if (rc != 0) {
        free(_pathname);
          result = globus_l_gfs_make_error("open/delete");
          globus_gridftp_server_finished_transfer(op, result);
          return;
        }
    } else {
      globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "%s : File %s exists - Not allowing overwrites\n", __FUNCTION__, _pathname);
      free(_pathname);
      result = globus_l_gfs_make_error("open: cannot overwrite");
      globus_gridftp_server_finished_transfer(op, result);
      return;      
    }
  }
  if(transfer_info->truncate) {
    flags |= O_TRUNC;
  }
  /* try to open */

  ceph_handle->fd = ceph_handle_open(_pathname, flags, 0644, ceph_handle);

  if (ceph_handle->fd < 0) {
    errno = EACCES; 
    result=globus_l_gfs_make_error("open/create");
    free(_pathname);
    globus_gridftp_server_finished_transfer(op, result);
    return;
  }

  /* reset all the needed variables in the handle */
  ceph_handle->cached_res = GLOBUS_SUCCESS;
  ceph_handle->outstanding = 0;
  ceph_handle->done = GLOBUS_FALSE;
  ceph_handle->blk_length = 0;
  ceph_handle->blk_offset = 0;
  ceph_handle->op = op;

  globus_gridftp_server_get_block_size(op, &ceph_handle->block_size);
  
  int blksize = getconfigint("GRIDFTP_CEPH_WRITE_SIZE");
  if (blksize > 0) {
     ceph_handle->block_size = blksize; 
  } else {
     globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,"%s: Invalid %s block_size: %ld\n",
          func, "GRIDFTP_CEPH_WRITE_SIZE", blksize);
  } 
  globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,"%s: block size set on ceph_handle: %ld\n",
                         func,ceph_handle->block_size);

  /* here we will save all checksums for the file blocks        */
  /* malloc memory for the first element in the checksum list   */
  /* we should always have at least one block for a file        */
  ceph_handle->checksum_list=
    (checksum_block_list_t *)globus_malloc(sizeof(checksum_block_list_t));
  if (ceph_handle->checksum_list==NULL) {
    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,"ERROR %s: malloc error \n",func);
    globus_gridftp_server_finished_transfer(op, GLOBUS_FAILURE);
    return;
  }
  ceph_handle->checksum_list->next=NULL;
  ceph_handle->checksum_list_p=ceph_handle->checksum_list;
  ceph_handle->number_of_blocks=0;

 
  
  const char* confSize = "GRIDFTP_CEPH_MODE_E_WRITE_SIZE";
    
  int rebuff_size = getconfigint(confSize);
  globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "INFO %s: GRIDFTP_CEPH_MODE_E_WRITE_SIZE = %d\n",
      func, rebuff_size);   
  
  const int lowpower = 20, highpower = 30, defaultpower = 29;
  
  if (rebuff_size >= lowpower && rebuff_size <= highpower) {
    rebuff_size = 1 << rebuff_size;
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
      "INFO %s: buffer size set to %d bytes\n", __FUNCTION__, rebuff_size);    
    
  } else {
    rebuff_size = 1 << defaultpower;
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
      "INFO %s: Invalid setting for %s, Range is %d to %d. Defaulting to 2^%d bytes (%d)\n",
      func, confSize, lowpower, highpower, defaultpower, rebuff_size);
  }   
  
  assembly_t * abuff = (assembly_t *)malloc(sizeof(assembly_t));
  
  ceph_handle->rebuff_size = rebuff_size;
  ceph_handle->active_start = 0;
  ceph_handle->active_end = rebuff_size-1; 
  
  abuff->buffer = (globus_byte_t *)malloc(rebuff_size * sizeof(globus_byte_t)); 
  abuff->nbytes = 0;

  ceph_handle->active_buff = abuff;

  assembly_t * obuff = (assembly_t *)malloc(sizeof(assembly_t));
  
  ceph_handle->overflow_start = rebuff_size;
  ceph_handle->overflow_end = ceph_handle->overflow_start + rebuff_size-1;
  
  obuff->buffer = (globus_byte_t *)malloc(rebuff_size * sizeof(globus_byte_t)); 
  obuff->nbytes = 0;

  
  ceph_handle->overflow_buff = obuff;

  ceph_handle->nblocks_in_range = 0;
  ceph_handle->nblocks_in_overflow = 0;
   
  ceph_handle->nblocks_in_range = 0;
  ceph_handle->nblocks_in_overflow = 0;
  
  
  globus_gridftp_server_begin_transfer(op, 0, ceph_handle);

  globus_mutex_lock(&ceph_handle->mutex);
  {
    globus_l_gfs_ceph_read_from_net(ceph_handle);
  }
  globus_mutex_unlock(&ceph_handle->mutex);
  free(_pathname);
  globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,"%s: finished\n",func);
  return;
}

/*************************************************************************
 *  send
 *  ----
 *  This interface function is called when the client requests to receive
 *  a file from the server.
 *
 *  To send a file to the client the following functions will be used in roughly
 *  the presented order.  They are doced in more detail with the
 *  gridftp server documentation.
 *
 *      globus_gridftp_server_begin_transfer();
 *      globus_gridftp_server_register_write();
 *      globus_gridftp_server_finished_transfer();
 *
 ************************************************************************/
static void globus_l_gfs_ceph_send(globus_gfs_operation_t op,
                                      globus_gfs_transfer_info_t *transfer_info,
                                      void *user_arg) {
  globus_l_gfs_ceph_handle_t *       ceph_handle;
  char * func="globus_l_gfs_ceph_send";
 // char * pathname;
  
  const char* pathname_to_test = cleanup_pathname(transfer_info->pathname);
  
  pathname = strdup(pathname_to_test);
  
  globus_bool_t done;
  globus_result_t result;

  const char * operation = "RETR";

  GlobusGFSName(globus_l_gfs_ceph_send);
  ceph_handle = (globus_l_gfs_ceph_handle_t *) user_arg;
  globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "%s: started\n", func);

  globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,
    "%s: rolename is %s\n", func, VO_Role);

  globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "%s: pathname: %s\n", func, pathname_to_test);

  int allowed = checkAccess(authdbProg, authdbFilename, VO_Role, "rd", pathname_to_test);

  if (!allowed) {
    char *error = strerror(errno);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
      "INFO %s: Authorization failure: 'RETR' operation  fails: %s\n", func, error);

    (void) snprintf(errorstr, ERRORMSGSIZE,
      "Authorization error: operation %s not allowed for role %s on path %s",
      operation, VO_Role, transfer_info->pathname);
    result = GlobusGFSErrorGeneric(errorstr);
    globus_gridftp_server_finished_transfer(op, result);
    return;
  } else {
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
      "INFO %s: acc.success: 'RETR' operation  allowed\n", func);
  }

  /* Check whether the file exists before going any further */
  struct stat64 sbuf;
  int rc = ceph_posix_stat64(transfer_info->pathname, &sbuf);
  if (rc != 0) {
    result = globus_l_gfs_make_error("open/stat64");
    globus_gridftp_server_finished_transfer(op, result);
    return;
  }

  /* mode is ignored */
  ceph_handle->fd = ceph_handle_open(transfer_info->pathname, O_RDONLY,
    0, ceph_handle);

  if (ceph_handle->fd < 0) {
    result = globus_l_gfs_make_error("open");
    globus_gridftp_server_finished_transfer(op, result);
    return;
  }

  /* reset all the needed variables in the handle */
  ceph_handle->cached_res = GLOBUS_SUCCESS;
  ceph_handle->outstanding = 0;
  ceph_handle->done = GLOBUS_FALSE;
  ceph_handle->blk_length = 0;
  ceph_handle->blk_offset = 0;
  ceph_handle->op = op;

  globus_gridftp_server_get_optimal_concurrency(op, &ceph_handle->optimal_count);
  globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "%s: optimal_concurrency: %u\n",
    func, ceph_handle->optimal_count);

  globus_gridftp_server_get_block_size(op, &ceph_handle->block_size);

  int blksize = getconfigint("GRIDFTP_CEPH_READ_SIZE");
  if (blksize > 0) {
    ceph_handle->block_size = blksize;
  } else {
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "%s: Invalid %s block_size: %ld\n",
      func, "GRIDFTP_CEPH_READ_SIZE", blksize);
  }
  globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "%s: block_size: %ld\n",
    func, ceph_handle->block_size);

  /* here we will save all checksums for the file blocks        */
  /* malloc memory for the first element in the checksum list   */
  /* we should always have at least one block for a file        */
  ceph_handle->checksum_list =
    (checksum_block_list_t *) globus_malloc(sizeof (checksum_block_list_t));
  if (ceph_handle->checksum_list == NULL) {
    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "ERROR %s: malloc error \n", func);
    globus_gridftp_server_finished_transfer(op, GLOBUS_FAILURE);
    return;
  }
  ceph_handle->checksum_list->next = NULL;
  ceph_handle->checksum_list_p = ceph_handle->checksum_list;
  ceph_handle->number_of_blocks = 0;

  globus_gridftp_server_begin_transfer(op, 0, ceph_handle);
  done = GLOBUS_FALSE;
  globus_mutex_lock(&ceph_handle->mutex);
  {
    int i;
    for (i = 0; i < ceph_handle->optimal_count && !done; i++) {
      done = globus_l_gfs_ceph_send_next_to_client(ceph_handle);
    }
  }
  globus_mutex_unlock(&ceph_handle->mutex);
  globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "%s: finished\n", func);
}

static globus_bool_t globus_l_gfs_ceph_send_next_to_client
(globus_l_gfs_ceph_handle_t *ceph_handle) {
  globus_result_t                     result;
  globus_result_t                     res;
  globus_off_t                        read_length;
  globus_off_t                        nbread;
  globus_off_t                        start_offset;
  globus_byte_t *                     buffer;
  unsigned long                       adler;
  checksum_block_list_t**             checksum_array;
  checksum_block_list_t *             checksum_list_pp;
  unsigned long                       index;
  unsigned long                       i;
  unsigned long                       file_checksum;
  char                                ckSumbuf[CA_MAXCKSUMLEN+1];
  char                                ckSumbufdisk[CA_MAXCKSUMLEN+1];
  char                                ckSumnamedisk[CA_MAXCKSUMNAMELEN+1];
  char *                              func = "globus_l_gfs_ceph_send_next_to_client";

  GlobusGFSName(globus_l_gfs_ceph_send_next_to_client);

  if (ceph_handle->blk_length == 0) {
    /* check the next range to read */
    globus_gridftp_server_get_read_range(ceph_handle->op,
                                         &ceph_handle->blk_offset,
                                         &ceph_handle->blk_length);
    if(ceph_handle->blk_length == 0) {
      globus_ceph_close(func, ceph_handle, NULL);
      if (ceph_handle->outstanding == 0) {
        globus_gridftp_server_finished_transfer(ceph_handle->op,
                                                ceph_handle->cached_res);
      }
      return ceph_handle->done;
    }
  }

  if (ceph_handle->blk_length == -1 ||
      (globus_size_t)ceph_handle->blk_length > ceph_handle->block_size)
    read_length = ceph_handle->block_size;
  else read_length = ceph_handle->blk_length;

  start_offset = ceph_posix_lseek64(ceph_handle->fd,
                                    ceph_handle->blk_offset,
                                    SEEK_SET);
  /* verify that it worked */
  if (start_offset != ceph_handle->blk_offset) {
    globus_ceph_close(func, ceph_handle, "failed to seek");
    if (ceph_handle->outstanding == 0) {
      globus_gridftp_server_finished_transfer(ceph_handle->op,
                                              ceph_handle->cached_res);
    }
    return ceph_handle->done;
  }

  buffer = globus_malloc(read_length);
  if (buffer == NULL) {
    globus_ceph_close(func, ceph_handle, "internal error (malloc failed)");
    if (ceph_handle->outstanding == 0) {
      globus_gridftp_server_finished_transfer(ceph_handle->op,
                                              ceph_handle->cached_res);
    }
    return ceph_handle->done;
  }
  globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,"%s:%d GLOBUS_MALLOC %p\n", __FUNCTION__, __LINE__, buffer);

  nbread = ceph_posix_read(ceph_handle->fd, buffer, read_length);
  if (nbread>0) {
    
    /* fill the checksum list  */
     
    int added_checksum = add_checksum_to_list(ceph_handle, buffer, ceph_handle->blk_offset, nbread);
    if (added_checksum == GLOBUS_FALSE) {

      ceph_handle->cached_res = GLOBUS_FAILURE;
      globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "ERROR %s: checksum malloc error \n", func);
      globus_free(buffer);
      
      ceph_handle->done = GLOBUS_TRUE;
      globus_mutex_unlock(&ceph_handle->mutex);
 
      globus_gridftp_server_finished_transfer(ceph_handle->op,
                                                ceph_handle->cached_res);    
      return ceph_handle->done;;

    } 
    
  }
  if (nbread == 0) { /* eof */
    result = GLOBUS_SUCCESS;
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,"%s:%d on EOF, GLOBUS_FREE %p\n", __FUNCTION__, __LINE__, buffer); 
    globus_free(buffer);

    /* checksum calculation */
    checksum_array=
      (checksum_block_list_t**)globus_calloc(ceph_handle->number_of_blocks,
                                             sizeof(checksum_block_list_t*));
    if (checksum_array==NULL){
      free_checksum_list(ceph_handle->checksum_list);
      globus_ceph_close(func, ceph_handle, "internal error (malloc failed)");
      if (ceph_handle->outstanding == 0) {
        globus_gridftp_server_finished_transfer(ceph_handle->op,
                                                ceph_handle->cached_res);
      }
      return ceph_handle->done;
    }
    checksum_list_pp=ceph_handle->checksum_list;
    /* sorting of the list to the array */
    index = 0;
    /* the latest block is always empty and has next pointer as NULL */
    while (checksum_list_pp->next != NULL) {
      checksum_array[index] = checksum_list_pp;
      checksum_list_pp=checksum_list_pp->next;
      index++;
    }
    qsort(checksum_array, index, sizeof(checksum_block_list_t*), offsetComparison);
    /* combine here  */
    /* ************* */
    file_checksum=checksum_array[0]->csumvalue;
    for (i=1;i<ceph_handle->number_of_blocks;i++) {
      file_checksum=adler32_combine_(file_checksum,checksum_array[i]->csumvalue,
                                     checksum_array[i]->size);
    }
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"INFO %s: checksum for fd %d : AD %08lx\n",
                           func,ceph_handle->fd,file_checksum);
    globus_free(checksum_array);
    free_checksum_list(ceph_handle->checksum_list);
    
    /* get extended attributes */


    int upgradeChecksum = 0;
    char* storedChecksum = NULL;

    storedChecksum = ceph_posix_get_new_format_checksum_fd(ceph_handle->fd);

    if (storedChecksum != NULL) {

      strncpy(ckSumbufdisk, storedChecksum, CA_MAXCKSUMLEN);
      ckSumbufdisk[CA_MAXCKSUMLEN] = '\0';      
      globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "INFO %s: Found new format checksum XrdCks.adler32 for %s.\n", __FUNCTION__, pathname);
      
    } else {
      
      storedChecksum = ceph_posix_get_old_format_checksum_fd(ceph_handle->fd);

      if (storedChecksum != NULL) {
        
        strncpy(ckSumbufdisk, storedChecksum, CA_MAXCKSUMLEN);
        ckSumbufdisk[CA_MAXCKSUMLEN] = '\0';        
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "INFO %s: Found old format checksum user.checksum.value for %s.\n", __FUNCTION__, pathname);
        upgradeChecksum = 1;  
        
      } 

    }
    snprintf(ckSumbuf, CA_MAXCKSUMLEN+1, "%08lx", file_checksum); // Format computed checksum same way as stored (disk) checksum
    
    if (storedChecksum == NULL|| upgradeChecksum) { // Store the checksum value we calculated reading data from disk
      
      if (upgradeChecksum) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, 
          "INFO %s: Found old format user.checksum.value stored checksum for %s, storing new format checksum XrdCks.adler32 , value =  %s\n", __FUNCTION__, pathname, ckSumbuf);
        
      } else {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, 
          "INFO %s: Cannot find any stored checksum for %s, storing new format checksum XrdCks.adler32 , value =  %s\n", __FUNCTION__, pathname, ckSumbuf);
      }
      
      ceph_posix_set_new_format_checksum_fd(ceph_handle->fd, "adler32", ckSumbuf);
      
    } else { /* we have the stored and the calculated checksums here */
      
      if (strncmp(ckSumbufdisk,ckSumbuf,CA_MAXCKSUMLEN)==0) {
        
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,"%s: checksums OK! \n",func);
        
      } else {
        
        char errorBuf[ERRORMSGSIZE+1];
        (void)snprintf(errorBuf, ERRORMSGSIZE,
                "checksum error detected reading fd: %d (recorded checksum: 0x%s calculated checksum: 0x%s)\n",
                ceph_handle->fd,
                ckSumbufdisk,
                ckSumbuf);
        /* to do something in error case */
        globus_ceph_close(func, ceph_handle, errorBuf);
        ceph_handle->cached_res =
          globus_error_put (globus_object_construct (GLOBUS_ERROR_TYPE_BAD_DATA));
        if (ceph_handle->outstanding == 0) {
          globus_gridftp_server_finished_transfer(ceph_handle->op,
                                                  ceph_handle->cached_res);
        }
        return ceph_handle->done;
      }
    } 
    globus_ceph_close(func, ceph_handle, NULL);
    if (ceph_handle->outstanding == 0) {
      globus_gridftp_server_finished_transfer(ceph_handle->op,
                                              ceph_handle->cached_res);
    }
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"INFO %s: finished (eof)\n",func);
    return ceph_handle->done;
  } // eof
  if (nbread < 0) { /* error */
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,"%s:%d on nbread < 0, GLOBUS_FREE %p\n", __FUNCTION__, __LINE__, buffer);      
    globus_free(buffer);
    globus_ceph_close(func, ceph_handle, "error reading from disk");
    if (ceph_handle->outstanding == 0) {
      globus_gridftp_server_finished_transfer(ceph_handle->op,
                                              ceph_handle->cached_res);
    }
    return ceph_handle->done;
  }

  if (nbread <= read_length) {
    /* if we have a file with size less than block_size we do not have use parrallel connections (one will be enough) */
    ceph_handle->optimal_count--;
  }
  read_length = nbread;

  if (ceph_handle->blk_length != -1) {
    ceph_handle->blk_length -= read_length;
  }

  /* start offset? */
  res = globus_gridftp_server_register_write(ceph_handle->op,
                                             buffer,
                                             read_length,
                                             ceph_handle->blk_offset,
                                             -1,
                                             globus_l_gfs_net_write_cb,
                                             ceph_handle);

  ceph_handle->blk_offset += read_length;

  if(res != GLOBUS_SUCCESS) {
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,"%s:%d, GLOBUS_FREE %p\n", __FUNCTION__, __LINE__, buffer);     
    globus_free(buffer);
    globus_ceph_close(func, ceph_handle, "error writing to network");
    ceph_handle->cached_res = res;
    if (ceph_handle->outstanding == 0) {
      globus_gridftp_server_finished_transfer(ceph_handle->op,
                                              ceph_handle->cached_res);
    }
    return ceph_handle->done;
  }

  ceph_handle->outstanding++;
  return GLOBUS_FALSE;
}

static void globus_l_gfs_net_write_cb(globus_gfs_operation_t op,
  globus_result_t result,
  globus_byte_t *buffer,
  globus_size_t nbytes,
  void *user_arg) {
  
  globus_l_gfs_ceph_handle_t *ceph_handle;
  char *func = "globus_l_gfs_net_write_cb";
  (void) nbytes;
  ceph_handle = (globus_l_gfs_ceph_handle_t *) user_arg;

  globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "%s:%d GLOBUS_FREE %p\n", __FUNCTION__, __LINE__, buffer);
  globus_free(buffer);
  globus_mutex_lock(&ceph_handle->mutex);
  {
    ceph_handle->outstanding--;
    if (result != GLOBUS_SUCCESS) {
      ceph_handle->cached_res = result;
      ceph_handle->done = GLOBUS_TRUE;
    }
    if (!ceph_handle->done) {
      globus_l_gfs_ceph_send_next_to_client(ceph_handle);
    } else if (ceph_handle->outstanding == 0) {
      /* this is a read, we don't care about the checksum */
      globus_ceph_close(func, ceph_handle, NULL);
      globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "INFO %s: finished transfer\n", func);
      globus_gridftp_server_finished_transfer(op, ceph_handle->cached_res);
    }
  }
  globus_mutex_unlock(&ceph_handle->mutex);
}


static int globus_l_gfs_ceph_activate(void);

static int globus_l_gfs_ceph_deactivate(void);

/*
 *  no need to change this
 */
static globus_gfs_storage_iface_t globus_l_gfs_ceph_dsi_iface = {
  GLOBUS_GFS_DSI_DESCRIPTOR_BLOCKING | GLOBUS_GFS_DSI_DESCRIPTOR_SENDER,
  globus_l_gfs_ceph_start,
  globus_l_gfs_ceph_destroy,
  NULL, /* list */
  globus_l_gfs_ceph_send,
  globus_l_gfs_ceph_recv,
  NULL, /* trev */
  NULL, /* active */
  NULL, /* passive */
  NULL, /* data destroy */
  globus_l_gfs_ceph_command,
  globus_l_gfs_ceph_stat,
  NULL, /* set_cred */
  NULL, /* buffer_send */
  NULL  /*realpath */
};

/*
 *  no need to change this
 */
GlobusExtensionDefineModule(globus_gridftp_server_ceph) = {
  "globus_gridftp_server_ceph",
  globus_l_gfs_ceph_activate,
  globus_l_gfs_ceph_deactivate,
  NULL,
  NULL,
  &local_version,
  NULL
};

/*
 *  no need to change this
 */
static int globus_l_gfs_ceph_activate(void) {
//  
  // initialize ceph wrapper log 
  ceph_posix_set_logfunc(ceph_logfunc_wrapper);

  if (getenv("GRIDFTP_USE_ORDERED_DATA") != NULL) {
    
    globus_l_gfs_ceph_dsi_iface.descriptor |= GLOBUS_GFS_DSI_DESCRIPTOR_REQUIRES_ORDERED_DATA;
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "INFO %s: Setting ordered data mode\n", __FUNCTION__);
  
  }
  globus_extension_registry_add(GLOBUS_GFS_DSI_REGISTRY,
    "ceph",
    GlobusExtensionMyModule(globus_gridftp_server_ceph),
    &globus_l_gfs_ceph_dsi_iface);

  return 0;


}




/*
 *  no need to change this
 */
static int globus_l_gfs_ceph_deactivate(void) {
  globus_extension_registry_remove(GLOBUS_GFS_DSI_REGISTRY, "ceph");
  // disconnect from ceph
  ceph_posix_disconnect_all();
  return 0;
}
