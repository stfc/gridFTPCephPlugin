# - Find xrootd
#
# XROOTD_INCLUDE_DIR        - location of the header files for xrootd
# XROOTD_LIBS               - list of xrootd libraries, with full path
#

# Be silent if XROOTD is already cached
if (XROOTD_INCLUDE_DIR)
  set(XROOTDFIND_QUIETLY TRUE)
endif (XROOTD_INCLUDE_DIR)

find_path (XROOTD_INCLUDE_DIR NAME xrootd) 

find_library (XROOTDSERVER_LIB XrdServer)
find_library (XROOTDUTILS_LIB XrdUtils)
set (XROOTD_LIBS ${XROOTDSERVER_LIB} ${XROOTDUTILS_LIB})

message (STATUS "XROOTD_INCLUDE_DIR        = ${XROOTD_INCLUDE_DIR}")
message (STATUS "XROOTD_LIBS               = ${XROOTD_LIBS}")

include (FindPackageHandleStandardArgs)
find_package_handle_standard_args (xrootd DEFAULT_MSG 
  XROOTD_INCLUDE_DIR
  XROOTD_LIBS)

