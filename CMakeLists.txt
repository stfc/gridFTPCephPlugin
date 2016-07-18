#
#                      gridftp2/CMakeLists.txt
#
# This file is part of the Castor project.
# See http://castor.web.cern.ch/castor
#
# Copyright (C) 2003  CERN
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
#
# Steven.Murray@cern.ch
#
cmake_minimum_required (VERSION 2.6)

set (CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
find_package (globus REQUIRED)
find_package (ceph REQUIRED)
include_directories(${PROJECT_SOURCE_DIR} ${RADOS_INCLUDE_DIR} )

execute_process (COMMAND uname -m OUTPUT_VARIABLE GLOBUS_UNAME)
string (REGEX REPLACE "\n" "" GLOBUS_UNAME ${GLOBUS_UNAME})
message (STATUS "GLOBUS_UNAME = ${GLOBUS_UNAME}")

if ("${GLOBUS_UNAME}" MATCHES "x86_64")
  set (GLOBUS_MOPTION "-m64")
else ()
  set (GLOBUS_MOPTION "-m32")
endif ()

message (STATUS "GLOBUS_MOPTION = ${GLOBUS_MOPTION}")

include_directories(${GLOBUS_CONFINC_PATH} ${GLOBUS_INC_PATH} )
# ${XROOTD_PATH})

#message (XROOTD_LIBS "${XROOTD_LIBS}")

set_property (SOURCE globus_gridftp_server_ceph.c
  PROPERTY COMPILE_FLAGS "${GLOBUS_MOPTION}")
add_library (globus_gridftp_server_ceph SHARED
  globus_gridftp_server_ceph.c ceph_posix.cpp gridftp_authz.c)
target_link_libraries(globus_gridftp_server_ceph ${RADOS_LIBS})
#  ${XROOTD_LIBS})
set_target_properties (globus_gridftp_server_ceph PROPERTIES
  LINK_FLAGS "${GLOBUS_FTPLIB} -lz")
