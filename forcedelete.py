#!/usr/bin/python
#########################################################################
#
# Delete all chunks of an object
#
# Alastair Dewhurst, Scientific Computing Department, STFC RAL
# Ian Johnson, Scientific Computing Department, STFC RAL
#
#########################################################################

import sys, math
import rados
import tempfile
import os

def plog(file, arg):
	print >> file, arg

def main(argv):
       
    flog = tempfile.NamedTemporaryFile(prefix='delete_log_', delete=False)
    plog(flog.file, [arg for arg in argv])
    
    configfile = argv[1]	
    pool = argv[2]
    objname = argv[3]

    try:
        cluster = rados.Rados(conffile=configfile, name = 'client.gridftp')
        cluster.connect()
        ioctx = cluster.open_ioctx(pool)
 
    except Exception as e:
        plog(flog.file, str(e))
        sys.exit(-1)
    
    chunk0 = objname + '.0000000000000000'
    limit = 0

# Get filesize from first chunk

    try:
       	filesize = int(ioctx.get_xattr(chunk0, "striper.size"))
        chunksize = int(ioctx.get_xattr(chunk0, "striper.layout.object_size"))
        
        if (filesize == 0 or chunksize == 0):
            filesize = 10 * 1024
            chunksize = 64
                   	       	
    except Exception as e:
        filesize = 10 * 1024
        chunksize = 64
        
    limit = int(math.ceil(filesize / chunksize)+1)  	      	
    plog(flog.file, "About to delete " + str(limit) + " chunks.")
    	
       		
# Delete all the chunks

    n_chunks = 0
    
    for i in range(0, limit):
      	n = hex(i)[2:]
       	chunk = objname + '.' + n.zfill(16)
       	
       	try:
       		ioctx.remove_object(chunk)
       		n_chunks += 1
       	except:
            pass

    plog(flog.file, "n_chunks removed = " + str(n_chunks))
    ioctx.close()
    cluster.shutdown()
    
    if n_chunks == 0:
    	return -2
    else:
    	return 0

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print "Usage: forcedelete conf pool object"
        sys.exit(-1)

    main(sys.argv)
    
    
