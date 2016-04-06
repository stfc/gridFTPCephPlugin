_objects_created = set([])

def objectName(self, nb=0):
    #_objects_created.add(objName)
    return (lambda test : test+str(nb))
Setup.getTag_objectName = objectName

def cephUserId(self):
    return self.options.get('Generic','cephUserId')
Setup.getTag_cephUserId = cephUserId

def cephPool(self):
    return self.options.get('Generic','cephPool')
Setup.getTag_cephPool = cephPool

#def cephCleanup(self):
    
#Setup.cleanup_ceph = ceph_cleanup
