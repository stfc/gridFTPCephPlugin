if os.name == 'posix':
    pathVar = 'LD_LIBRARY_PATH'
elif os.name == 'mac':
    pathVar = 'DYLD_LIBRARY_PATH'
else:
    raise OSError('Unsupported OS : ' + os.name)

if not os.environ.has_key('LD_LIBRARY_PATH'):
    os.environ[pathVar] = os.environ['GLOBUSSYS'] + os.sep + 'lib'
else:
    os.environ[pathVar] = os.environ['GLOBUSSYS'] + os.sep + 'lib' + os.pathsep + os.environ[pathVar]

def globus_url_copy(self):
    return os.environ['GLOBUSSYS'] + os.sep + 'bin' + os.sep + 'globus-url-copy'
Setup.getTag_globus_url_copy = globus_url_copy

def grid_proxy_info(self):
    return os.environ['GLOBUSSYS'] + os.sep + 'bin' + os.sep + 'grid-proxy-info'
Setup.getTag_grid_proxy_info = grid_proxy_info

def gsiFTPURLPrefix(self, nb=0):
    snb = ''
    if nb > 0: snb = str(nb)
    return (lambda test : 'gsiftp://'+self.options.get('Generic','gridFTPServer')+'/')
Setup.getTag_gsiFTPURLPrefix = gsiFTPURLPrefix

def tmpLocalDir(self):
    d = tempfile.mkdtemp(prefix='GridFTPTestSuite')
    print os.linesep+'Temporary files will be stored in directory ' + d
    return d
Setup.getTag_tmpLocalDir = tmpLocalDir

def tmpLocalFileName(self, nb=0):
    return (lambda test : self.getTag(test, 'tmpLocalDir') + os.sep + test + '.' + str(nb))
Setup.getTag_tmpLocalFileName = tmpLocalFileName
