# TODO: Switch to an stdio based method instead of needing to TCP server.
import remoteobj
import socket

if __name__ == "__main__":
  # Server
  try:
    from sys import argv
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(argv[1])
    remoteobj.Connection(sock, argv[2]).runServer(__import__('ctypes'))
  except:
    print 'The remotectypes32 process is angrily exiting.'
    raise
else:
  # Client
  import sys, os, time, subprocess, atexit
  secret = os.urandom(20).encode('hex')
  sockpath = '/tmp/remotectypes32.sock'+os.urandom(4).encode('hex')

  atexit.register(os.remove, sockpath)

  sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
  sock.bind(sockpath)
  sock.listen(1)


  if 'PYTHON32' in os.environ:
    python32 = (os.environ['PYTHON32'],)
  elif sys.platform == 'darwin':
    python32 = ('/usr/bin/arch', '-i386', '/System/Library/Frameworks/Python.framework/Versions/Current/bin/python2.7')
  else:
    raise Exception('Set env variable PYTHON32 to an i386 python.')

  p = subprocess.Popen(python32+(__file__, sockpath, secret))

  conn, addr = sock.accept()
  ctypes = remoteobj.Connection(conn, secret).connectProxy()

  # Make `from remotectypes32 import *` work as expected
  __all__ = []
  d = ctypes.__dict__
  for k in d:
    if k.startswith('__') and k.endswith('__'): continue
    v = d[k]
    locals()[k] = v
    __all__.append(k)
