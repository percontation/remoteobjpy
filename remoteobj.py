#!/usr/bin/env python
# TODO: Dict/sets/lists should get unpacked to wrappers that are local for read-only access,
#       but update the remote for write access. Note that __eq__ will be an interesting override.
import struct
import socket
import marshal
import zlib
import sys, errno, traceback
from types import FunctionType
from os import urandom
from binascii import hexlify
from hashlib import sha1

__version__ = '0.5.0'

DEBUG = False

# These execeptions are handled differently:
# 1. They're propagated in the process that generated them.
#    (Other exceptions are caught and sent to the remote).
# 2. When receiving these from the remote, they're raised as
#    an Exception() instance instead of their actual class.
EXIT_EXCEPTIONS = (KeyboardInterrupt, SystemExit)

USE_MARSHAL = False

#
# Python 2/3 compat stubs
#

try:
  from os import fsencode, fsdecode
except ImportError:
  def fsencode(x):
    if isinstance(x, unicode):
      return x.encode('utf-8')
    return x
  def fsdecode(x):
    if isinstance(x, unicode):
      # Yep, still an encode. Kinda like how python3 fsdecode
      # will pass through a str, we do unicode -> str.
      return x.encode('utf-8')
    return x

try: long
except NameError: long = int
try: unicode
except NameError: unicode = str

def myprint(*args):
  sys.stderr.write(' '.join(str(i) for i in args) + '\n')

# These are types that are sent across non-proxied.
simple_types = (bool, int, long, float, complex, str, bytes, bytearray, unicode, type(None), type(Ellipsis))
compound_types = (tuple, list, set, frozenset, dict)
all_types = simple_types + compound_types

# remoteobj.py was originally meant for use with marshal, but now I'm
# retrofitting it for cross Python 2.7 / 3.x proxying. Not using marshal
# opens up the door to lots of changes, but, I'm ignoring that for now.
if USE_MARSHAL:
  packing_sentinel = StopIteration
  serialize = marshal.dumps
  deserialize = marshal.loads
else:
  class PackingSentinelType:
    def __repr__(self):
      return 'packing_sentinel'
  packing_sentinel = PackingSentinelType()
  # All of our types repr-eval round trip; and furthermore, this presents an
  # easy method for bytes/str/unicode conversion between python2 and python3.
  def serialize(obj):
    return zlib.compress(fsencode(repr(obj)))
  def deserialize(dat):
    return eval(fsdecode(zlib.decompress(dat)))

objgetattr = object.__getattribute__

class Proxy(object):
  def __init__(self, conn, info, parent=None):
    object.__setattr__(self, '_proxyconn', conn)
    object.__setattr__(self, '_proxyinfo', info)
    object.__setattr__(self, '_proxyparent', parent)
  def __getattribute__(self, attr):
    info = objgetattr(self, '_proxyinfo')
    if attr in info.lazyattrs:
      # We need to retain parent for garbage collection purposes.
      return Proxy(objgetattr(self, '_proxyconn'), info.lazy_getattr(attr), parent=self)
    else:
      return objgetattr(self, '_proxyconn').get(self, attr)

  def __getattr__(self, attr):
    return objgetattr(self, '__getattribute__')(attr)
  def __setattr__(self, attr, val):
    objgetattr(self, '_proxyconn').set(self, attr, val)
  def __delattr__(self, attr):
    objgetattr(self, '_proxyconn').callattr(self, '__delattr__', (attr,), {})
  def __call__(self, *args, **kwargs):
    return objgetattr(self, '_proxyconn').call(self, args, kwargs)
  # TODO: Does this GC still crash python in some cases?
  def __del__(self):
    if objgetattr(self, '_proxyparent') is not None: return
    if not struct or not socket or not marshal or not zlib:
      return # Reduce spurious messages when quitting python
    objgetattr(self, '_proxyconn').delete(self)

  # hash and repr need to be handled specially, due to hash(type) != type.__hash__()
  # (and the same for repr). Incidentally, we'll cache the hash.
  def __hash__(self):
    info = objgetattr(self, '_proxyinfo')
    if info.proxyhash is None:
      info.proxyhash = objgetattr(self, '_proxyconn').hash(self)
    return info.proxyhash
  def __repr__(self):
    return objgetattr(self, '_proxyconn').repr(self)

  # Iter must return an iterator, so it gets special cased.
  def __iter__(self):
    return objgetattr(self, '_proxyconn').iter(self)

  # Truth-testing an object tries __nonzero__, then __len__, then True.
  # Without special casing, a local truth test may raise a remote AttributeError.
  def __nonzero__(self):
    return objgetattr(self, '_proxyconn').bool(self)
  def __bool__(self):
    return objgetattr(self, '_proxyconn').bool(self)

  # Special methods don't always go through __getattribute__, so redirect them all there.
  for special in ('__str__', '__lt__', '__le__', '__eq__', '__ne__', '__gt__', '__ge__', '__cmp__', '__rcmp__', '__unicode__', '__len__', '__getitem__', '__setitem__', '__delitem__', '__reversed__', '__contains__', '__getslice__', '__setslice__', '__delslice__', '__add__', '__sub__', '__mul__', '__floordiv__', '__mod__', '__divmod__', '__pow__', '__lshift__', '__rshift__', '__and__', '__xor__', '__or__', '__div__', '__truediv__', '__radd__', '__rsub__', '__rmul__', '__rdiv__', '__rtruediv__', '__rfloordiv__', '__rmod__', '__rdivmod__', '__rpow__', '__rlshift__', '__rrshift__', '__rand__', '__rxor__', '__ror__', '__iadd__', '__isub__', '__imul__', '__idiv__', '__itruediv__', '__ifloordiv__', '__imod__', '__ipow__', '__ilshift__', '__irshift__', '__iand__', '__ixor__', '__ior__', '__neg__', '__pos__', '__abs__', '__invert__', '__complex__', '__int__', '__long__', '__float__', '__oct__', '__hex__', '__index__', '__coerce__', '__enter__', '__exit__'):
    exec("def {special}(self, *args, **kwargs):\n\treturn objgetattr(self, '_proxyconn').callattr(self, '{special}', args, kwargs)".format(special=special))

class ProxyInfo(object):
  @classmethod
  def isPacked(cls, obj):
    return type(obj) == tuple and len(obj) == 6 and obj[0] == packing_sentinel
  @classmethod
  def fromPacked(cls, obj):
    return cls(obj[1], obj[2], obj[3] or '', obj[4], obj[5] or ())

  def __init__(self, endpoint, remoteid, attrpath = '', proxyhash = None, lazyattrs = (), dbgnote = ''):
    self.endpoint = endpoint
    self.remoteid = remoteid
    self.attrpath = attrpath
    self.proxyhash = proxyhash
    self.lazyattrs = set(lazyattrs)
    self.dbgnote = dbgnote

  def __repr__(self):
    args = [repr(self.endpoint), hex(self.remoteid)]
    for i in ('attrpath', 'proxyhash', 'lazyattrs', 'dbgnote'):
      x = getattr(self, i)
      if x:
        args.append(i + '=' + repr(x))
    return 'ProxyInfo(' + ', '.join(args) + ')'

  def packed(self):
    # Never pack lazyattrs
    return (packing_sentinel, self.endpoint, self.remoteid, self.attrpath or None, self.proxyhash, None)

  def lazy_getattr(self, attr):
    path = self.attrpath+'.'+attr if self.attrpath else attr
    return type(self)(self.endpoint, self.remoteid, attrpath = path)

class Connection(object):
  def __init__(self, sock, secret, endpoint = fsdecode(hexlify(urandom(8)))):
    self.sock = sock
    self.secret = secret
    self.endpoint = endpoint
    self.garbage = []

  def __del__(self):
    # __del__ is gonna ignore all exceptions anyways, but do it quietly
    # for any while closing the socket.
    try: self.sock.close()
    except Exception: pass

  def sendmsg(self, msg):
    x = serialize(msg)
    self.sock.sendall(struct.pack('<I', len(x)))
    self.sock.sendall(x)

  def recvall(self, nbytes):
    if nbytes < 512:
      buf = self.sock.recv(nbytes, socket.MSG_WAITALL)
      while len(buf) < nbytes:
        t = self.sock.recv(nbytes - len(buf))
        if len(t) == 0:
          raise socket.error(errno.ECONNRESET, 'The socket was closed while receiving a message.')
        buf += t
    else:
      buf = bytearray(nbytes)
      view = memoryview(buf)
      i = 0
      while i < nbytes:
        t = self.sock.recv_into(view[i:], nbytes-i, socket.MSG_WAITALL)
        if t <= 0:
          raise socket.error(errno.ECONNRESET, 'The socket was closed while receiving a message.')
        i += t
      buf = memoryview(buf).tobytes()
    return buf

  def recvmsg(self):
    x = struct.unpack('<I', self.recvall(4))[0]
    return deserialize(self.recvall(x))

  # Note: must send after non-info_only packing, or objects will be left with +1 retain count in self.vended
  # TODO: This will get wrecked by recursive sets/lists/dicts; need a more picklish method.
  def pack(self, val, info_only = False, isDictKey = False, limit = None):
    if limit is None:
      limit = sys.getrecursionlimit() / 2
    else:
      limit -= 1

    if limit > 1:
      if type(val) in simple_types:
        return val
      elif type(val) == tuple:
        return tuple(self.pack(i, info_only, limit=limit) for i in val)
      elif type(val) == list:
        return [self.pack(i, info_only, limit=limit) for i in val]
      elif type(val) == set:
        return {self.pack(i, info_only, limit=limit) for i in val}
      elif type(val) == frozenset:
        return frozenset(self.pack(i, info_only, limit=limit) for i in val)
      elif type(val) == dict:
        return {self.pack(k, info_only, isDictKey=True, limit=limit):self.pack(v, info_only, limit=limit) for k,v in val.iteritems()}
      elif type(val) == Proxy:
        return objgetattr(val, '_proxyinfo').packed()

    if not info_only:
      self.vended.setdefault(id(val), [val, 0])[1] += 1
    t = hash(val) if isDictKey else None
    return ProxyInfo(self.endpoint, id(val), proxyhash=t).packed()

  def unpack(self, val, info_only = False):
    if ProxyInfo.isPacked(val):
      info = ProxyInfo.fromPacked(val)
      try:
        if self.endpoint == info.endpoint:
          try:
            obj = self.vended[info.remoteid][0]
          except KeyError:
            if not info_only:
              raise Exception("Whoops, "+self.endpoint+" can't find reference to object "+repr(info.remoteid))
            else:
              info.dbgnote = 'missing local reference'
              return info
          if info.attrpath:
            for i in info.attrpath.split('.'):
              obj = getattr(obj, i)
          return obj
        else:
          return Proxy(self, info) if not info_only else info
      except:
        if not info_only: raise
        info.dbgnote = 'While unpacking, ' + ''.join(traceback.format_exc())
        return info
    elif type(val) == tuple:
      return tuple(self.unpack(i, info_only) for i in val)
    elif type(val) == list:
      return [self.unpack(i, info_only) for i in val]
    elif type(val) == set:
      return {self.unpack(i, info_only) for i in val}
    elif type(val) == frozenset:
      return frozenset(self.unpack(i, info_only) for i in val)
    elif type(val) == dict:
      return {self.unpack(k, info_only):self.unpack(v, info_only) for k,v in val.iteritems()}
    else:
      return val

  def connectProxy(self):
    self.vended = {}
    self.sock.sendall(b'yo')
    chal = urandom(20)
    self.sock.sendall(chal)
    rchal = self.sock.recv(20)
    self.sock.sendall(sha1(self.secret+rchal).digest())
    if self.sock.recv(20) != sha1(self.secret+chal).digest():
      myprint("Server failed challenge!")
      return None

    return self.unpack(self.recvmsg())

  def runServer(self, obj):
    try:
      if self.sock.recv(2) != b'yo':
        myprint("Spurious connection!")
        return
      chal = urandom(20)
      self.sock.sendall(chal)
      rchal = self.sock.recv(20)
      self.sock.sendall(sha1(self.secret+rchal).digest())
      if self.sock.recv(20) != sha1(self.secret+chal).digest():
        myprint("Client failed challenge!")
        return
    except socket.error as e:
      myprint("Socket error while starting!")
      return

    try:
      self.vended = {}
      self.sendmsg(self.pack(obj))
      while self.vended:
        self.handle(self.recvmsg())
    except socket.error as e:
      if e.errno in (errno.EPIPE, errno.ECONNRESET):
        pass # Client disconnect is a non-error.
      else:
        raise
    finally:
      del self.vended
      del self.garbage[:]

  def request(self, msg):
    self.sendmsg(msg)
    while True:
      x = self.recvmsg()
      if DEBUG: myprint(self.endpoint, self.unpack(x, True))
      if x[0] == 'ok':
        return self.unpack(x[1])
      elif x[0] == 'exn':
        exntyp = __builtins__.__dict__.get(x[1]) or globals().get(x[1])
        args = self.unpack(x[2])
        trace = x[3]
        if exntyp is not None and issubclass(exntyp, BaseException) and not issubclass(exntyp, EXIT_EXCEPTIONS):
          if DEBUG: myprint('Remote '+''.join(trace))
          raise exntyp(*args)
        else:
          raise Exception(str(x[1])+repr(args)+'\nRemote '+''.join(trace))
      else:
        self.handle(x)

  def handle(self, msg):
    if DEBUG: myprint(self.endpoint, self.unpack(msg, True))
    try:
      ret = {
        'get' : self.handle_get,
        'set' : self.handle_set,
        'call' : self.handle_call,
        'callattr' : self.handle_callattr,
        'hash' : self.handle_hash,
        'repr' : self.handle_repr,
        'iter' : self.handle_iter,
        'bool' : self.handle_bool,
        'gc' : self.handle_gc,
        'eval' : self.handle_eval,
        'exec' : self.handle_exec,
        'deffun' : self.handle_deffun,
      }[msg[0]](*msg[1:])
      self.sendmsg(('ok', ret))
    except:
      typ, val, tb = sys.exc_info()
      self.sendmsg(('exn', typ.__name__, self.pack(val.args), traceback.format_exception(typ, val, tb)))
      if issubclass(typ, EXIT_EXCEPTIONS):
        raise

  def get(self, proxy, attr):
    info = objgetattr(proxy, '_proxyinfo')
    x, addlazy = self.request(('get', info.packed(), attr))
    if addlazy:
      info.lazyattrs.add(attr)
    return x
  def handle_get(self, obj, attr):
    obj1 = self.unpack(obj)
    attr1 = getattr(obj1, attr)

    # Start of the "addlazy" perf hack, which may lead to incorrect behavior in some cases.
    addlazy = True
    addlazy = addlazy and type(attr1) not in all_types
    try:
      addlazy = addlazy and not isinstance(getattr(obj1.__class__, attr), property)
    except Exception:
      pass

    return self.pack(attr1), addlazy

  def set(self, proxy, attr, val):
    self.request(('set', objgetattr(proxy, '_proxyinfo').packed(), attr, self.pack(val)))
  def handle_set(self, obj, attr, val):
    setattr(self.unpack(obj), attr, self.unpack(val))

  def call(self, proxy, args, kwargs):
    return self.request(('call', objgetattr(proxy, '_proxyinfo').packed(), self.pack(args or None), self.pack(kwargs or None)))
  def handle_call(self, obj, args, kwargs):
    return self.pack(self.unpack(obj)(*(self.unpack(args) or ()), **(self.unpack(kwargs) or {})))

  def callattr(self, proxy, attr, args, kwargs):
    return self.request(('callattr', objgetattr(proxy, '_proxyinfo').packed(), attr, self.pack(args or None), self.pack(kwargs or None)))
  def handle_callattr(self, obj, attr, args, kwargs):
    return self.pack(getattr(self.unpack(obj), attr)(*(self.unpack(args) or ()), **(self.unpack(kwargs) or {})))

  def hash(self, proxy):
    return self.request(('hash', objgetattr(proxy, '_proxyinfo').packed()))
  def handle_hash(self, obj):
    return self.pack(hash(self.unpack(obj)))

  def repr(self, proxy):
    return self.request(('repr', objgetattr(proxy, '_proxyinfo').packed()))
  def handle_repr(self, obj):
    return self.pack(repr(self.unpack(obj)))

  # TODO: Think about a good way to handle this. Maybe use itertools to send like 10 items at a time?
  def iter(self, proxy):
    return iter(self.request(('iter', objgetattr(proxy, '_proxyinfo').packed())))
  def handle_iter(self, obj):
    return self.pack(list(iter(self.unpack(obj))))

  def bool(self, proxy):
    return self.request(('bool', objgetattr(proxy, '_proxyinfo').packed()))
  def handle_bool(self, obj):
    return self.pack(True) if self.unpack(obj) else self.pack(False)

  def delete(self, proxy):
    info = objgetattr(proxy, '_proxyinfo')
    if info.attrpath != '': return
    self.garbage.append(info.packed())
    if len(self.garbage) > 50: # TODO: This number was made up. Find a better one.
      try: self.request(('gc', self.garbage))
      except socket.error: pass # No need for complaints about a dead connection
      del self.garbage[:]
  def handle_gc(self, objs):
    for obj in objs:
      try:
        info = ProxyInfo.fromPacked(obj)
        if info.endpoint != self.endpoint: continue
        assert info.attrpath == ''
        self.vended[info.remoteid][1] -= 1
        if self.vended[info.remoteid][1] == 0:
          del self.vended[info.remoteid]
        elif self.vended[info.remoteid][1] < 0:
          myprint("Too many releases on", self.unpack(obj, True), self.vended[info.remoteid][1])
      except:
        myprint("Exception while releasing", self.unpack(obj, True))
        traceback.print_exc(sys.stderr)

  def close(self):
    # Don't care if we're already disconnected.
    try: self.sock.shutdown(socket.SHUT_RDWR)
    except socket.error: pass
    try: self.sock.close()
    except socket.error: pass
    try: del self.vended
    except AttributeError: pass
    del self.garbage[:]

  def _eval(self, expr, vars = None):
    return self.request(('eval', self.pack(expr), self.pack(vars)))
  def handle_eval(self, expr, vars):
    d = self.unpack(vars)
    _globals = globals().copy()
    if d is not None:
      _globals.update(d)
    ret = eval(self.unpack(expr), _globals)
    return self.pack(ret)

  def _exec(self, stmt, vars = None):
    d = self.request(('exec', self.pack(stmt), self.pack(vars)))
    if vars is not None:
      vars.clear()
      vars.update(d)
  def handle_exec(self, stmt, vars):
    d = self.unpack(vars)
    _globals = globals().copy()
    if d is not None:
      _globals.update(d)
    _locals = {}
    exec(self.unpack(stmt), _globals, _locals)
    if d is None:
      return self.pack({})
    else:
      for k in d:
        if k not in _locals and k in _globals:
          _locals[k] = _globals[k]
      return self.pack(_locals)

  def deffun(self, func, func_globals = (), remote_globals = None):
    """
    Define a function on the remote side. Its __globals__ will be
    the local client-side func.__globals__ filtered to the keys in
    func_globals, underlaid with the remote server-side globals()
    filtered to the keys in remote_globals. None is a special value
    for the filters, and disables any filtering.
    This only works when the __code__ on both ends is compatible; in
    other cases you can use _exec to remotely define the function.
    """
    glbls = {k:v for k,v in func.__globals__.iteritems() if k in func_globals} if func_globals is not None else func.__globals__
    return self.request(('deffun', self.pack((marshal.dumps(func.__code__), glbls, func.__name__, func.__defaults__, func.__closure__)), self.pack(func.__dict__), self.pack(func.__doc__), remote_globals))
  def handle_deffun(self, func, fdict, fdoc, remote_globals):
    func = self.unpack(func)
    g = globals()
    glbls = {k:g[k] for k in remote_globals if k in g} if remote_globals is not None else g.copy()
    glbls.update(func[1])
    func[1].update(glbls)
    f = FunctionType(marshal.loads(func[0]), *func[1:])
    f.__dict__ = self.unpack(fdict)
    f.__doc__ = self.unpack(fdoc)
    return self.pack(f)



__all__ = [Connection,]

# For demo purposes.
if __name__ == "__main__":
  from sys import argv
  if len(argv) <= 3:
    myprint("Usage:", argv[0], "server <address> <port> [<password>]")
    myprint("       python -i", argv[0], "client <address> <port> [<password>]")
    myprint("In the client python shell, the server's module is available as 'proxy'")
    myprint("A good demo is `proxy.__builtins__.__import__('ctypes').memset(0,0,1)`")
    exit(64)

  hostport = (argv[2], int(argv[3]))
  password = fsencode(argv[4] if len(argv) > 4 else 'lol, python')
  if argv[1] == 'server':
    import socketserver
    class Server(socketserver.BaseRequestHandler):
      def handle(self):
        myprint('Accepting client', self.client_address)
        Connection(self.request, password).runServer(sys.modules[__name__])
        myprint('Finished with client', self.client_address)
    socketserver.TCPServer.allow_reuse_address = True
    socketserver.TCPServer(hostport, Server).serve_forever()
    exit(1)
  elif argv[1] == 'client':
    connection = Connection(socket.create_connection(hostport), password)
    proxy = connection.connectProxy()
    myprint("`proxy` and `connection` are available for you to play with at the interactive prompt.")
  else:
    exit(64)
