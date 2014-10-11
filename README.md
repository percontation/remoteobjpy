# remoteobj

remoteobj is a remote objects hack for python2.7

It's for replacing a "real solution" when real solutions seem hard. You should be able to throw it in and tear it out with minimal, sometimes zero (!) changes to your codebase.

# Theory of operation

It's super simple (by necessity; who wants to use a thousand lines of hacks???):

1. The client and server do not run in parallel; using remoteobj serializes on the remote side. (Use normal python threading to overcome this if desired.)

2. A proxied object is an object of a `Proxy` class that has every method, even the "\_\_special\_\_" methods, overwritten with stubs that contact the remote endpoint and block on a response.

3. Primitive python types like `str` and `int` and whatnot are always passed by copy and never by proxy. This helps keep the vast majority of code interacting over remoteobj from ever realizing that proxying is happening.

...and then there are some RPC speed hacks & allowances for manual optimization because the naive implementation wasn't fast enough for me.

# FAQ

* There is decent support for exceptions.

* Callbacks are supported; remoteobj clients and servers are symmetric.

* There is no built-in security: the client and server get code execution on one another, and so can a man-in-the-middle. Use a TLS socket if you're going to be using this over a network.

* This is a hack and always will be.

* Still have questions? Go read the code, it's really short!

# Limitations

* Proxying does not extend into the type system, e.g. the type of a proxied object as displayed by `type(x)` will be `remoteobj.Proxy`. This isn't too bad of a limitation, since built-in types like `str` and `int` (that people most often check for) are copied and not proxied.

* Current and past versions of remoteobj are exposing some Python bugs. The garbage collection integration is currently off for this reason. If anyone wants a fun exploitation challenge, check out the version that says "Don't call help()" and call `help()` on a proxied object ^\_^

# History

remoteobj was written because sometimes you really, really want to simulate loading a 32-bit shared object into 64-bit python via ctypes.
