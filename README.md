# remoteobj

remoteobj is a simple, transparent remote objects hack for CPython2.7

## Theory of operation

1. The client and server do not run in parallel; using remoteobj serializes on the remote side. (Use normal python threading to overcome this if desired.)

2. A proxied object is an object of `remoteobj.Proxy` class that has its \_\_getattribute\_\_ (and other \_\_special\_\_ methods) overwritten with stubs that contact the remote endpoint and block on a response.

3. The marshallable types like `str` and `int` and whatnot are passed by copy. Other types are passed by proxy. This is what keeps remoteobj transparent to most code.

4. Remote exceptions are raised through proxied objects, and are translated to a local Exception subclass of the same name (or just Exception if none exists).

...and then there are some RPC speed hacks & allowances for manual optimization because the naive implementation wasn't fast enough for my purposes.

## FAQ

* Callbacks are supported; remoteobj clients and servers are symmetric.

* There is no built-in security: the client and server get code execution on one another, and so can a man-in-the-middle. Use a TLS socket if you need security.

* There are most certainly deficiencies in the `Proxy` class. I fix them as I encounter them. Particularly, I imagine there are issues with old-style classes.

* Other questions? Go read the code, it's pretty short!

## Limitations

* Proxying does not extend into the type system, e.g. the type of a proxied object as displayed by `type(x)` will be `remoteobj.Proxy`. Of course, built-in types like `str` and `int` are copied and not proxied, so checking those dynamically isn't an issue.

* Previously, remoteobj exposed some CPython bugs and caused segfaults. I haven't checked to see whether those got fixed, but for extra stability the garbage collection integration can be disabled by commenting out Proxy.\_\_del\_\_
