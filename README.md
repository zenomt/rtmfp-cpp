Secure Real-Time Media Flow Protocol Library
============================================
This is a C++11 implementation of the Secure Real-Time Media Flow Protocol
(RTMFP) as described in [RFC 7016][]. This library is currently a
**WORK IN PROGRESS**. There are probably bugs still, and there is lots of
room for optimization.

The library includes sample Platform Adapters and other utilities, such as a
simple `select()` based run loop, but these are not required to be used. The
protocol implementation is intended to be adaptable to any host program
environment.

The library is intended for clients, servers, and P2P applications. It includes
the necessary helpers and callbacks to support P2P introduction and load
balancing.

The [`test`](test/) directory includes unit tests and examples. Of special
note is [`tcrelay`](test/tcrelay.cpp), an RTMFP ←→ RTMP relay/proxy.

How to Use
----------
The most complete API documentation is currently in the
[`rtmfp.hpp`](include/rtmfp/rtmfp.hpp) header file.

An application will instantiate an `IPlatformAdapter` and an `ICryptoAdapter`,
then a `com::zenomt::rtmfp::RTMFP` (which requires these adapters).  Typically
the platform adapter will need to be told of the new `RTMFP` instance so it
can invoke the instance’s platform methods (such as `howLongToSleep()` and
`onReceivePacket()`).

The platform will add at least one *interface* by calling `RTMFP::addInterface()`.

The application can open sending flows to new or current endpoints with
`RTMFP::openFlow()` and `Flow::openFlow`, and can open associated return flows
with `RecvFlow::openReturnFlow()`.

The application can accept new flows by implementing the `onRecvFlow` callbacks
on the `RTMFP` (for bare incoming flows) or on `SendFlow`s (for associated
return flows).

The application can send messages to far peers with `SendFlow::write()`, and
receive messages from far peers by implementing the `onMessage` callback on
`RecvFlow`s.  Messages can expire and be abandoned if not started or delivered
by per-message deadlines, or by arbitrary application logic using the
[`WriteReceipt`](include/rtmfp/WriteReceipt.hpp)s returned by `SendFlow::write()`.
The application can be notified by callback when a message is delivered or
abandoned.

`SendFlow`s set to priority `PRI_4` or higher (`PRI_PRIORITY`, `PRI_IMMEDIATE`,
`PRI_FLASH`, and `PRI_FLASHOVERRIDE`) are considered
[time critical](https://tools.ietf.org/html/rfc7016#section-3.1). Sending
messages on time critical flows affects congestion control.

When it’s done, the application can shut down the `RTMFP` in an orderly manner
or abruptly.

### Threading Model
The protocol implementation is single-threaded and has no locks/mutexes. All
calls to its APIs must be externally synchronized, for example by all being
in the same thread or run-loop-like construct. This was done to improve
portability and performance, since locking can be very expensive on modern
CPUs. Synchronization is abstracted by the Platform Adapter’s `perform` method
to allow for offloading some expensive or time-consuming operations to other
cores/threads, if desired.

### Platform Adapter
The protocol implementation doesn’t directly interact with the operating
system’s UDP sockets, clock, run loops, locks, or threads. These interactions
are abstracted to a *Platform Adapter* provided by the host program.

The *Platform Adapter* will be a concrete implementation of
[`com::zenomt::rtmfp::IPlatformAdapter`](include/rtmfp/rtmfp.hpp), that calls
the `RTMFP` public instance methods in its “Used by the Platform Adapter”
section.  The adapter provides the current time, reading and writing to
sockets, timing, and synchronization.

The library provides two example platform adapters that run in
[`RunLoop`](include/rtmfp/RunLoop.hpp)s:
[`PosixPlatformAdapter`](include/rtmfp/PosixPlatformAdapter.hpp) for pure
single-threaded applications, and
[`PerformerPosixPlatformAdapter`](include/rtmfp/PerformerPosixPlatformAdapter.hpp) to
allow for offloading CPU-intensive public-key cryptography to a worker thread.
These platform adapters should be suitable for many applications and should
serve as examples of how to write single-threaded and multi-threaded platform
adapters for your host application.

There is no requirement for *Platform Adapter’s* interfaces to be UDP sockets.
For example, an *interface* could be a SOCKS proxy, tunnel, or network
simulator.

#### RunLoop and Performer
This library provides a [simple `select()` based](include/rtmfp/SelectRunLoop.hpp)
[run loop](include/rtmfp/RunLoop.hpp) suitable for many socket-based applications.

A [`Performer`](include/rtmfp/Performer.hpp) can be attached to a run loop
to enable invoking a task inside/synchronized with the run loop from any
thread. `Performer`s are used with the `PerformerPosixPlatformAdapter`.

### Cryptography Adapter
[RFC 7016][] describes a generalized framework for securing RTMFP communication
according to the needs of the application, and leaves cryptographic specifics
to a *Cryptography Profile*. This library doesn’t lock its application to any
particular cryptography profile, and is written to support many potential
profiles. The cryptography profile is implemented by a concrete
[`ICryptoAdapter`](include/rtmfp/rtmfp.hpp) provided to the `RTMFP` on
instantiation.

Most applications of RTMFP will use the
[*Cryptography Profile for Flash Communication* described in RFC 7425][RFC 7425].
This is provided by the [`FlashCryptoAdapter`](include/rtmfp/FlashCryptoAdapter.hpp).
Note that this adapter is abstract and must be subclassed to provide concrete
implementations of the required cryptographic primitives. A
[concrete implementation](src/FlashCryptoAdapter_OpenSSL.cpp) using OpenSSL is
provided by
[`FlashCryptoAdapter_OpenSSL`](include/rtmfp/FlashCryptoAdapter_OpenSSL.hpp),
which can also serve as an example for how to use other cryptography
libraries. If you don’t have OpenSSL or you don’t want to use it, you can suppress
building this module by defining `make` variable `WITHOUT_OPENSSL`. If your
OpenSSL is installed outside of your compiler’s default include and linker
search paths, you can define `make` variables `OPENSSL_INCLUDEDIR` and
`OPENSSL_LIBDIR` with appropriate directives (see the [`Makefile`](Makefile)
for examples).

The OpenSSL implementation of the `FlashCryptoAdapter` implements
[4096-bit Internet Key Exchange (IKE) Group 16][MODP 4096],
[2048-bit IKE Group 14][MODP 2048], and [1024-bit IKE Group 2][MODP 1024] for
Diffie-Hellman key agreement. All implementations of the
Flash Communication cryptography profile
[**MUST** implement at least Group 2](https://tools.ietf.org/html/rfc7425#section-4.2);
some also implement Group 14. This implementation prefers the strongest
common group.

Note that RTMFP is not limited to Flash platform communication.  This library
provides a [`PlainCryptoAdapter`](include/rtmfp/PlainCryptoAdapter.hpp)
suitable for testing and evaluation. As it provides no actual cryptography
(and its `cryptoHash256()` and `pseudoRandomBytes()` methods are especially
weak), it is not suitable for production use in the open Internet. Don’t.


To Do
-----
* SendFlow unsent low water mark
* More documentation
* More unit tests
* More examples
* Performance counters
* Persistent no-acks on buffer probes should be a timeout (eventually kill session)

  [MODP 1024]: https://tools.ietf.org/html/rfc7296#appendix-B.2
  [MODP 2048]: https://tools.ietf.org/html/rfc3526#section-3
  [MODP 4096]: https://tools.ietf.org/html/rfc3526#section-5
  [RFC 7016]: https://tools.ietf.org/html/rfc7016
  [RFC 7425]: https://tools.ietf.org/html/rfc7425
