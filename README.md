Secure Real-Time Media Flow Protocol Library
============================================
This is a C++ (11) implementation of the Secure Real-Time Media Flow Protocol
(RTMFP) as described in [RFC 7016][].

The library includes sample Platform Adapters and other utilities, such as a
simple `select()` based run loop, but these are not required to be used. The
protocol implementation is intended to be adaptable to any host program
environment.

The library is intended for clients, servers, and P2P applications. It includes
the necessary helpers and callback hooks to support P2P introduction and load
balancing.

The [`test`](test/) directory includes unit tests and examples. Of special
note are [`tcserver`](test/tcserver.md), a simple RTMFP and RTMP live media
server; [`tcrelay`](test/tcrelay.cpp), an RTMFP ↔︎ RTMP relay/proxy; and
[`redirector`](test/redirector.cpp), a simple load balancer.

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

The application can accept new flows by setting the `onRecvFlow` callbacks
on the `RTMFP` (for bare incoming flows) or on `SendFlow`s (for associated
return flows).

The application can send messages to far peers with `SendFlow::write()`, and
receive messages from far peers by setting the `onMessage` callback on
`RecvFlow`s.  Messages can expire and be abandoned if not started or delivered
by per-message deadlines, or by arbitrary application logic using the
[`WriteReceipt`](include/rtmfp/WriteReceipt.hpp)s returned by `SendFlow::write()`.
The application can be notified by callback when a message is delivered or
abandoned.

`SendFlow`s set to [priority](include/rtmfp/Priority.hpp) `PRI_PRIORITY` (`PRI_4`)
or higher (`PRI_IMMEDIATE`, `PRI_FLASH`, and `PRI_FLASHOVERRIDE`) are considered
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
For example, an *interface* could be a SOCKS or TURN proxy, tunnel, or network
simulator.

#### RunLoop and Performer
This library provides a [simple `select()` based](include/rtmfp/SelectRunLoop.hpp)
[run loop](include/rtmfp/RunLoop.hpp) suitable for many socket-based applications.
It also includes a [simple `epoll` based run loop](include/rtmfp/EPollRunLoop.hpp)
for Linux that scales better than `select()` for handling many sockets. Use the
[`PreferredRunLoop` alias](include/rtmfp/RunLoops.hpp) to automatically choose the
best variant available at compile time for the target OS.

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

Delay-Based Congestion Detection
--------------------------------
[Bufferbloat](https://www.bufferbloat.net) (excessive buffering and queuing
in the network) can cause high end-to-end delays resulting in unacceptable
performance for real-time applications. Unfortunately, the best solution to
this problem
([Active Queue Management](https://datatracker.ietf.org/doc/html/rfc7567)
with
[Explicit Congestion Notification](https://datatracker.ietf.org/doc/html/rfc3168))
is not universally deployed in the Internet at this time.

In addition to the normal congestion signals (loss and Explicit Congestion
Notification), this library can optionally infer likely congestion on a session
from increases in Round-Trip Time (RTT). To enable this capability, use
`Flow::setSessionCongestionDelay()` to set an amount of additional delay above
the baseline RTT to be interpreted as an indication of congestion.  The default
value is `INFINITY`. A value of `0.1` seconds of additional delay is suggested
for this feature.

The baseline RTT is the minimum RTT observed over at most the past three
minutes. The baseline RTT observation window is cleared and reset in the
following circumstances:

  * On a
    [timeout](https://datatracker.ietf.org/doc/html/rfc7016#section-3.5.2.2)
    (either from total loss or no data to send);
  * If the congestion window falls to the minimum value,
    which might happen after persistent inferred congestion that isn't actually
    our fault (such as from a change to the path or from competing traffic);
  * If the far end’s address changes;
  * If our address might have changed (inferred from receipt of a non-empty Ping,
    which might be an
    [address change validation probe](https://datatracker.ietf.org/doc/html/rfc7016#section-3.5.4.2)
    from the far end).

From time-to-time, if a significant portion of the congestion window is being
used, the congestion window will be temporarily reduced in order to probe the
path for a new baseline RTT (in case our own sending is masking the baseline).
Note that this can cause jitter.

If the Smoothed RTT is observed to be above the baseline plus the configured
`CongestionDelay` (and is also at least 30ms), this is assumed to be an
indication of congestion. The congestion controller responds to this as though
it was loss.

This congestion detection scheme, like all end-to-end delay-based ones, is
imperfect, and is subject to false positive signals caused by cases including:

  * Additional delay caused by data from the other end of this session;
  * Additional delay caused by delay-insensitive queue-filling transmissions
    competing through the bottleneck in either direction;
  * Changes to the return direction of the path that delay RTT measurements.

As such, this feature may not be indicated for all use cases. Care should be
taken to enable this feature only when false positive congestion signals are
unlikely, such as for substantially unidirectional media transmission through
a dedicated bottleneck. False positives can cause transmission starvation.

This feature is inspired by
[Low Extra Delay Background Transport (LEDBAT)](https://datatracker.ietf.org/doc/html/rfc6817),
[Self-Clocked Rate Adaptation for Multimedia (SCReAM)](https://datatracker.ietf.org/doc/html/rfc8298),
and
[Google’s BBR congestion control algorithm](https://github.com/google/bbr).


Explicit Congestion Notification
--------------------------------
This implementation of RTMFP adds support for Explicit Congestion
Notification (ECN). It adds a new experimental chunk “ECN Report” (type `0xec`) for the
receiver to send counts of received ECN codepoints back to the ECN sender.
An RTMFP **MUST NOT** send an ECN Report to its peer unless it has received
at least one valid packet in its `S_OPEN` session with that peer that is
marked with an ECN Capable Transport code point (`ECT(0)`, `ECT(1)`, or
`ECN-CE`).

An RTMFP receiver that is ECN-capable sends ECN Reports to its ECN-capable
peer.  ECN Reports **SHOULD** be assembled before the first Acknowledgement
chunk in any packet containing an Acknowledgement (to avoid truncation of the
report). In order that the ECN sender can detect whether the near and far
interfaces, path, and receiver support ECN, an ECN-capable receiver **SHOULD**
send an ECN Report in any packet that contains an Acknowledgement, if any
packet marked with an ECN Capable Transport code point has been received
either since the last time an ECN Report was sent or if a report has not yet
been sent.

An RTMFP sender **MUST** stop marking packets with ECN Capable Transport code
points if it determines that the receiver is not ECN-capable (for example,
if the sender has not received at least one ECN Report along with an
Acknowledgement for User Data that was sent in a marked packet during the
open session with the peer).

An ECN-capable RTMFP receiver keeps at least a count of the number of packets
received marked with `ECN-CE`. The endpoint sends the low 8 bits of the current
counter to its peer in ECN Report chunks.

This implementation sends `ECT(0)`.  The congestion controller responds to
increases of the `ECN-CE-count` as though it was loss. `ECT(0)` is only sent
on packets containing User Data.

### Explicit Congestion Notification Report Chunk (ECN Report)

	 0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|      0xec     |               1               | ECN-CE-count  |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	
	struct ecnReportChunkPayload_t
	{
	    uint8_t congestionExperiencedCountMod256; // ECN-CE-count
	} :8;

- `congestionExperiencedCountMod256`: The low 8 bits of the count of packets
  received from the peer marked with `ECN-CE` (ECN Congestion Experienced).

To Do
-----
* SendFlow unsent low water mark
* More documentation
* More unit tests
* Performance counters
* Persistent no-acks on buffer probes should be a timeout (eventually kill session)

  [MODP 1024]: https://tools.ietf.org/html/rfc7296#appendix-B.2
  [MODP 2048]: https://tools.ietf.org/html/rfc3526#section-3
  [MODP 4096]: https://tools.ietf.org/html/rfc3526#section-5
  [RFC 7016]: https://tools.ietf.org/html/rfc7016
  [RFC 7425]: https://tools.ietf.org/html/rfc7425
