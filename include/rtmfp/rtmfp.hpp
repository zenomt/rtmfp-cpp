#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

// Implemenation of the Secure Real-Time Media Flow Protocol (RTMFP) as
// described in RFC 7016. Section references ("§") refer to that document.

#include <cmath>
#include <map>

#include "Timer.hpp"
#include "List.hpp"
#include "IndexSet.hpp"
#include "Address.hpp"

namespace com { namespace zenomt { namespace rtmfp {

class SendFlow; class RecvFlow; class WriteReceipt;
class IPlatformAdapter;
class ICryptoAdapter; class SessionCryptoKey; class CryptoCert;
class Interface; class ISession; class Session; class StartupSession;
struct PacketAssembler;

using Bytes = std::vector<uint8_t>;

const int NUM_PRIORITIES = 8;
enum Priority {
	// Priorities 4 and higher are considered Time Critical. Currently implemented as precedence.
	PRI_0 = 0, PRI_1, PRI_2, PRI_3, PRI_4, PRI_5, PRI_6, PRI_7,
	PRI_LOWEST = PRI_0, PRI_HIGHEST = NUM_PRIORITIES - 1,
	PRI_BACKGROUND = PRI_LOWEST, PRI_BULK = PRI_1, PRI_DATA = PRI_2, PRI_ROUTINE = PRI_3,
	PRI_PRIORITY = PRI_4, PRI_IMMEDIATE = PRI_5, PRI_FLASH = PRI_6, PRI_FLASHOVERRIDE = PRI_7
};
enum ReceiveOrder {
	RO_SEQUENCE, // Original queuing order
	RO_NETWORK,  // Network arrival order
	RO_HOLD      // Suspend delivery
};
enum FIHelloResponseMode { FI_SEND_RHELLO, FI_SEND_REDIRECT, FI_IGNORE };
const int INTERFACE_ID_ALL = -1;

class RTMFP : public Object {
public:
	RTMFP(IPlatformAdapter *platformAdapter, ICryptoAdapter *cryptoAdapter);
	RTMFP() = delete;
	~RTMFP();

	// Open a new flow to Endpoint Discriminator epd having metadata with initial priority pri.
	// Returns an empty shared_ptr on error.
	std::shared_ptr<SendFlow> openFlow(const void *epd, size_t epdLen, const void *metadataBytes, size_t metadataLen, Priority pri = PRI_ROUTINE);
	std::shared_ptr<SendFlow> openFlow(const Bytes &epd, const Bytes &metadata, Priority pri = PRI_ROUTINE);

	// Called when a new non-associated receiving flow starts. flow must
	// be accepted during this callback or it will be rejected automatically.
	std::function<void(std::shared_ptr<RecvFlow> flow)> onRecvFlow;

	// Shut down this RTMFP. If immediately is false, attempt an orderly close of all
	// open sessions. If immediately is true, abruptly close all sessions.
	// platform->onShutdownComplete() will be called when all sessions have been closed.
	void shutdown(bool immediately = false);

	// Called when an IHello (§2.3.2) is received having an Endpoint Discriminator that does
	// not select this endpoint according to cryptoAdapter->isSelectedByEPD(). Used by
	// Forwarders/Redirectors §3.5.1.4, §3.5.1.5, §3.5.1.6.
	std::function<void(const void *epd, size_t epdLen, const void *tag, size_t tagLen, int interfaceID, const struct sockaddr *srcAddr)> onUnmatchedIHello;

	// Send a Responder Redirect to dstAddr via interfaceID. §2.3.5, §3.5.1.1.1, §3.5.1.1.2, §3.5.1.4.
	// use INTERFACE_ID_ALL to send the Redirect on all interfaces.
	void sendResponderRedirect(const void *tag, size_t tagLen, const std::vector<Address> &addrs, int interfaceID, const struct sockaddr *dstAddr);

	// New sessions inherit these values when transitioning to S_OPEN.
	void setDefaultSessionKeepalivePeriod(Time keepalive);
	Time getDefaultSessionKeepalivePeriod() const;

	void setDefaultSessionRetransmitLimit(Time limit);
	Time getDefaultSessionRetransmitLimit() const;

	void setDefaultSessionIdleLimit(Time limit);
	Time getDefaultSessionIdleLimit() const;

	Time getCurrentTime() const; // Convenience method calls the platform adapter.
	Time getInstanceAge() const; // Answer how many seconds since this RTMFP was created.

	// --- Used by the Platform Adapter

	// Answers how long until doTimerWork() should be called.
	Time howLongToSleep() const;

	// The platform must call this function ASAP after howLongToSleep() seconds.
	void doTimerWork();

	// Add a new platform interface to this RTMFP. An RTMFP must have at least one interface.
	// interfaceID is a non-negative integer meaningful to the Platform Adapter. It need not
	// be a socket file descriptor.
	void addInterface(int interfaceID);
	// void removeInterface(int interfaceID); // TODO: someday. what do we do with sessions bound to the interface?

	// The platform calls this method when a new packet for this RTMFP is received.
	// Answers true if this packet was for this instance, false if not recognized (for further processing)
	bool onReceivePacket(const void *bytes, size_t len, int interfaceID, const struct sockaddr *addr);

protected:
	friend class Interface;
	friend class StartupSession;
	friend class Session;
	friend class ISession;
	friend class SendFlow;
	friend class RecvFlow;

	bool scheduleWrite(int interfaceID, std::shared_ptr<ISession> session, int pri);
	unsigned long getNextThreadNum();
	std::shared_ptr<Timer> scheduleRel(Time delta, Time recurInterval = 0);
	uint16_t getCurrentTimestamp() const;
	Bytes makeCookie(const struct sockaddr *addr) const;
	enum CookieCheck { COOKIE_BAD, COOKIE_MISMATCH, COOKIE_OK };
	CookieCheck checkCookie(const uint8_t *cookie, size_t cookieLen, const struct sockaddr *addr) const;
	void sendCookieChange(uint32_t sessionID, const uint8_t *cookie, size_t cookieLen, int interfaceID, const struct sockaddr *addr);
	std::shared_ptr<Session> makeSession(std::shared_ptr<SessionCryptoKey>, unsigned role);
	std::shared_ptr<Session> findOpeningSessionByAddress(const Address &addr);
	std::shared_ptr<Session> findOpeningSessionByEPD(const Bytes &epd, const Session *exclude);
	std::shared_ptr<Session> findOpeningSessionByTag(const Bytes &epd);
	std::shared_ptr<Session> findOpenSessionByAddress(const Address &addr);
	std::shared_ptr<Session> findOpenSessionByEPD(const Bytes &epd);
	void makeRIKeyingChunk(Bytes &dst, uint32_t rsid, const Bytes &skrc, Bytes &skic, std::shared_ptr<CryptoCert> recipient);
	bool tryRIKeyingRetransmit(int interfaceID, const Address &addr, uint32_t isid, const Bytes &skic);
	void onSessionDidOpen(std::shared_ptr<Session> session);
	void onSessionWillOpen(std::shared_ptr<Session> session);
	void onSessionDidClose(std::shared_ptr<Session> session, bool releaseSessionID);
	void onSessionAddressDidChange(std::shared_ptr<Session> session, const Address &oldAddr);
	void onSessionReceivedTC(const void *session);
	bool shouldSessionReportTCR(const void *session) const;
	void sendFlowIsNotOpening(const std::shared_ptr<SendFlow> &flow);
	void checkShutdownComplete();

	void onIHello(const uint8_t *epd, size_t epdLen, const uint8_t *tag, size_t tagLen, int interfaceID, const struct sockaddr *addr, FIHelloResponseMode mode);
	void onRHello(const uint8_t *tag, size_t tagLen, const uint8_t *cookie, size_t cookieLen, const uint8_t *cert, size_t certLen, int interfaceID, const struct sockaddr *addr);
	void onIIKeying(uint32_t initiatorSessionID, const uint8_t *cookie, size_t cookieLen, const uint8_t *cert, size_t certLen, const uint8_t *skic, size_t skicLen, const uint8_t *signedParams, size_t signedParamsLen, const uint8_t *sig, size_t sigLen, int interfaceID, const struct sockaddr *addr);
	void onRedirect(const uint8_t *tag, size_t tagLen, const std::vector<Address> &redirectDestinations);

	IPlatformAdapter *m_platform;
	ICryptoAdapter   *m_crypto;

	Time              m_epoch;
	TimerList         m_timers;
	uint8_t          *m_plaintextBuf;
	uint8_t          *m_ciphertextBuf;
	uint8_t           m_secret[512/8]; // block size of SHA256
	unsigned long     m_nextThreadNum;
	std::atomic_long  m_waitingPerformCount;
	uintptr_t         m_sessionReportingTC;
	Time              m_sessionTC_time;
	Time              m_previous_sessionTC_time;
	Time              m_tc_sent_time;

	Time              m_default_session_keepalive_period;
	Time              m_default_session_retransmit_limit;
	Time              m_default_session_idle_limit;
	bool              m_shutdown;
	bool              m_shutdownComplete;

	std::map<int, std::shared_ptr<Interface> >   m_interfaces;
	List<std::shared_ptr<Session> >              m_sessions;
	std::map<Address, std::shared_ptr<Session> > m_openSessionsByAddress;
	std::map<Bytes, std::shared_ptr<Session> >   m_openSessionsByCanonicalEPD;
	List<std::shared_ptr<Session> >              m_openingSessions;
	List<std::shared_ptr<SendFlow> >             m_openingFlows;
	std::shared_ptr<StartupSession>              m_startupSession;
};

class Flow : public Object {
public:
	// Open a new flow in the same S_OPEN session. Returns an empty shared_ptr on error.
	std::shared_ptr<SendFlow> openFlow(const void *metadataBytes, size_t metadataLen, Priority pri = PRI_ROUTINE);
	std::shared_ptr<SendFlow> openFlow(const Bytes &metadata, Priority pri = PRI_ROUTINE);

	virtual bool isOpen() const; // Answers true if this flow hasn't been closed (manually/exception/error).
	virtual void close(); // Close this flow. No callbacks on this flow will be called after this.

	void    closeSession(); // Close the session to which this flow belongs. Does not count as closing this flow.

	// These are all properties of the session.
	Bytes   getNearNonce()        const; // §3.5
	Bytes   getFarNonce()         const;
	Bytes   getFarCertificate()   const;
	Bytes   getFarCanonicalEPD()  const; // §3.2
	Address getFarAddress()       const; // §3.5 DESTADDR. Is there any need for the interface ID?
	Time    getSRTT()             const; // Smoothed round-trip time per §3.5.2.2.
	Time    getRTTVariance()      const; // Round-trip time variance §3.5.2.2.
	size_t  getCongestionWindow() const;

	void    setSessionKeepalivePeriod(Time keepalive); // Idle time before a keepalive check is performed.
	Time    getSessionKeepalivePeriod() const;
	void    setSessionRetransmitLimit(Time limit); // Time after which a retransmitting session will terminate.
	Time    getSessionRetransmitLimit() const;
	void    setSessionIdleLimit(Time limit); // Time after which a quiescent session with no flows will terminate.
	Time    getSessionIdleLimit() const;

	// Send an FIHello §2.3.3, §3.5.1.5
	bool forwardIHello(const void *epd, size_t epdLen, const Address &replyAddress, const void *tag, size_t tagLen);

	void setSessionFIHelloMode(FIHelloResponseMode mode); // §3.5.1.1.2. Default is FI_IGNORE.
	FIHelloResponseMode getSessionFIHelloMode() const;

	Task onFarAddressDidChange; // Called after DESTADDR change verified §3.5.4.2.

protected:
	Flow(RTMFP *rtmfp);
	Flow() = delete;

	std::shared_ptr<SendFlow> basicOpenFlow(const Bytes &metadata, const RecvFlow *assoc, Priority pri);

	RTMFP *m_rtmfp; // weak ref
	std::shared_ptr<Session> m_session;
	bool m_base_isOpen;
};

class SendFlow : public Flow {
public:
	// If this flow triggered a new opening session, use these methods to add a
	// candidate endpoint address for the responder.
	void addCandidateAddress(const Address &addr, Time delay = 0);
	void addCandidateAddress(const struct sockaddr *addr, Time delay = 0);

	// Answers true if the flow is open, bound to an S_OPEN session, and buffered size is less than capacity.
	bool isWritable() const;

	void notifyWhenWritable(); // Trigger callbacks to onWritable.
	void setBufferCapacity(size_t bufferLengthInBytes); // Advisory maximum size of the send buffer.
	size_t getBufferCapacity() const;
	size_t getBufferedSize() const; // How many bytes (including overhead) are in the send buffer.
	size_t getRecvBufferBytesAvailable() const; // Latest buffer advertised by the receiver §3.6.3.5.
	size_t getOutstandingBytes() const; // Count of unacknowledged bytes in the network §3.5.

	// Queue new data for transmission. Note the buffer capacity is advisory and writes are limited by
	// available system memory. Writes are not allowed if the flow isn't open and bound to an S_OPEN session.
	// Answers a WriteReceipt on success or an empty shared_ptr on error.
	// startWithin and finishWithin are the initial values for the WriteReceipt, which can be changed later.
	std::shared_ptr<WriteReceipt> write(const void *message, size_t len, Time startWithin = INFINITY, Time finishWithin = INFINITY);
	std::shared_ptr<WriteReceipt> write(const Bytes &message, Time startWithin = INFINITY, Time finishWithin = INFINITY);

	void close() override;

	Priority getPriority() const;
	void setPriority(Priority pri);

	// Called after notifyWhenWritable() while the flow is writable (open, in an S_OPEN session,
	// and getBufferedSize() < getBufferCapacity() and while this function answers true. Answer
	// false to stop being called until after the next call to notifyWhenWritable().
	std::function<bool(void)> onWritable;

	// Called when the flow is rejected or if the session closes or times out.
	std::function<void(uintmax_t reason)> onException;

	// Called when a new associated return flow starts. flow must be accepted during
	// this callback or it will be rejected automatically.
	std::function<void(std::shared_ptr<RecvFlow> flow)> onRecvFlow;

protected:
	friend class RTMFP;
	friend class Session;
	friend class Flow;
	struct SendFrag;

	SendFlow(RTMFP *rtmfp, const Bytes &epd, const Bytes &metadata, const RecvFlow *assoc, Priority pri);
	~SendFlow();

	std::shared_ptr<WriteReceipt> basicWrite(const void *message, size_t len, Time startWithin, Time finishWithin);
	void onSessionDidOpen(std::shared_ptr<SendFlow> myself, std::shared_ptr<Session> session);
	void onSessionWillOpen(std::shared_ptr<Session> session);
	void onSessionDidClose(std::shared_ptr<Session> session);
	void queueWritableNotify();
	void doWritable();
	void scheduleForTransmission();
	bool isMaybeReadyForTransmission();
	void trimSendQueue(Time now);
	uintmax_t findForwardSequenceNumber(Time now);
	bool assembleData(PacketAssembler *packet, int pri);
	void ackRange(long &name, uintmax_t ackFrom, uintmax_t ackTo);
	void onAck(uint8_t chunkType, size_t bufferBytesAvailable, uintmax_t cumulativeAck, const uint8_t *disjointed, const uint8_t *limit);
	void onExceptionReport(uintmax_t exceptionCode);
	void setPersistTimer();
	void onPersistTimer(const std::shared_ptr<Timer> &sender, Time now);
	void onLoss(size_t amount);
	void gotoStateClosed();

	enum State { F_OPEN, F_CLOSING, F_COMPLETE_LINGER, F_CLOSED };

	long      m_flow_id;
	Bytes     m_epd;
	bool      m_writablePending;
	bool      m_shouldNotifyWhenWritable;
	Bytes     m_startup_options;
	Priority  m_priority;
	size_t    m_buffer_capacity;
	size_t    m_outstanding_bytes;
	size_t    m_rx_buffer_size;
	uintmax_t m_next_sn;
	uintmax_t m_final_sn;
	bool      m_exception;
	State     m_state;
	std::shared_ptr<Session> m_openingSession;
	SumList<std::shared_ptr<SendFrag> > m_send_queue;
	std::shared_ptr<Timer> m_persistTimer;
};

class RecvFlow : public Flow {
public:
	bool         isOpen() const override;
	void         accept(); // Call this during the onRecvFlow callback to accept a new receiving flow.
	void         setReceiveOrder(ReceiveOrder order); // Default RO_SEQUENCE.
	ReceiveOrder getReceiveOrder() const;
	void         setBufferCapacity(size_t bufferLengthInBytes); // §3.6.3
	size_t       getBufferCapacity() const;
	size_t       getBufferedSize() const; // §3.6.3
	void         close() override; // Reject this flow with default (0) reason §3.6.3.7.
	void         close(uintmax_t reason); // Reject this flow with reason EXCEPTION_CODE.

	Bytes getMetadata() const;

	// Answer the sending flow to which this flow is a return/response, or empty if
	// this is an unassociated flow.
	std::shared_ptr<SendFlow> getAssociatedSendFlow() const;

	// Open a new flow in return/response to this flow.
	std::shared_ptr<SendFlow> openReturnFlow(const void *metadataBytes, size_t metadataLen, Priority pri = PRI_ROUTINE);
	std::shared_ptr<SendFlow> openReturnFlow(const Bytes &metadata, Priority pri = PRI_ROUTINE);

	// This function is called as complete messages are received according to the ReceiveOrder.
	// Messages are discarded if this callback is not set.
	std::function<void(const uint8_t *bytes, size_t len, uintmax_t sequenceNumber, size_t fragmentCount)> onMessage;

	// Called when the flow concludes or has an error (such as the session closing while the flow is still open).
	std::function<void(bool error)> onComplete;

protected:
	friend class RTMFP;
	friend class Session;
	friend class SendFlow;
	struct RecvFrag;

	RecvFlow(std::shared_ptr<Session> session, uintmax_t flowID, const uint8_t *metadata, size_t metadataLen, std::shared_ptr<SendFlow> associatedFlow);
	~RecvFlow();

	void abort();
	void closeAndNotify(bool error);
	void onData(uint8_t flags, uintmax_t sequenceNumber, uintmax_t fsn, const uint8_t *data, size_t len);
	long insertFragment(uintmax_t sequenceNumber, uint8_t flags, const uint8_t *data, size_t len);
	void deliverMessage(long name);
	void tryDelivery(long hint);
	void scheduleAck(bool now);
	bool assembleAck(PacketAssembler *packet, bool truncateAllowed);

	enum State { RF_OPEN, RF_REJECTED, RF_COMPLETE_LINGER, RF_CLOSED };

	uintmax_t    m_flow_id;
	Bytes        m_metadata;
	bool         m_accepted;
	ReceiveOrder m_rxOrder;
	IndexSet     m_sequence_set;
	uintmax_t    m_final_sn;
	bool         m_final_sn_seen;
	SumList<std::shared_ptr<RecvFrag> > m_recv_buffer;
	size_t       m_buffer_capacity;
	size_t       m_prev_rwnd;
	bool         m_should_ack;
	uintmax_t    m_exception_code;
	State        m_state;
	std::shared_ptr<SendFlow> m_associatedFlow;
	std::shared_ptr<Timer>    m_complete_linger_alarm;
};

class WriteReceipt : public Object {
public:
	WriteReceipt(Time origin, Time startWithin, Time finishWithin);

	void abandon(); // Abandon the message if not finished already.

	// The (platform) times by which transmission of this message must be started,
	// and by which delivery of it must finish, to not be automatically abandoned.
	Time startBy;
	Time finishBy;

	// If set, this message will be abandoned if the parent is abandoned. Useful for
	// chaining dependent messages together (such as a predictive-coded video frame that
	// can't be decoded if the previous one is not received).
	std::shared_ptr<WriteReceipt> parent;

	void setStartWithin(Time age); // Set startBy to createdAt() + age.
	void setFinishWithin(Time age); // Set finishBy to createdAt() + age.

	Time createdAt()   const; // The time at which this message was queued.
	bool isAbandoned() const; // True if this message was abandoned before finishing.
	bool isStarted()   const; // True if any part of this message has been transmitted at least once.
	bool isDelivered() const; // True if the entire message was successfully sent to the far end.
	bool isFinished()  const; // True if the message was delivered or abandoned.
	
	std::function<void(bool wasAbandoned)> onFinished;

protected:
	friend class SendFlow;
	WriteReceipt() = delete;

	void useCountUp();
	void useCountDown();
	void start();
	void abandonIfNeeded(Time now);

	Time   m_origin;
	bool   m_started;
	bool   m_abandoned;
	size_t m_useCount;
};

class IPlatformAdapter {
public:
	virtual ~IPlatformAdapter() {}

	virtual Time getCurrentTime() = 0; // Answer the current time (seconds).

	// Called if the deadline for calling RTMFP::doTimerWork() changes. This can be
	// used for re-setting a platform alarm for calling doTimerWork().
	virtual void onHowLongToSleepDidChange() {}

	// Start calling onwritable when interface is writable until onwritable answers false.
	virtual bool notifyWhenInterfaceWritable(int interfaceID, std::function<bool(void)> onwritable) = 0;

	// Write a datagram via interfaceID.
	virtual bool writePacket(const void *bytes, size_t len, int interfaceID, const struct sockaddr *addr, socklen_t addrLen) = 0;

	// Invoke task as soon as possible after this method completes (for example, by putting it
	// on a queue to run at the end of the current trip through the run loop). This is the ONLY
	// synchronization primitive used by the implementation (that is, there are no mutexes). Tasks
	// for the same thread MUST be invoked in the order this method is called. Thread "0" MUST be synchronized
	// with, or the same as, the main RTMFP thread. Non-zero threads can be the same or different platform
	// threads. The intent is, if the platform supports it, for time consuming public key crypto operations
	// to happen on a different thread/core so that RTMFP will remain responsive, and otherwise for RTMFP to
	// be single-threaded. See PosixPlatformAdapter and PerformerPosixPlatformAdapter for illustrative examples.
	virtual bool perform(unsigned long thread, const Task &task) = 0;

	virtual void onShutdownComplete() {} // See RTMFP::shutdown().
};

class ICryptoAdapter {
public:
	virtual ~ICryptoAdapter() {};

	// Answer a new SessionCryptoKey. Until it is completed, its encrypt and
	// decrypt methods should use the Default Session Key.
	virtual std::shared_ptr<SessionCryptoKey> getKeyForNewSession() = 0;

	// Answer this end's certificate, potentially customized for epd.
	virtual Bytes getNearEncodedCertForEPD(const uint8_t *epd, size_t epdLen) = 0;

	// Answer true if this end is selected by epd, false if not.
	virtual bool isSelectedByEPD(const uint8_t *epd, size_t epdLen) = 0;

	// Sign msg according to my identity, customized (if appropriate) to recipient.
	virtual Bytes sign(const uint8_t *msg, size_t msgLen, std::shared_ptr<CryptoCert> recipient) = 0;

	// Answer true if the near end wins glare §3.5.1.3.
	virtual bool checkNearWinsGlare(std::shared_ptr<CryptoCert> far) = 0;

	// Answer a CryptoCert object for the encoded certificate, or empty if
	// bytes does not encode a valid certificate.
	virtual std::shared_ptr<CryptoCert> decodeCertificate(const uint8_t *bytes, size_t len) = 0;

	// Place len ostensibly cryptographically strong pseudorandom bytes at dst.
	// Note that answering not-stronly-random bytes has security implications.
	virtual void pseudoRandomBytes(uint8_t *dst, size_t len) = 0;

	// Compute an ostensibly cryptographic 256-bit hash (such as SHA-256) of msg and place it
	// at dst. Used internally by the RTMFP implementation for e.g. cookies, mobility
	// checks, etc. Factored out here to allow re-use of existing/optimized crypto libraries.
	// Note that using a non-cryptographic hash here has security implications.
	virtual void cryptoHash256(uint8_t *dst, const uint8_t *msg, size_t len) = 0;
};

class SessionCryptoKey : public Object {
public:
	// Answer number of bytes to leave at the front of the source (cleartext) buffer
	// for e.g. a checksum or sequence number, so encryption can potentially avoid
	// a copy and keep the source buffer conveniently aligned.
	virtual size_t getEncryptSrcFrontMargin() = 0;

	// Encrypt src[srcFronMargin..srcLen-1] to dst. On input ioDstLen is the capacity
	// of dst, not to be exceeded. On success, answer true and set ioDstLen to the number
	// of bytes written at dst. On failure answer false. This method is allowed to
	// modify src[0..srcFrontMargin-1] to e.g. insert a checksum or sequence number
	// or something, and to modify src[srcLen..srcLen+63] to e.g. pad a cipher block.
	// Until the key handshake is completed, encrypt with the Default Session Key.
	virtual bool encrypt(uint8_t *dst, size_t &ioDstLen, uint8_t *src, size_t srcLen, size_t srcFrontMargin) = 0;

	// Decrypt src[src..srcLen - 1] to dst. On input, ioDstLen is the capacity of dst. On
	// success, answer true, set ioDstLen to the number of bytes written to dst, including
	// the front margin if any, and set dstFrontMargin to the number of bytes past dst
	// where the clear packet begins, for example to skip over a decrypted checksum or
	// sequence number and avoid a copy. On failure, answer false (for example, if a
	// checksum check fails or there is a syntax error in the packet, indicating this
	// packet may not belong to this key).
	// Until the key handshake is completed, decrypt with the Default Session Key.
	virtual bool decrypt(uint8_t *dst, size_t &ioDstLen, size_t &dstFrontMargin, const uint8_t *src, size_t srcLen) = 0;

	// Answer the session near/far nonces §3.5.
	virtual Bytes getNearNonce() = 0;
	virtual Bytes getFarNonce() = 0;

	// Set this key to initiator mode and generate a Session Key Initiator Component (SKIC) §2.3.7
	// appropriate to responder. On success, place the SKIC into outComponent and answer true.
	// On failure answer false.
	virtual bool generateInitiatorKeyingComponent(std::shared_ptr<CryptoCert> responder, Bytes *outComponent) = 0;

	// Combine the state from the SKIC generated above with the Session Key Responder Component (SKRC)
	// at responderComponent received from the responder, completing this key. Answer true if the SKRC
	// is successfully combined to complete the key, false otherwise.
	virtual bool initiatorCombineResponderKeyingComponent(const uint8_t *responderComponent, size_t len) = 0;

	// Set this key to responder mode. Take the initiatorComponent SKIC from initiator, and if acceptable,
	// generate the SKRC to outComponent, complete the key, and answer true. If unacceptable, answer false.
	virtual bool generateResponderKeyingComponent(std::shared_ptr<CryptoCert> initiator, const uint8_t *initiatorComponent, size_t len, Bytes *outComponent) = 0;
};

class CryptoCert : public Object {
public:
	// Test if this certificate is authentic (for example, a signature/endorsement chain checks out).
	// Call onauthentic (sync or async, and from any thread so long as the platform adapter's perform
	// method can be called from any thread) if authentic, otherwise do nothing.
	virtual void isAuthentic(const Task &onauthentic) = 0;

	// Answer true if this certificate is selected by epd, false otherwise.
	virtual bool isSelectedByEPD(const uint8_t *epd, size_t epdLen) = 0;

	// Answer the Canonical Endpoint Discriminator for this certificate.
	virtual Bytes getCanonicalEPD() = 0;

	// Test if sig(nature) over msg was issued by this certificate's owner. Call ongood
	// (sync or async, from any thread with above caveat) if sig is good, otherwise do nothing.
	virtual void checkSignature(const uint8_t *msg, size_t msgLen, const uint8_t *sig, size_t sigLen, const Task &ongood) = 0;

	// Answer true if other overrides a session with this certificate §3.2.
	virtual bool doesCertOverrideSession(std::shared_ptr<CryptoCert> other) = 0;
};

} } } // namespace com::zenomt::rtmfp
