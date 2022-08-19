#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "../include/rtmfp/rtmfp.hpp"

#include <deque>
#include <queue>
#include <set>

namespace com { namespace zenomt { namespace rtmfp {

struct PacketAssembler;

class ISession : public Object {
public:
	virtual bool onInterfaceWritable(int interfaceID, int priority) = 0;
	virtual bool onReceivePacket(const uint8_t *bytes, size_t len, int interfaceID, const struct sockaddr *addr, int tos, uint8_t *decryptBuf);
	virtual bool onPacketHeader(uint8_t flags, long timestamp, long timestampEcho, int tos) = 0;
	virtual void onChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr) = 0;
	virtual void onPacketAfterChunks(uint8_t flags, long timestamp, long timestampEcho, int interfaceID, const struct sockaddr *addr);
	void encryptAndSendPacket(PacketAssembler *packet, uint32_t sessionID, int interfaceID, const Address &addr, int tos, SessionCryptoKey *cryptoKeyOverride);

	RTMFP *m_rtmfp;
	std::shared_ptr<SessionCryptoKey> m_cryptoKey;

protected:
	friend class RTMFP;
	ISession(RTMFP *rtmfp, std::shared_ptr<SessionCryptoKey> cryptoKey);
	ISession() = delete;
};

class StartupSession : public ISession {
public:
	struct SendItem {
		SendItem(const std::vector<uint8_t> &bytes, uint32_t sessionID, const struct sockaddr *addr, std::shared_ptr<Session> session);

		std::vector<uint8_t>     m_bytes;
		uint32_t                 m_sessionID;
		Address                  m_dest;
		std::shared_ptr<Session> m_session;
	};

	~StartupSession();

	void sendPacket(const std::vector<uint8_t> &bytes, uint32_t sessionID, int interfaceID, const struct sockaddr *addr);
	void sendPacket(const std::vector<uint8_t> &bytes, uint32_t sessionID, int interfaceID, const struct sockaddr *addr, std::shared_ptr<Session> session);
	bool empty() const;

	bool onInterfaceWritable(int interfaceID, int priority) override;
	bool onPacketHeader(uint8_t flags, long timestamp, long timestampEcho, int tos) override;
	void onChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr) override;

	void onIHelloChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr);
	void onRHelloChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr);
	void onRedirectChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr);
	void onIIKeyingChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr);

protected:
	friend class RTMFP;
	StartupSession(RTMFP *rtmfp, std::shared_ptr<SessionCryptoKey> cryptoKey);
	std::map<int, std::queue<std::shared_ptr<SendItem> > > m_sendItems;
	bool m_seenIHelloThisPacket;
};

class Session : public ISession {
public:
	enum State { S_UNKNOWN, S_IHELLO_SENT, S_KEYING_SENT, S_OPEN,
		S_NEARCLOSE, S_FARCLOSE_LINGER, S_CLOSED };

	~Session();

	static void initiateToEPD(std::shared_ptr<Session> myself, const Bytes &epd);
	bool isOpeningToAddress(const Address &addr) const;
	void sendClose(bool closeAck);
	void close(bool orderly);
	void abortFlowsAndTimers();
	void abort();
	void setOpen(std::shared_ptr<Session> myself, uint32_t txSessionID);
	void setNearclose();
	void setFarcloseLinger();
	void setKeepalivePeriod(Time keepalive);
	void setKeepaliveAlarm();
	Time getKeepalivePeriod() const;
	void setRetransmitLimit(Time limit);
	Time getRetransmitLimit() const;
	void setIdleLimit(Time limit);
	Time getIdleLimit() const;
	void setTrafficClass(int tos);
	int getTrafficClass() const;
	void onKeepaliveAlarm(Time now);
	void onIdleAlarm(Time now);
	Bytes makeMobilityCheck(uintmax_t now, int interfaceID, const struct sockaddr *addr);
	void sendMobilityCheck(uintmax_t now, int interfaceID, const struct sockaddr *addr);
	void sendKeepalivePing();
	void sendPing();
	void sendRIKeying();
	void interestUp();
	void interestDown();
	void addCandidateAddress(const Address &addr, Time delay, bool fromRedirect);
	void replayEarlyPackets();
	void bindFlow(std::shared_ptr<SendFlow> flow);
	void unbindFlow(long flowID, SendFlow *flow);
	void unbindFlow(uintmax_t flowID, RecvFlow *flow);
	void startIIKeying(const Bytes &iikeyingChunk);
	bool makeIIKeyingChunk(const Bytes &cookie, const Bytes &skic, Bytes &dst);
	long getTimestampIfNew();
	long getTimestampEcho();
	void scheduleAck(std::shared_ptr<RecvFlow> flow);
	void ackNow();
	bool assembleEcnReport(PacketAssembler *packet);
	bool sendAcks(PacketAssembler *packet, bool obligatory);
	void sendPacket(const Bytes &chunks);
	void scheduleFlowForTransmission(const std::shared_ptr<SendFlow> &flow, Priority pri);
	void rescheduleTimeoutAlarm();
	void onTimeoutAlarm();
	void rescheduleTransmission();
	void updateCWND(size_t acked_bytes_this_packet, size_t lost_bytes_this_packet, bool any_loss, bool any_naks);
	void scheduleBurstAlarm();

	static void onRHello(std::shared_ptr<Session> myself, const uint8_t *cookie, size_t cookieLen, const uint8_t *cert, size_t certLen, int interfaceID, const struct sockaddr *addr);
	void onCookieChange(const uint8_t *oldCookie, size_t oldCookieLen, const uint8_t *newCookie, size_t newCookieLen, int interfaceID, const struct sockaddr *addr);
	void onRIKeying(uint32_t responderSessionID, const uint8_t *skrc, size_t skrcLen, const uint8_t *signedParameters, size_t signedParametersLen, const uint8_t *sig, size_t sigLen, int interfaceID, const struct sockaddr *addr);
	void onUserData(uint8_t flags, uintmax_t flowID, uintmax_t sequenceNumber, uintmax_t fsn, uintmax_t *associatedFlowID, const uint8_t *metadata, size_t metadataLen, const uint8_t *data, size_t len, bool mustReject);
	void onBufferProbe(uintmax_t flowID);
	void onMobilityCheckReply(const uint8_t *chunk, const uint8_t *limit, uintmax_t ts, int interfaceID, const struct sockaddr *addr);

	bool onInterfaceWritable(int interfaceID, int priority) override;
	bool onReceivePacket(const uint8_t *bytes, size_t len, int interfaceID, const struct sockaddr *addr, int tos, uint8_t *decryptBuf) override;
	bool onPacketHeader(uint8_t flags, long timestamp, long timestampEcho, int tos) override;
	void onChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr) override;
	void onPacketAfterChunks(uint8_t flags, long timestamp, long timestampEcho, int interfaceID, const struct sockaddr *addr) override;

	void onRIKeyingChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr);
	void onCookieChangeChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr);
	void onFIHelloChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr);
	void onUserDataChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr);
	void onBufferProbeChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr);
	void onExceptionChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr);
	void onPingChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr);
	void onPingReplyChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr);
	void onAckChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr);
	void onEcnReportChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr);
	void onCloseChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr);
	void onCloseAckChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr);

	struct EarlyPacket {
		EarlyPacket(const uint8_t *bytes, size_t len, int tos) :
			m_bytes(bytes, bytes + len),
			m_tos(tos)
		{}

		Bytes m_bytes;
		int   m_tos;
	};

	State    m_state;
	unsigned m_role; // one of HEADER_MODE_INITIATOR or HEADER_MODE_RESPONDER
	uint32_t m_rxSessionID;
	uint32_t m_txSessionID;
	bool     m_resp_cookieChanged;
	Bytes    m_skic;
	Bytes    m_resp_cookie;
	Bytes    m_skrc;
	Bytes    m_rikeying;
	Bytes    m_epd;
	Bytes    m_tag;
	Bytes    m_ihello;
	int      m_destInterfaceID;
	Address  m_destAddr;
	std::shared_ptr<CryptoCert> m_cryptoCert;
	std::set<Address> m_openingAddresses;
	long     m_interestCount;
	FIHelloResponseMode m_fihelloMode;
	std::shared_ptr<Timer> m_iikeyingTimer;
	std::queue<EarlyPacket> m_earlyPackets;
	List<std::shared_ptr<SendFlow> >                m_sendFlows;
	std::map<uintmax_t, std::shared_ptr<RecvFlow> > m_recvFlows;
	List<std::shared_ptr<RecvFlow> >                m_ackFlows;
	List<std::shared_ptr<SendFlow> >                m_readyFlows[NUM_PRIORITIES];
	SumList<std::shared_ptr<SendFlow::SendFrag> >   m_outstandingFrags;
	bool      m_seenUserDataThisPacket;
	uintmax_t m_parsingFlowID;
	uintmax_t m_parsingSequenceNumber;
	uintmax_t m_parsingFSN;

	// snake-case names based on RFC 7016 names
	long      m_ts_rx;
	Time      m_ts_rx_time;
	long      m_ts_echo_tx;
	Time      m_mrto;
	Time      m_erto;
	size_t    m_rx_data_packets;
	bool      m_ack_now;
	std::shared_ptr<Timer> m_delack_alarm;
	std::shared_ptr<Timer> m_timeout_alarm;
	std::shared_ptr<Timer> m_burst_alarm;
	long      m_ts_tx;
	long      m_ts_echo_rx;
	Time      m_srtt;
	Time      m_rttvar;
	Time      m_last_rtt;
	Time      m_last_rtt_time;

	size_t    m_cwnd;
	size_t    m_ssthresh;
	size_t    m_acked_bytes_accumulator;
	size_t    m_recovery_remaining;
	size_t    m_recovery_loss_allowance;
	size_t    m_pre_ack_outstanding;
	bool      m_any_acks;
	Time      m_tc_sent_time;
	Time      m_tcr_recv_time;
	long      m_data_burst_limit;
	uintmax_t m_next_tsn;
	uintmax_t m_max_tsn_ack;

	// keepalive
	Time      m_last_keepalive_tx_time;
	Time      m_keepalive_period;
	Time      m_retransmit_limit;
	Time      m_retransmit_deadline_epoch;
	Time      m_idle_limit;
	Time      m_last_idle_time;
	bool      m_keepalive_outstanding;
	std::shared_ptr<Timer> m_keepalive_timer;
	std::shared_ptr<Timer> m_idle_timer;

	// mobility
	uintmax_t m_mob_tx_ts;
	uintmax_t m_mob_rx_ts;

	// explicit congestion notification
	bool      m_send_ect;
	bool      m_seen_ecn_report;
	bool      m_seen_new_ecn;
	bool      m_congestionNotifiedThisPacket;
	uintmax_t m_ecn_ce_count;
	uint8_t   m_rx_ece_count;
	int       m_tos;

	// keep track of minimum RTT over a sliding window RTT_HISTORY_CAPACITY buckets each RTT_HISTORY_THRESH long.
	struct RTTMeasurement {
		Time min_rtt;
		Time origin;
	};
	std::deque<RTTMeasurement> m_rttMeasurements;
	Time      m_base_rtt { INFINITY };
	Time      m_last_minrtt_probe { INFINITY };
	Time      m_last_delaycc_action { -INFINITY };
	Time      m_delaycc_congestion_delay { INFINITY };
	void checkBaseRTT(Time rtt, Time now);
	void resetBaseRTT();

protected:
	friend class RTMFP;
	Session(RTMFP *rtmfp, std::shared_ptr<SessionCryptoKey> cryptoKey);
};

} } } // namespace com::zenomt::rtmfp
