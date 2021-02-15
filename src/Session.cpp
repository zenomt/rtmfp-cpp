// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cassert>
#include <climits>
#include <cstring>

#include "Session.hpp"
#include "Interface.hpp"
#include "../include/rtmfp/VLU.hpp"
#include "../include/rtmfp/packet.hpp"
#include "../include/rtmfp/params.hpp"
#include "../include/rtmfp/PacketAssembler.hpp"
#include "SendFrag.hpp"

namespace com { namespace zenomt { namespace rtmfp {

// --- ISession

ISession::ISession(RTMFP *rtmfp, std::shared_ptr<SessionCryptoKey> cryptoKey) :
	m_rtmfp(rtmfp),
	m_cryptoKey(cryptoKey)
{
}

bool ISession::onReceivePacket(const uint8_t *bytes, size_t len, int interfaceID, const struct sockaddr *addr, uint8_t *decryptBuf)
{
	size_t decryptedLen = DECRYPT_BUF_LENGTH;
	size_t frontMargin = 0;
	if( (not m_cryptoKey->decrypt(decryptBuf, decryptedLen, frontMargin, bytes, len))
	 or (frontMargin >= decryptedLen) // at least one byte of cleartext
	)
		return false;

	uint8_t *cursor = decryptBuf + frontMargin;
	uint8_t *limit = decryptBuf + decryptedLen;

	uint8_t flags = *cursor++;
	long ts = -1, tse = -1;

	if(flags & HEADER_FLAG_TS)
	{
		if(limit - cursor < 2)
			return false;
		ts = (cursor[0] << 8) + cursor[1];
		cursor += 2;
	}
	if(flags & HEADER_FLAG_TSE)
	{
		if(limit - cursor < 2)
			return false;
		tse = (cursor[0] << 8) + cursor[1];
		cursor += 2;
	}

	if(not onPacketHeader(flags, ts, tse))
		return false;

	uint8_t mode = flags & HEADER_FLAG_MOD_MASK;

	while(size_t(limit - cursor) >= CHUNK_HEADER_LENGTH)
	{
		uint8_t chunkType = cursor[0];
		size_t chunkLength = (cursor[1] << 8) + cursor[2];
		cursor += CHUNK_HEADER_LENGTH;

		if(chunkLength > size_t(limit - cursor))
			break;

		onChunk(mode, chunkType, cursor, cursor + chunkLength, interfaceID, addr);
		cursor += chunkLength;
	}

	onPacketAfterChunks(flags, ts, tse, interfaceID, addr);

	return true;
}

void ISession::onPacketAfterChunks(uint8_t flags, long timestamp, long timestampEcho, int interfaceID, const struct sockaddr *addr)
{
}

void ISession::encryptAndSendPacket(PacketAssembler *packet, uint32_t sessionID, int interfaceID, const Address &addr, SessionCryptoKey *cryptoKey)
{
	uint8_t *sendBuf = m_rtmfp->m_ciphertextBuf + ENCRYPT_BUF_SSID_OFFSET;
	uint8_t *dst = sendBuf + sizeof(uint32_t); // so we can try to keep cipher blocks 16-byte aligned
	size_t dstLen = ENCRYPT_BUF_LENGTH;

	if(not cryptoKey->encrypt(dst, dstLen, packet->m_buf, packet->m_cursor - packet->m_buf, packet->m_frontMargin))
		return;

	uint32_t sid_encode[3] = { 0, 0, 0 };
	memmove(sid_encode + 1, dst, dstLen < 8 ? dstLen : 8);
	sid_encode[0] = sessionID ^ sid_encode[1] ^ sid_encode[2];
	memmove(sendBuf, sid_encode, sizeof(uint32_t));

	m_rtmfp->m_platform->writePacket(sendBuf, dstLen + sizeof(uint32_t), interfaceID, addr.getSockaddr(), addr.getSockaddrLen());
}

// --- StartupSession

StartupSession::SendItem::SendItem(const std::vector<uint8_t> &bytes, uint32_t sessionID, const struct sockaddr *addr, std::shared_ptr<Session> session) :
	m_bytes(bytes),
	m_sessionID(sessionID),
	m_dest(addr),
	m_session(session)
{
}

StartupSession::StartupSession(RTMFP *rtmfp, std::shared_ptr<SessionCryptoKey> cryptoKey) :
	ISession(rtmfp, cryptoKey)
{
}

StartupSession::~StartupSession()
{
}

void StartupSession::sendPacket(const std::vector<uint8_t> &bytes, uint32_t sessionID, int interfaceID, const struct sockaddr *addr, std::shared_ptr<Session> session)
{
	if(interfaceID < 0)
	{
		for(auto it = m_rtmfp->m_interfaces.begin(); it != m_rtmfp->m_interfaces.end(); it++)
			sendPacket(bytes, sessionID, it->first, addr, session);
	}
	else
	{
		if(m_rtmfp->scheduleWrite(interfaceID, share_ref(this), PRI_IMMEDIATE))
			m_sendItems[interfaceID].push(std::make_shared<SendItem>(bytes, sessionID, addr, session));
	}
}

void StartupSession::sendPacket(const std::vector<uint8_t> &bytes, uint32_t sessionID, int interfaceID, const struct sockaddr *addr)
{
	sendPacket(bytes, sessionID, interfaceID, addr, std::shared_ptr<Session>());
}

bool StartupSession::empty() const
{
	for(auto it = m_sendItems.begin(); it != m_sendItems.end(); it++)
		if(not it->second.empty())
			return false;
	return true;
}

bool StartupSession::onInterfaceWritable(int interfaceID, int priority)
{
	auto &sendItems = m_sendItems[interfaceID];
	if(sendItems.empty())
	{
		m_rtmfp->checkShutdownComplete();
		return false;
	}

	auto item = sendItems.front();
	sendItems.pop();

	SessionCryptoKey *cryptoKey = m_cryptoKey.get();
	long timestampEcho = -1;
	uint8_t mode = HEADER_MODE_STARTUP;
	if(item->m_session)
	{
		timestampEcho = item->m_session->getTimestampEcho();
		cryptoKey = item->m_session->m_cryptoKey.get();
		mode = item->m_session->m_role;
		if(m_rtmfp->shouldSessionReportTCR(item->m_session.get()))
			mode |= HEADER_FLAG_TCR;
	}

	PacketAssembler packet;
	packet.init(m_rtmfp->m_plaintextBuf, cryptoKey->getEncryptSrcFrontMargin(), MAX_STARTUP_PACKET_LENGTH, mode, m_rtmfp->getCurrentTimestamp(), timestampEcho);
	if(packet.push(item->m_bytes))
		encryptAndSendPacket(&packet, item->m_sessionID, interfaceID, item->m_dest, cryptoKey);

	return true;
}

bool StartupSession::onPacketHeader(uint8_t flags, long timestamp, long timestampEcho)
{
	return HEADER_MODE_STARTUP == (flags & HEADER_FLAG_MOD_MASK);
}

void StartupSession::onChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr)
{
	switch(chunkType)
	{
	case CHUNK_IHELLO:
		onIHelloChunk(mode, chunkType, chunk, limit, interfaceID, addr);
		break;
	case CHUNK_RHELLO:
		onRHelloChunk(mode, chunkType, chunk, limit, interfaceID, addr);
		break;
	case CHUNK_REDIRECT:
		onRedirectChunk(mode, chunkType, chunk, limit, interfaceID, addr);
		break;
	case CHUNK_IIKEYING:
		onIIKeyingChunk(mode, chunkType, chunk, limit, interfaceID, addr);
		break;
	default:
		break;
	}
}

void StartupSession::onIHelloChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr)
{
	size_t rv;
	const uint8_t *epd;
	size_t epdLen;
	const uint8_t *cursor = chunk;

	if(0 == (rv = VLU::parseField(cursor, limit, &epd, &epdLen)))
		return;
	cursor += rv;

	m_rtmfp->onIHello(epd, epdLen, cursor, limit - cursor, interfaceID, addr, FI_SEND_RHELLO);
}

void StartupSession::onRHelloChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr)
{
	size_t rv;
	const uint8_t *tag;
	size_t tagLen;
	const uint8_t *cookie;
	size_t cookieLen;
	const uint8_t *cert;
	size_t certLen;
	const uint8_t *cursor = chunk;

	if(0 == (rv = VLU::parseField(cursor, limit, &tag, &tagLen)))
		return;
	cursor += rv;

	if(0 == (rv = VLU::parseField(cursor, limit, &cookie, &cookieLen)))
		return;
	cursor += rv;

	cert = cursor;
	certLen = limit - cursor;

	m_rtmfp->onRHello(tag, tagLen, cookie, cookieLen, cert, certLen, interfaceID, addr);
}

void StartupSession::onRedirectChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr)
{
	size_t rv;
	const uint8_t *tag;
	size_t tagLen;
	std::vector<Address> redirectDestinations;
	const uint8_t *cursor = chunk;

	if(0 == (rv = VLU::parseField(cursor, limit, &tag, &tagLen)))
		return;
	cursor += rv;

	Address tmp;
	while(cursor < limit)
	{
		if(0 == (rv = tmp.setFromEncoding(cursor, limit)))
			return;
		redirectDestinations.emplace_back(tmp);
	}

	if(redirectDestinations.empty())
		redirectDestinations.emplace_back(addr, Address::ORIGIN_OBSERVED);

	m_rtmfp->onRedirect(tag, tagLen, redirectDestinations);
}

void StartupSession::onIIKeyingChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr)
{
	size_t rv;
	const uint8_t *cursor = chunk;
	const uint8_t *signedParameters = chunk;
	size_t signedParametersLen;
	uint32_t initiatorSessionID;
	const uint8_t *cookie;
	size_t cookieLen;
	const uint8_t *cert;
	size_t certLen;
	const uint8_t *skic;
	size_t skicLen;
	const uint8_t *signature;
	size_t signatureLen;

	if(size_t(limit - chunk) < sizeof(uint32_t))
		return;

	memmove(&initiatorSessionID, cursor, sizeof(initiatorSessionID));
	cursor += sizeof(initiatorSessionID);

	if(0 == (rv = VLU::parseField(cursor, limit, &cookie, &cookieLen)))
		return;
	cursor += rv;

	if(0 == (rv = VLU::parseField(cursor, limit, &cert, &certLen)))
		return;
	cursor += rv;

	if(0 == (rv = VLU::parseField(cursor, limit, &skic, &skicLen)))
		return;
	cursor += rv;

	signedParametersLen = cursor - signedParameters;

	signature = cursor;
	signatureLen = limit - cursor;

	m_rtmfp->onIIKeying(initiatorSessionID, cookie, cookieLen, cert, certLen, skic, skicLen, signedParameters, signedParametersLen, signature, signatureLen, interfaceID, addr);
}

// --- Session

Session::Session(RTMFP *rtmfp, std::shared_ptr<SessionCryptoKey> cryptoKey) :
	ISession(rtmfp, cryptoKey),
	m_state(S_UNKNOWN),
	m_role(0),
	m_rxSessionID(0),
	m_txSessionID(0),
	m_resp_cookieChanged(false),
	m_destInterfaceID(-1),
	m_interestCount(0),
	m_fihelloMode(FI_IGNORE),
	m_outstandingFrags(SendFlow::SendFrag::size_outstanding),
	m_ts_rx(-1),
	m_ts_rx_time(-INFINITY),
	m_ts_echo_tx(-1),
	m_mrto(INITIAL_MRTO),
	m_erto(INITIAL_ERTO),
	m_rx_data_packets(0),
	m_ack_now(false),
	m_ts_tx(-1),
	m_ts_echo_rx(-1),
	m_srtt(-1),
	m_rttvar(0),
	m_cwnd(CWND_INIT),
	m_ssthresh(SIZE_MAX),
	m_acked_bytes_accumulator(0),
	m_recovery_remaining(0),
	m_pre_ack_outstanding(0),
	m_any_acks(false),
	m_tc_sent_time(-INFINITY),
	m_tcr_recv_time(-INFINITY),
	m_data_packet_count(0),
	m_next_tsn(1),
	m_max_tsn_ack(0),
	m_last_keepalive_tx_time(-INFINITY),
	m_keepalive_period(INFINITY),
	m_retransmit_limit(INFINITY),
	m_retransmit_deadline_epoch(INFINITY),
	m_idle_limit(INFINITY),
	m_last_idle_time(-INFINITY),
	m_keepalive_outstanding(false),
	m_mob_tx_ts(0),
	m_mob_rx_ts(0)
{
}

Session::~Session()
{
	if(m_iikeyingTimer)
		m_iikeyingTimer->cancel();

	if(m_delack_alarm)
		m_delack_alarm->cancel();

	if(m_timeout_alarm)
		m_timeout_alarm->cancel();

	if(m_keepalive_timer)
		m_keepalive_timer->cancel();

	if(m_idle_timer)
		m_idle_timer->cancel();

	if(m_burst_alarm)
		m_burst_alarm->cancel();
}

void Session::initiateToEPD(std::shared_ptr<Session> myself, const Bytes &epd)
{
	assert(HEADER_MODE_INITIATOR == myself->m_role);
	assert(S_UNKNOWN == myself->m_state);

	myself->m_epd = epd;
	myself->m_state = S_IHELLO_SENT;

	uint8_t tag[IHELLO_TAG_LENGTH];
	myself->m_rtmfp->m_crypto->pseudoRandomBytes(tag, sizeof(tag));
	myself->m_tag.insert(myself->m_tag.end(), tag, tag + sizeof(tag));

	myself->m_rtmfp->scheduleRel(ULTIMATE_SESSION_TIMEOUT)->action = Timer::makeAction([myself] {
		if(myself->m_state < S_OPEN)
			myself->abort();
	});

	uint8_t tmp[MAX_STARTUP_PACKET_LENGTH];
	PacketAssembler ihello;
	ihello.init(tmp, 0, sizeof(tmp));
	ihello.startChunk(CHUNK_IHELLO);
	ihello.pushField(myself->m_epd);
	ihello.push(tag, sizeof(tag));
	ihello.commitChunk();

	myself->m_ihello = ihello.toVector();
}

bool Session::isOpeningToAddress(const Address &addr) const
{
	switch(m_state)
	{
	case S_IHELLO_SENT:
		return m_openingAddresses.find(addr) != m_openingAddresses.end();
	case S_KEYING_SENT:
		return addr == m_destAddr;
	default:
		break;
	}
	return false;
}

void Session::sendClose(bool ack)
{
	uint8_t buf[CHUNK_HEADER_LENGTH] = { 0, 0, 0 };
	buf[0] = ack ? CHUNK_CLOSE_ACK : CHUNK_CLOSE;
	sendPacket(Bytes(buf, buf + sizeof(buf)));
}

void Session::close(bool orderly)
{
	switch(m_state)
	{
	case S_UNKNOWN:
	case S_IHELLO_SENT:
	case S_KEYING_SENT:
		abort();
		return;

	case S_OPEN:
		if(not orderly)
		{
			sendClose(true);
			abort();
			return;
		}
		setNearclose();
		break;

	case S_NEARCLOSE:
	case S_FARCLOSE_LINGER:
		if(not orderly)
		{
			sendClose(true);
			abort();
		}
		break;

	default:
		break;
	}
}

void Session::abortFlowsAndTimers()
{
	if(m_iikeyingTimer)
		m_iikeyingTimer->cancel();
	m_iikeyingTimer.reset();

	if(m_delack_alarm)
		m_delack_alarm->cancel();
	m_delack_alarm.reset();

	if(m_timeout_alarm)
		m_timeout_alarm->cancel();
	m_timeout_alarm.reset();

	if(m_keepalive_timer)
		m_keepalive_timer->cancel();
	m_keepalive_timer.reset();

	if(m_idle_timer)
		m_idle_timer->cancel();
	m_idle_timer.reset();

	if(m_burst_alarm)
		m_burst_alarm->cancel();
	m_burst_alarm.reset();

	auto myself = share_ref(this);
	while(not m_sendFlows.empty())
	{
		long firstName = m_sendFlows.first();
		m_sendFlows.firstValue()->onSessionDidClose(myself); // should unbind, removing itself from m_sendFlows
		assert(not m_sendFlows.has(firstName));
	}

	while(not m_recvFlows.empty())
	{
		auto it = m_recvFlows.begin();
		it->second->abort();
		m_recvFlows.erase(it);
	}
}

void Session::abort()
{
	if(m_state < S_CLOSED)
	{
		m_state = S_CLOSED;
		abortFlowsAndTimers();
		m_rtmfp->onSessionDidClose(share_ref(this), true);
	}
}

void Session::setOpen(std::shared_ptr<Session> myself, uint32_t txSessionID)
{
	m_state = S_OPEN;
	m_epd = m_cryptoCert->getCanonicalEPD();
	m_txSessionID = txSessionID;
	m_last_keepalive_tx_time = m_last_idle_time = m_rtmfp->getCurrentTime();
	m_retransmit_deadline_epoch = INFINITY;
	setKeepalivePeriod(m_rtmfp->getDefaultSessionKeepalivePeriod());
	setRetransmitLimit(m_rtmfp->getDefaultSessionRetransmitLimit());
	setIdleLimit(m_rtmfp->getDefaultSessionIdleLimit());

	m_rtmfp->onSessionDidOpen(myself);
	replayEarlyPackets();
}

void Session::setNearclose()
{
	m_state = S_NEARCLOSE;
	abortFlowsAndTimers();

	auto myself = share_ref(this);
	Time limit = m_rtmfp->getCurrentTime() + NEARCLOSE_PERIOD;
	m_rtmfp->scheduleRel(0, NEARCLOSE_RTX_PERIOD)->action = [myself, limit] (const std::shared_ptr<Timer> &sender, Time now) {
		if((S_NEARCLOSE != myself->m_state) or (now >= limit))
		{
			myself->abort();
			sender->cancel();
			return;
		}
		myself->sendClose(false);
	};
}

void Session::setFarcloseLinger()
{
	m_state = S_FARCLOSE_LINGER;
	abortFlowsAndTimers();

	auto myself = share_ref(this);
	m_rtmfp->scheduleRel(FARCLOSE_LINGER_PERIOD)->action = Timer::makeAction([myself] { myself->abort(); });
}

void Session::setKeepalivePeriod(Time keepalive)
{
	m_keepalive_period = std::max(keepalive, MIN_KEEPALIVE_PERIOD);
	setKeepaliveAlarm();
}

void Session::setKeepaliveAlarm()
{
	if(S_OPEN != m_state)
		return;

	if(m_keepalive_timer)
		m_keepalive_timer->cancel();
	m_keepalive_timer = m_rtmfp->scheduleRel(0);
	m_keepalive_timer->action = [this] (const std::shared_ptr<Timer> &sender, Time now) { onKeepaliveAlarm(now); };
}

Time Session::getKeepalivePeriod() const
{
	return m_keepalive_period;
}

void Session::setRetransmitLimit(Time limit)
{
	m_retransmit_limit = std::max(limit, MIN_RTX_PERIOD);
}

Time Session::getRetransmitLimit() const
{
	return m_retransmit_limit;
}

void Session::setIdleLimit(Time limit)
{
	m_idle_limit = std::max(limit, MIN_IDLE_PERIOD);

	if(S_OPEN != m_state)
		return;
	if(m_idle_timer)
		m_idle_timer->setNextFireTime(m_rtmfp->getCurrentTime());
	else
	{
		m_idle_timer = m_rtmfp->scheduleRel(0);
		m_idle_timer->action = [this] (const std::shared_ptr<Timer> &sender, Time now) { onIdleAlarm(now); };
	}
}

Time Session::getIdleLimit() const
{
	return m_idle_limit;
}

void Session::onKeepaliveAlarm(Time now)
{
	if(S_OPEN != m_state)
		return;

	Time deadline = m_last_keepalive_tx_time + m_keepalive_period;

	// in case both sides have the same keepalive period, the responder will wait a smidge longer
	if(HEADER_MODE_RESPONDER == m_role)
		deadline += m_mrto;

	if(now < deadline)
	{
		m_keepalive_timer->setNextFireTime(deadline);
		return;
	}

	m_keepalive_timer.reset();
	sendKeepalivePing();
}

void Session::onIdleAlarm(Time now)
{
	if(S_OPEN != m_state)
		return;

	Time deadline = m_last_idle_time + m_idle_limit;
	if(now < deadline)
	{
		m_idle_timer->setNextFireTime(deadline);
		return;
	}

	if((0 == m_sendFlows.size()) and (0 == m_recvFlows.size()))
		close(true);
	else
		m_idle_timer->setNextFireTime(now + m_idle_limit);
}

Bytes Session::makeMobilityCheck(uintmax_t now, int interfaceID, const struct sockaddr *addr)
{
	Bytes dough;
	Bytes rv;

	dough.insert(dough.end(), PING_MARKING_MOBILITY);
	rv.insert(rv.end(), PING_MARKING_MOBILITY);

	VLU::append(now, dough);
	VLU::append(now, rv);

	VLU::append(interfaceID, dough);

	auto encodedAddr = Address(addr).encode();
	dough.insert(dough.end(), encodedAddr.begin(), encodedAddr.end());

	dough.insert(dough.end(), m_rtmfp->m_secret, m_rtmfp->m_secret + sizeof(m_rtmfp->m_secret));

	uint8_t hash[256/8];
	m_rtmfp->m_crypto->cryptoHash256(hash, dough.data(), dough.size());
	rv.insert(rv.end(), hash, hash + sizeof(hash));

	return rv;
}

void Session::sendMobilityCheck(uintmax_t now, int interfaceID, const struct sockaddr *addr)
{
	uint8_t buf[MAX_PING_MESSAGE_LENGTH];
	PacketAssembler ping;
	ping.init(buf, 0, sizeof(buf));
	ping.startChunk(CHUNK_PING);
	ping.push(makeMobilityCheck(now, interfaceID, addr));
	ping.commitChunk();

	m_rtmfp->m_startupSession->sendPacket(ping.toVector(), m_txSessionID, interfaceID, addr, share_ref(this));
	m_mob_tx_ts = now;
}

void Session::sendKeepalivePing()
{
	sendPing();
	m_keepalive_outstanding = true;
	m_last_keepalive_tx_time = m_rtmfp->getCurrentTime();
	rescheduleTimeoutAlarm();
}

void Session::sendPing()
{
	uint8_t buf[CHUNK_HEADER_LENGTH] = { CHUNK_PING, 0, 0 };
	sendPacket(Bytes(buf, buf + sizeof(buf)));
}

void Session::sendRIKeying()
{
	if((S_OPEN == m_state) and m_rikeying.size())
		m_rtmfp->m_startupSession->sendPacket(m_rikeying, m_txSessionID, m_destInterfaceID, m_destAddr.getSockaddr());
}

void Session::interestUp()
{
	m_interestCount++;
}

void Session::interestDown()
{
	m_interestCount--;
	if((0 == m_interestCount) and (S_IHELLO_SENT == m_state))
		abort();
}

void Session::addCandidateAddress(const Address &addr, Time delay, bool fromRedirect)
{
	if( (S_IHELLO_SENT != m_state)
	 or (fromRedirect and (m_openingAddresses.size() >= REDIRECT_THRESHOLD))
	 or (m_openingAddresses.find(addr) != m_openingAddresses.end()) // already opening to this address
	)
		return;

	m_openingAddresses.insert(addr);

	auto myself = share_ref(this);
	m_rtmfp->scheduleRel(delay)->action = [myself, addr] (const std::shared_ptr<Timer> &sender, Time now) {
		if(S_IHELLO_SENT != myself->m_state)
		{
			sender->cancel();
			return;
		}

		myself->m_rtmfp->m_startupSession->sendPacket(myself->m_ihello, 0, -1, addr.getSockaddr());

		Time interval = sender->getRecurInterval();
		interval = (interval < IHELLO_INITIAL_RTX) ? IHELLO_INITIAL_RTX : interval + IHELLO_BACKOFF_INTERVAL;
		sender->setRecurInterval(interval);
	};
}

void Session::replayEarlyPackets()
{
	while(not m_earlyPackets.empty())
	{
		auto &packet = m_earlyPackets.front();
		ISession::onReceivePacket(packet.data(), packet.size(), m_destInterfaceID, m_destAddr.getSockaddr(), m_rtmfp->m_plaintextBuf);
		m_earlyPackets.pop();
	}
}

void Session::bindFlow(std::shared_ptr<SendFlow> flow)
{
	flow->m_flow_id = m_sendFlows.append(flow);
	m_rtmfp->sendFlowIsNotOpening(flow);
}

void Session::unbindFlow(long flowID, SendFlow *flow)
{
	if(m_sendFlows.has(flowID) and (flow == m_sendFlows.at(flowID).get()))
		m_sendFlows.remove(flowID);
	m_last_idle_time = m_rtmfp->getCurrentTime();
}

void Session::unbindFlow(long flowID, RecvFlow *flow)
{
	auto it = m_recvFlows.find(flowID);
	if((it != m_recvFlows.end()) and (it->second.get() == flow))
		m_recvFlows.erase(flowID);
	m_last_idle_time = m_rtmfp->getCurrentTime();
}

void Session::startIIKeying(const Bytes &iikeyingChunk)
{
	if(m_iikeyingTimer)
		m_iikeyingTimer->cancel();
	m_iikeyingTimer.reset();

	if(S_KEYING_SENT != m_state)
		return;

	auto myself = share_ref(this);

	m_iikeyingTimer = m_rtmfp->scheduleRel(0);
	m_iikeyingTimer->action = [myself, iikeyingChunk] (const std::shared_ptr<Timer> &sender, Time now) {
		if(S_KEYING_SENT != myself->m_state)
		{
			myself->m_iikeyingTimer.reset();
			sender->cancel();
			return;
		}

		myself->m_rtmfp->m_startupSession->sendPacket(iikeyingChunk, 0, myself->m_destInterfaceID, myself->m_destAddr.getSockaddr());
		Time interval = sender->getRecurInterval();
		interval = (interval < IIKEYING_INITIAL_RTX) ? IIKEYING_INITIAL_RTX : interval + IIKEYING_BACKOFF_INTERVAL;
		sender->setRecurInterval(interval);
	};
}

bool Session::makeIIKeyingChunk(const Bytes &cookie, const Bytes &skic, Bytes &dst)
{
	uint8_t buf[MAX_STARTUP_PACKET_LENGTH];
	PacketAssembler chunk;
	chunk.init(buf, 0, sizeof(buf));
	chunk.startChunk(CHUNK_IIKEYING);
	const uint8_t *signedParameters = chunk.m_cursor;
	if( (not chunk.push(&m_rxSessionID, sizeof(m_rxSessionID)))
	 or (not chunk.pushField(cookie))
	 or (not chunk.pushField(m_rtmfp->m_crypto->getNearEncodedCertForEPD(nullptr, 0)))
	 or (not chunk.pushField(skic))
	)
		return false;

	const uint8_t *signedParametersLimit = chunk.m_cursor;
	if(not chunk.push(m_rtmfp->m_crypto->sign(signedParameters, signedParametersLimit - signedParameters, m_cryptoCert)))
		return false;

	chunk.commitChunk();
	dst = chunk.toVector();
	return true;
}

long Session::getTimestampIfNew()
{
	long timestamp = m_rtmfp->getCurrentTimestamp();
	return (timestamp != m_ts_tx) ? timestamp : -1;
}

long Session::getTimestampEcho()
{
	Time ts_rx_elapsed = m_rtmfp->getCurrentTime() - m_ts_rx_time;
	if(ts_rx_elapsed > MAX_TS_ECHO_ELAPSED)
	{
		m_ts_rx = -1;
		m_ts_echo_tx = -1;
		return -1;
	}

	long ts_rx_elapsed_ticks = (long)(ts_rx_elapsed * HEADER_TIMESTAMP_SCALE);
	long ts_echo = (m_ts_rx + ts_rx_elapsed_ticks) & 0xffff;
	if(ts_echo != m_ts_echo_tx)
		return ts_echo;

	return -1;
}

void Session::scheduleAck(std::shared_ptr<RecvFlow> flow)
{
	if(S_OPEN != m_state)
		return;

	m_ackFlows.append(flow);

	if((not m_ack_now) and not m_delack_alarm)
	{
		m_delack_alarm = m_rtmfp->scheduleRel(DELACK_ALARM_PERIOD);
		auto myself = share_ref(this);
		m_delack_alarm->action = Timer::makeAction([myself] { myself->ackNow(); });
	}
}

void Session::ackNow()
{
	if(S_OPEN != m_state)
		return;

	if(not m_ack_now)
	{
		m_ack_now = true;
		m_rtmfp->scheduleWrite(m_destInterfaceID, share_ref(this), PRI_IMMEDIATE);
	}
	if(m_delack_alarm)
	{
		m_delack_alarm->cancel();
		m_delack_alarm.reset();
	}
}

bool Session::sendAcks(PacketAssembler *packet, bool obligatory)
{
	bool didAck = false;
	bool truncateAllowed = obligatory;

	if(obligatory and not m_ack_now)
		return false;

	while(not m_ackFlows.empty())
	{
		if(m_ackFlows.firstValue()->assembleAck(packet, truncateAllowed))
		{
			didAck = true;
			truncateAllowed = false;
			m_ackFlows.removeFirst();
		}
		else
			break;
	}

	if(m_ackFlows.empty())
	{
		m_ack_now = false;
		m_rx_data_packets = 0;
		if(m_delack_alarm)
		{
			m_delack_alarm->cancel();
			m_delack_alarm.reset();
		}
	}

	return didAck;
}

void Session::sendPacket(const Bytes &chunks)
{
	m_rtmfp->m_startupSession->sendPacket(chunks, m_txSessionID, m_destInterfaceID, m_destAddr.getSockaddr(), share_ref(this));
}

void Session::scheduleFlowForTransmission(const std::shared_ptr<SendFlow> &flow, Priority pri)
{
	if(not m_readyFlows[pri].find(flow))
	{
		m_readyFlows[pri].append(flow);
		m_rtmfp->scheduleWrite(m_destInterfaceID, share_ref(this), pri);
	}
}

void Session::rescheduleTimeoutAlarm()
{
	if(m_timeout_alarm)
		m_timeout_alarm->setNextFireTime(m_rtmfp->getCurrentTime() + m_erto);
	else
	{
		m_timeout_alarm = m_rtmfp->scheduleRel(m_erto);
		m_timeout_alarm->action = Timer::makeAction([this] { this->onTimeoutAlarm(); });
	}

	m_retransmit_deadline_epoch = std::min(m_retransmit_deadline_epoch, m_rtmfp->getCurrentTime());
}

void Session::onTimeoutAlarm()
{
	m_timeout_alarm.reset();

	m_data_packet_count = 0;
	m_ssthresh = std::max(m_ssthresh, (m_cwnd * 3) / 4); // RFC 7016 §A.2
	m_acked_bytes_accumulator = 0;
	m_recovery_remaining = 0;

	if(S_OPEN != m_state)
		return;

	if(m_outstandingFrags.empty() and not m_keepalive_outstanding)
	{
		m_cwnd = CWND_INIT;
		m_retransmit_deadline_epoch = INFINITY;
		setKeepaliveAlarm();
	}
	else
	{
		if(m_rtmfp->getCurrentTime() >= m_retransmit_deadline_epoch + m_retransmit_limit)
		{
			close(true);
			return;
		}

		m_outstandingFrags.valuesDo([] (std::shared_ptr<SendFlow::SendFrag> &each) {
			each->m_in_flight = false;
			each->m_session_outstanding_name = -1;
			each->m_owner->onLoss(each->m_transmit_size);
			return true;
		});
		m_outstandingFrags.clear();
		m_cwnd = CWND_TIMEDOUT;

		m_erto = std::max(std::min(m_erto * ERTO_BACKOFF_FACTOR, MAX_ERTO), m_mrto);

		rescheduleTransmission();

		if(m_keepalive_outstanding)
			sendKeepalivePing();
	}
}

void Session::rescheduleTransmission()
{
	auto myself = share_ref(this);

	for(int pri = PRI_HIGHEST; pri >= PRI_LOWEST; pri--)
		if(not m_readyFlows[pri].empty())
			m_rtmfp->scheduleWrite(m_destInterfaceID, myself, pri);
}

static inline size_t MIN(size_t l, size_t r)
{
	return l < r ? l : r;
}

static inline size_t MAX(size_t l, size_t r)
{
	return l > r ? l : r;
}

// implement CWND algorithm described in RFC 7016 Appendix A (page 112), with modifications
void Session::updateCWND(size_t acked_bytes_this_packet, size_t lost_bytes_this_packet, bool any_loss, bool any_naks)
{
	Time now = m_rtmfp->getCurrentTime();
	bool fastgrow_allowed = (m_tcr_recv_time + TIMECRITICAL_TIMEOUT < now) and (m_rtmfp->m_tc_sent_time + TIMECRITICAL_TIMEOUT < now);
	bool tc_sent = m_tc_sent_time + TIMECRITICAL_TIMEOUT >= now;

	size_t drained_bytes_this_packet = acked_bytes_this_packet + lost_bytes_this_packet;
	if(m_recovery_remaining > drained_bytes_this_packet)
	{
		m_recovery_remaining -= drained_bytes_this_packet;
		return;
	}
	else
		m_recovery_remaining = 0;

	if(any_loss)
	{
		if(tc_sent or ((m_pre_ack_outstanding > 67200) and fastgrow_allowed))
			m_ssthresh = m_pre_ack_outstanding * 7 / 8;
		else
			m_ssthresh = m_pre_ack_outstanding / 2;
		m_ssthresh = MAX(m_ssthresh, CWND_INIT);
		m_cwnd = m_ssthresh;
		m_acked_bytes_accumulator = 0;
		m_recovery_remaining = m_outstandingFrags.sum();
	}
	else if((not any_naks) and (m_pre_ack_outstanding > m_cwnd * 63 / 64))
	{
		size_t increase = 0;

		if(fastgrow_allowed)
		{
			if(m_cwnd < m_ssthresh)
			{
				increase = acked_bytes_this_packet;
				m_acked_bytes_accumulator = 0;
			}
			else
			{
				size_t aithresh = MIN(MAX(m_cwnd / 16, 64), 4800);
				m_acked_bytes_accumulator += acked_bytes_this_packet;

				while(m_acked_bytes_accumulator >= aithresh)
				{
					m_acked_bytes_accumulator -= aithresh;
					increase += 48;
				}
			}
		}
		else
		{
			if(tc_sent and (m_cwnd < m_ssthresh))
			{
				increase = (acked_bytes_this_packet + 3) / 4;
				m_acked_bytes_accumulator = 0;
			}
			else
			{
				size_t aithresh = MIN(MAX(m_cwnd / 16, 64), 4800);
				m_acked_bytes_accumulator += acked_bytes_this_packet;

				while(m_acked_bytes_accumulator >= aithresh)
				{
					m_acked_bytes_accumulator -= aithresh;
					increase += tc_sent ? 48 : 24;
				}
			}
		}

		m_cwnd = MAX(m_cwnd + MIN(increase, SENDER_MSS), CWND_INIT);
	}
	else if((not any_naks) and m_cwnd > m_pre_ack_outstanding + CWND_DECAY_MARGIN)
		m_cwnd -= CWND_DECAY_SIZE;
}

void Session::scheduleBurstAlarm()
{
	m_burst_alarm = m_rtmfp->scheduleRel(DATA_PACKET_BURST_PERIOD);
	m_burst_alarm->action = [this] (const std::shared_ptr<Timer> &sender, Time now) {
		m_burst_alarm.reset();
		m_data_packet_count = 0;
		rescheduleTransmission();
	};
}

namespace {

struct InitiatorState {
	InitiatorState(unsigned long threadNum, const uint8_t *cookie, size_t cookieLen, const uint8_t *cert, size_t certLen, std::shared_ptr<CryptoCert> cryptoCert, int interfaceID, const struct sockaddr *addr) :
		m_threadNum(threadNum),
		m_cryptoCert(cryptoCert),
		m_cookie(cookie, cookie + cookieLen),
		m_interfaceID(interfaceID),
		m_addr(addr)
	{}

	unsigned long m_threadNum;
	std::shared_ptr<CryptoCert> m_cryptoCert;
	Bytes   m_cookie;
	Bytes   m_canonicalEPD;
	Bytes   m_skic;
	Bytes   m_iikeying;
	int     m_interfaceID;
	Address m_addr;
};

}

void Session::onRHello(std::shared_ptr<Session> myself, const uint8_t *cookie, size_t cookieLen, const uint8_t *cert, size_t certLen, int interfaceID, const struct sockaddr *addr)
{
	auto cryptoCert = myself->m_rtmfp->m_crypto->decodeCertificate(cert, certLen);

	if((S_IHELLO_SENT != myself->m_state) or (not cryptoCert) or (not cryptoCert->isSelectedByEPD(myself->m_epd.data(), myself->m_epd.size())))
		return;

	auto state = std::make_shared<InitiatorState>(myself->m_rtmfp->getNextThreadNum(), cookie, cookieLen, cert, certLen, cryptoCert, interfaceID, addr);
	myself->m_rtmfp->m_platform->perform(state->m_threadNum, [myself, state] {
		state->m_cryptoCert->isAuthentic([myself, state] { myself->m_rtmfp->m_platform->perform(0, [myself, state] {
			if(S_IHELLO_SENT != myself->m_state) // still
				return;

			state->m_canonicalEPD = state->m_cryptoCert->getCanonicalEPD();
			auto existingSession = myself->m_rtmfp->findOpenSessionByEPD(state->m_canonicalEPD);
			if(existingSession and existingSession->m_cryptoCert->isSelectedByEPD(myself->m_epd.data(), myself->m_epd.size()))
			{
				myself->m_rtmfp->onSessionDidOpen(existingSession);
				myself->abort();
				return;
			}

			existingSession = myself->m_rtmfp->findOpeningSessionByEPD(state->m_canonicalEPD, myself.get());
			if(existingSession)
			{
				myself->m_rtmfp->onSessionWillOpen(existingSession);
				myself->abort();
				return;
			}

			myself->m_state = S_KEYING_SENT;
			myself->m_destInterfaceID = state->m_interfaceID;
			myself->m_destAddr = state->m_addr;
			myself->m_resp_cookie = state->m_cookie;
			myself->m_cryptoCert = state->m_cryptoCert;

			myself->m_rtmfp->m_platform->perform(state->m_threadNum, [myself, state] {
				if( (not myself->m_cryptoKey->generateInitiatorKeyingComponent(state->m_cryptoCert, &state->m_skic))
				 or (not myself->makeIIKeyingChunk(state->m_cookie, state->m_skic, state->m_iikeying))
				)
				{
					myself->m_rtmfp->m_platform->perform(0, [myself] { myself->abort(); });
					return;
				}

				myself->m_rtmfp->m_platform->perform(0, [myself, state] {
					myself->m_skic = state->m_skic;
					myself->startIIKeying(state->m_iikeying);
				});
			});
		});
	}); });
}

void Session::onCookieChange(const uint8_t *oldCookie_, size_t oldCookieLen, const uint8_t *newCookie_, size_t newCookieLen, int interfaceID, const struct sockaddr *addr)
{
	Bytes oldCookie(oldCookie_, oldCookie_ + oldCookieLen);

	if( (S_KEYING_SENT != m_state)
	 or (m_resp_cookieChanged)
	 or (oldCookie != m_resp_cookie)
	)
		return;

	m_resp_cookieChanged = true;
	m_resp_cookie = Bytes(newCookie_, newCookie_ + newCookieLen);

	auto myself = share_ref(this);
	m_rtmfp->m_platform->perform(m_rtmfp->getNextThreadNum(), [myself] {
		Bytes iikeying;
		if(not myself->makeIIKeyingChunk(myself->m_resp_cookie, myself->m_skic, iikeying))
		{
			myself->m_rtmfp->m_platform->perform(0, [myself] { myself->abort(); });
			return;
		}

		myself->m_rtmfp->m_platform->perform(0, [myself, iikeying] { myself->startIIKeying(iikeying); });
	});
}

namespace {

struct RIKeyingState {
	RIKeyingState(unsigned long threadNum, uint32_t rsid, const uint8_t *skrc, size_t skrcLen, const uint8_t *signedParameters, size_t signedParametersLen, const uint8_t *sig, size_t sigLen) :
		m_threadNum(threadNum),
		m_responderSessionID(rsid),
		m_skrc(skrc, skrc + skrcLen),
		m_signedParameters(signedParameters, signedParameters + signedParametersLen),
		m_signature(sig, sig + sigLen)
	{}

	unsigned long m_threadNum;
	uint32_t      m_responderSessionID;
	Bytes         m_skrc;
	Bytes         m_signedParameters;
	Bytes         m_signature;
};

}

void Session::onRIKeying(uint32_t responderSessionID, const uint8_t *skrc, size_t skrcLen, const uint8_t *signedParameters, size_t signedParametersLen, const uint8_t *sig, size_t sigLen, int interfaceID, const struct sockaddr *addr)
{
	if(S_KEYING_SENT != m_state)
		return;

	auto myself = share_ref(this);
	auto state = std::make_shared<RIKeyingState>(m_rtmfp->getNextThreadNum(), responderSessionID, skrc, skrcLen, signedParameters, signedParametersLen, sig, sigLen);

	// the signature is over the portion in the RIKeying plus the SKIC
	state->m_signedParameters.insert(state->m_signedParameters.end(), m_skic.begin(), m_skic.end());

	m_rtmfp->m_platform->perform(state->m_threadNum, [myself, state] {
		myself->m_cryptoCert->checkSignature(state->m_signedParameters.data(), state->m_signedParameters.size(), state->m_signature.data(), state->m_signature.size(), [myself, state] { myself->m_rtmfp->m_platform->perform(state->m_threadNum, [myself, state] {
			if(not myself->m_cryptoKey->initiatorCombineResponderKeyingComponent(state->m_skrc.data(), state->m_skrc.size()))
				return;

			myself->m_rtmfp->m_platform->perform(0, [myself, state] {
				if(S_KEYING_SENT != myself->m_state)
					return;

				myself->setOpen(myself, state->m_responderSessionID);
			});
		}); });
	});
}

void Session::onUserData(uint8_t flags, uintmax_t flowID, uintmax_t sequenceNumber, uintmax_t fsn, uintmax_t *associatedFlowID, const uint8_t *metadata, size_t metadataLen, const uint8_t *data, size_t len, bool mustReject)
{
	std::shared_ptr<RecvFlow> flow;

	auto flow_it = m_recvFlows.find(flowID);
	if(flow_it != m_recvFlows.end())
		flow = flow_it->second;

	if(not flow)
	{
		auto onRecvFlow_f = m_rtmfp->onRecvFlow;

		std::shared_ptr<SendFlow> associatedFlow;
		if(associatedFlowID)
		{
			if((*associatedFlowID < LONG_MAX) and m_sendFlows.has(*associatedFlowID))
			{
				associatedFlow = m_sendFlows.at(*associatedFlowID);
				onRecvFlow_f = associatedFlow->onRecvFlow;

				if(not associatedFlow->isOpen())
					mustReject = true;
			}
			else
				mustReject = true;
		}

		if(not metadata)
			mustReject = true;

		flow = share_ref(new RecvFlow(share_ref(this), flowID, metadata, metadataLen, associatedFlow), false);
		m_recvFlows[flowID] = flow;
		
		if(onRecvFlow_f and not mustReject)
			onRecvFlow_f(flow);

		if(not flow->isOpen())
			mustReject = true;
	}

	if(mustReject)
		flow->closeAndNotify(true);

	flow->onData(flags, sequenceNumber, fsn, data, len);
}

void Session::onBufferProbe(uintmax_t flowID)
{
	auto flow_it = m_recvFlows.find(flowID);
	if(flow_it != m_recvFlows.end())
		flow_it->second->scheduleAck(true);
}

void Session::onMobilityCheckReply(const uint8_t *chunk, const uint8_t *limit, uintmax_t ts, int interfaceID, const struct sockaddr *addr)
{
	if((ts <= m_mob_rx_ts) or (ts + MAX_MOBILITY_LIFETIME < (uintmax_t)(m_rtmfp->getInstanceAge())))
		return;

	if(Bytes(chunk, limit) != makeMobilityCheck(ts, interfaceID, addr))
		return;

	m_mob_rx_ts = ts;

	Address oldAddr(m_destAddr);

	m_destInterfaceID = interfaceID;
	m_destAddr.setSockaddr(addr);

	m_rtmfp->onSessionAddressDidChange(share_ref(this), oldAddr);

	rescheduleTransmission();

	m_sendFlows.safeValuesDo([] (std::shared_ptr<SendFlow> flow) {
		if(flow->onFarAddressDidChange)
			flow->onFarAddressDidChange();
		return true;
	});

	auto recvFlowsCopy = m_recvFlows;
	for(auto it = recvFlowsCopy.begin(); it != recvFlowsCopy.end(); it++)
	{
		if(it->second->onFarAddressDidChange)
			it->second->onFarAddressDidChange();
	}
}

bool Session::onInterfaceWritable(int interfaceID, int priority)
{
	if(interfaceID != m_destInterfaceID)
	{
		m_rtmfp->scheduleWrite(m_destInterfaceID, share_ref(this), priority);
		return false;
	}

	if(S_OPEN != m_state)
		return false; // other states handled by StartupSession

	long timestamp = getTimestampIfNew();
	long timestampEcho = getTimestampEcho();

	uint8_t flags = m_role;
	if(m_rtmfp->shouldSessionReportTCR(this))
		flags |= HEADER_FLAG_TCR;

	PacketAssembler packet;
	packet.init(m_rtmfp->m_plaintextBuf, m_cryptoKey->getEncryptSrcFrontMargin(), MAX_SESSION_PACKET_LENGTH, flags, timestamp, timestampEcho);
	size_t startingSize = packet.remaining();

	bool sentObligatoryAcks = sendAcks(&packet, true);
	if((not sentObligatoryAcks) and (m_cwnd > m_outstandingFrags.sum()))
	{
		if(m_data_packet_count < MAX_DATA_PACKET_BURST)
		{
			List<std::shared_ptr<SendFlow> > &flows = m_readyFlows[priority];
			while(not flows.empty())
			{
				if(flows.firstValue()->assembleData(&packet, priority))
				{
					flows.moveNameToTail(flows.first());
					m_data_packet_count++;
					break;
				}
				else
					flows.removeFirst();
			}
		}
		else
		{
			if((m_srtt > BURST_RTT_THRESH) and not m_burst_alarm)
				scheduleBurstAlarm();
		}
	}

	if(packet.remaining() == startingSize)
		return false;

	// else we put something in the packet, try to piggyback any waiting acks
	sendAcks(&packet, false);

	Time now = m_rtmfp->getCurrentTime();

	if(timestamp >= 0)
		m_ts_tx = timestamp;
	if(timestampEcho >= 0)
		m_ts_echo_tx = timestampEcho;
	if(packet.getTimeCriticalFlag())
		m_rtmfp->m_tc_sent_time = m_tc_sent_time = now;

	m_last_keepalive_tx_time = now;

	encryptAndSendPacket(&packet, m_txSessionID, interfaceID, m_destAddr, m_cryptoKey.get());

	return true;
}

bool Session::onReceivePacket(const uint8_t *bytes, size_t len, int interfaceID, const struct sockaddr *addr, uint8_t *decryptBuf)
{
	bool rv = ISession::onReceivePacket(bytes, len, interfaceID, addr, decryptBuf);

	if((not rv) and (S_KEYING_SENT == m_state))
	{
		m_earlyPackets.push(Bytes(bytes, bytes + len));
		while(m_earlyPackets.size() > MAX_EARLY_PACKETS)
			m_earlyPackets.pop();
	}

	return rv;
}

bool Session::onPacketHeader(uint8_t flags, long timestamp, long timestampEcho)
{
	uint8_t mode = flags & HEADER_FLAG_MOD_MASK;
	if((0 == mode) or (m_role == mode))
		return false;

	m_seenUserDataThisPacket = false;
	m_any_acks = false;
	m_pre_ack_outstanding = m_outstandingFrags.sum();

	if((S_OPEN == m_state) or (S_KEYING_SENT == m_state))
	{
		if((timestamp >= 0) and (timestamp != m_ts_rx))
		{
			m_ts_rx = timestamp;
			m_ts_rx_time = m_rtmfp->getCurrentTime();
		}
	}

	if(S_OPEN == m_state)
	{
		if((timestampEcho >= 0) and (timestampEcho != m_ts_echo_rx))
		{
			m_ts_echo_rx = timestampEcho;
			uint16_t rtt_ticks = m_rtmfp->getCurrentTimestamp() - timestampEcho;
			if(rtt_ticks < 32768)
			{
				Time rtt = rtt_ticks;
				rtt *= HEADER_TIMESTAMP_PERIOD;
				if(m_srtt >= 0.0)
				{
					Time rtt_delta = m_srtt - rtt;
					if(rtt_delta < 0.0)
						rtt_delta = -rtt_delta;
					m_rttvar = ((3.0 * m_rttvar) + rtt_delta) / 4.0;
					m_srtt = ((7.0 * m_srtt) + rtt) / 8.0;
				}
				else
				{
					m_srtt = rtt;
					m_rttvar = rtt / 2.0;
				}

				m_mrto = m_srtt + 4.0 * m_rttvar + DELACK_ALARM_PERIOD;
				m_erto = std::max(m_mrto, MINIMUM_ERTO);
			}
		}

		if(flags & HEADER_FLAG_TC)
			m_rtmfp->onSessionReceivedTC(this);

		if(flags & HEADER_FLAG_TCR)
			m_tcr_recv_time = m_rtmfp->getCurrentTime();
	}

	return true;
}

void Session::onChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr)
{
	if(S_KEYING_SENT == m_state)
	{
		if(HEADER_MODE_STARTUP != mode)
			return;

		switch(chunkType)
		{
		case CHUNK_RIKEYING:
			onRIKeyingChunk(mode, chunkType, chunk, limit, interfaceID, addr);
			break;
		case CHUNK_RHELLO_COOKIE_CHANGE:
			onCookieChangeChunk(mode, chunkType, chunk, limit, interfaceID, addr);
			break;
		default:
			break;
		}
	}
	else if(HEADER_MODE_STARTUP != mode)
	{
		if(S_OPEN == m_state)
		{
			switch(chunkType)
			{
			case CHUNK_FIHELLO:
				onFIHelloChunk(mode, chunkType, chunk, limit, interfaceID, addr);
				break;

			case CHUNK_PING:
				onPingChunk(mode, chunkType, chunk, limit, interfaceID, addr);
				break;
			case CHUNK_PING_REPLY:
				onPingReplyChunk(mode, chunkType, chunk, limit, interfaceID, addr);
				break;

			case CHUNK_USERDATA:
			case CHUNK_NEXT_USERDATA:
				onUserDataChunk(mode, chunkType, chunk, limit, interfaceID, addr);
				break;

			case CHUNK_BUFFERPROBE:
				onBufferProbeChunk(mode, chunkType, chunk, limit, interfaceID, addr);
				break;

			case CHUNK_ACK_BITMAP:
			case CHUNK_ACK_RANGES:
				onAckChunk(mode, chunkType, chunk, limit, interfaceID, addr);
				break;
			case CHUNK_EXCEPTION:
				onExceptionChunk(mode, chunkType, chunk, limit, interfaceID, addr);
				break;

			default:
				break;
			}
		}

		if((S_OPEN == m_state) or (S_NEARCLOSE == m_state) or (S_FARCLOSE_LINGER == m_state))
		{
			switch(chunkType)
			{
			case CHUNK_CLOSE:
				onCloseChunk(mode, chunkType, chunk, limit, interfaceID, addr);
				break;
			case CHUNK_CLOSE_ACK:
				onCloseAckChunk(mode, chunkType, chunk, limit, interfaceID, addr);
				break;
			default:
				break;
			}
		}
	}
}

void Session::onPacketAfterChunks(uint8_t flags, long timestamp, long timestampEcho, int interfaceID, const struct sockaddr *addr)
{
	if(m_seenUserDataThisPacket)
		m_rx_data_packets++;

	if(m_rx_data_packets >= OBLIGATORY_ACK_AFTER)
		ackNow();

	if(m_any_acks)
	{
		size_t acked_bytes_this_packet = m_pre_ack_outstanding - m_outstandingFrags.sum();
		size_t lost_bytes_this_packet = 0;

		m_data_packet_count = 0;
		if(m_burst_alarm)
			m_burst_alarm->cancel();
		m_burst_alarm.reset();

		// Negative Acknowledgement
		bool any_loss = false;
		bool any_naks = false;
		long name = m_outstandingFrags.first();
		while(name > 0)
		{
			long next = m_outstandingFrags.next(name);
			auto &each = m_outstandingFrags.at(name);

			if(each->m_tsn > m_max_tsn_ack)
				break;

			each->m_nak_count++;
			if(not each->m_sent_abandoned)
				any_naks = true;

			if(each->m_nak_count >= NAKS_FOR_LOSS)
			{
				each->m_in_flight = false;
				each->m_session_outstanding_name = -1;
				if(not each->m_sent_abandoned)
					any_loss = true;

				each->m_owner->onLoss(each->m_transmit_size);
				lost_bytes_this_packet += each->m_transmit_size;

				m_outstandingFrags.remove(name);
			}

			name = next;
		}

		updateCWND(acked_bytes_this_packet, lost_bytes_this_packet, any_loss, any_naks);

		rescheduleTransmission();
		rescheduleTimeoutAlarm();
	}

	// check for mobility
	uintmax_t now = (uintmax_t)(m_rtmfp->getInstanceAge());
	if(  (S_OPEN == m_state)
	 and (not ((interfaceID == m_destInterfaceID) and (Address(addr) == m_destAddr)))
	 and (now > m_mob_tx_ts)
	)
		sendMobilityCheck(now, interfaceID, addr);
}

void Session::onRIKeyingChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr)
{
	size_t rv;
	const uint8_t *cursor = chunk;
	const uint8_t *signedParameters = chunk;
	size_t signedParametersLen;
	uint32_t responderSessionID;
	const uint8_t *skrc;
	size_t skrcLen;
	const uint8_t *signature;
	size_t signatureLen;

	if(size_t(limit - chunk) < sizeof(uint32_t))
		return;

	memmove(&responderSessionID, cursor, sizeof(responderSessionID));
	cursor += sizeof(responderSessionID);

	if(0 == (rv = VLU::parseField(cursor, limit, &skrc, &skrcLen)))
		return;
	cursor += rv;

	signedParametersLen = cursor - signedParameters;

	signature = cursor;
	signatureLen = limit - cursor;

	onRIKeying(responderSessionID, skrc, skrcLen, signedParameters, signedParametersLen, signature, signatureLen, interfaceID, addr);
}

void Session::onCookieChangeChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr)
{
	size_t rv;
	const uint8_t *cursor = chunk;
	const uint8_t *oldCookie;
	size_t oldCookieLen;
	const uint8_t *newCookie;
	size_t newCookieLen;

	if(0 == (rv = VLU::parseField(cursor, limit, &oldCookie, &oldCookieLen)))
		return;
	cursor += rv;

	newCookie = cursor;
	newCookieLen = limit - cursor;

	onCookieChange(oldCookie, oldCookieLen, newCookie, newCookieLen, interfaceID, addr);
}

void Session::onFIHelloChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr)
{
	size_t rv;
	const uint8_t *cursor = chunk;
	const uint8_t *epd;
	size_t epdLen;
	Address replyAddress;
	const uint8_t *tag;
	size_t tagLen;

	if(0 == (rv = VLU::parseField(cursor, limit, &epd, &epdLen)))
		return;
	cursor += rv;

	if(0 == (rv = replyAddress.setFromEncoding(cursor, limit)))
		return;
	cursor += rv;

	tag = cursor;
	tagLen = limit - cursor;

	m_rtmfp->onIHello(epd, epdLen, tag, tagLen, -1, replyAddress.getSockaddr(), m_fihelloMode);
}

void Session::onUserDataChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr)
{
	size_t rv;
	const uint8_t *cursor = chunk;
	uint8_t flags;
	uintmax_t flowID;
	uintmax_t sequenceNumber;
	uintmax_t fsnOffset;
	uintmax_t fsn;
	uintmax_t associatedFlowID = 0;
	uintmax_t *associatedFlowIDPtr = nullptr;
	const uint8_t *metadata = nullptr;
	size_t metadataLen = 0;
	const uint8_t *userData;
	size_t userDataLen;
	bool mustReject = false;

	if(cursor >= limit)
		return;
	flags = *cursor++;

	if(CHUNK_USERDATA == chunkType)
	{
		if(0 == (rv = VLU::parse(cursor, limit, &flowID)))
			return;
		cursor += rv;

		if(0 == (rv = VLU::parse(cursor, limit, &sequenceNumber)))
			return;
		cursor += rv;

		if(0 == (rv = VLU::parse(cursor, limit, &fsnOffset)))
			return;
		cursor += rv;

		if(fsnOffset > sequenceNumber)
			return;

		fsn = sequenceNumber - fsnOffset;
	}
	else if(CHUNK_NEXT_USERDATA == chunkType)
	{
		if(not m_seenUserDataThisPacket)
			return;

		flowID = m_parsingFlowID;
		sequenceNumber = m_parsingSequenceNumber + 1;
		fsn = m_parsingFSN;
	}
	else
		return;

	if(flags & USERDATA_FLAG_OPT)
	{
		while(true)
		{
			if(cursor >= limit)
				return;

			uintmax_t optionType;
			const uint8_t *optionValue;
			size_t optionValueLen;

			if(0 == (rv = Option::parse(cursor, limit, &optionType, &optionValue, &optionValueLen)))
				return;
			cursor += rv;

			if(nullptr == optionValue)
				break; // marker, done parsing option list

			switch(optionType)
			{
			case USERDATA_OPTION_METADATA:
				metadata = optionValue;
				metadataLen = optionValueLen;
				break;

			case USERDATA_OPTION_RETURN_ASSOCIATION:
				if(0 == VLU::parse(optionValue, optionValue + optionValueLen, &associatedFlowID))
					return;
				associatedFlowIDPtr = &associatedFlowID;
				break;

			default:
				if(optionType < USERDATA_OPTION_MANDATORY_CUTOFF)
					mustReject = true;
				break;
			}
		}
	}

	userData = cursor;
	userDataLen = limit - cursor;

	m_parsingFlowID = flowID;
	m_parsingSequenceNumber = sequenceNumber;
	m_parsingFSN = fsn;
	m_seenUserDataThisPacket = true; // wait til now in case there were problems parsing options

	onUserData(flags, flowID, sequenceNumber, fsn, associatedFlowIDPtr, metadata, metadataLen, userData, userDataLen, mustReject);
}

void Session::onBufferProbeChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr)
{
	uintmax_t flowID;

	if(0 == VLU::parse(chunk, limit, &flowID))
		return;

	onBufferProbe(flowID);
}

void Session::onExceptionChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr)
{
	const uint8_t *cursor = chunk;
	uintmax_t flowID;
	uintmax_t exceptionCode;
	size_t rv;

	if(0 == (rv = VLU::parse(cursor, limit, &flowID)))
		return;
	cursor += rv;

	if(0 == VLU::parse(cursor, limit, &exceptionCode))
		return;

	if(m_sendFlows.has(flowID))
		m_sendFlows.at(flowID)->onExceptionReport(exceptionCode);
}

void Session::onPingChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr)
{
	uint8_t buf[MAX_PING_MESSAGE_LENGTH];
	PacketAssembler pingReply;
	pingReply.init(buf, 0, sizeof(buf));
	pingReply.startChunk(CHUNK_PING_REPLY);
	if(not pingReply.push(chunk, limit - chunk))
		return;
	pingReply.commitChunk();
	sendPacket(pingReply.toVector());
	m_last_keepalive_tx_time = m_rtmfp->getCurrentTime();
}

void Session::onPingReplyChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr)
{
	m_keepalive_outstanding = false;
	m_retransmit_deadline_epoch = INFINITY;

	if(limit == chunk)
		return;

	const uint8_t *cursor = chunk;
	uint8_t marking = *cursor++;

	if(PING_MARKING_MOBILITY == marking)
	{
		uintmax_t ts;
		if(0 == VLU::parse(cursor, limit, &ts))
			return;

		onMobilityCheckReply(chunk, limit, ts, interfaceID, addr);
		return;
	}
}

void Session::onAckChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr)
{
	const uint8_t *cursor = chunk;
	size_t rv;
	uintmax_t flowID;
	uintmax_t bufferBlocksAvailable;
	uintmax_t cumulativeAck;

	if(0 == (rv = VLU::parse(cursor, limit, &flowID)))
		return;
	cursor += rv;

	if(0 == (rv = VLU::parse(cursor, limit, &bufferBlocksAvailable)))
		return;
	cursor += rv;

	if(0 == (rv = VLU::parse(cursor, limit, &cumulativeAck)))
		return;
	cursor += rv;

	if(m_sendFlows.has(flowID))
	{
		size_t bufferBytesAvailable;
		if(bufferBlocksAvailable > SIZE_MAX / 1024)
			bufferBytesAvailable = SIZE_MAX;
		else
			bufferBytesAvailable = bufferBlocksAvailable * 1024;

		m_sendFlows.at(flowID)->onAck(chunkType, bufferBytesAvailable, cumulativeAck, cursor, limit);
		m_any_acks = true;
		m_keepalive_outstanding = false;
		m_retransmit_deadline_epoch = INFINITY;
	}
}

void Session::onCloseChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr)
{
	switch(m_state)
	{
	case S_OPEN:
		setFarcloseLinger();
		// fall-through
	case S_NEARCLOSE:
	case S_FARCLOSE_LINGER:
		sendClose(true);
		break;

	default:
		break;
	}
}

void Session::onCloseAckChunk(uint8_t mode, uint8_t chunkType, const uint8_t *chunk, const uint8_t *limit, int interfaceID, const struct sockaddr *addr)
{
	switch(m_state)
	{
	case S_OPEN:
		sendClose(true);
		// fall-through
	case S_NEARCLOSE:
	case S_FARCLOSE_LINGER:
		abort();
		break;

	default:
		break;
	}
}

} } } // namespace com::zenomt::rtmfp
