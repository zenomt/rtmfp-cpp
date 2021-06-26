// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cstdlib>
#include <cstring>

#include "../include/rtmfp/rtmfp.hpp"
#include "Interface.hpp"
#include "../include/rtmfp/VLU.hpp"
#include "../include/rtmfp/packet.hpp"
#include "../include/rtmfp/params.hpp"
#include "../include/rtmfp/PacketAssembler.hpp"

namespace com { namespace zenomt { namespace rtmfp {

RTMFP::RTMFP(IPlatformAdapter *platformAdapter, ICryptoAdapter *cryptoAdapter) :
	m_platform(platformAdapter),
	m_crypto(cryptoAdapter),
	m_plaintextBuf(nullptr),
	m_nextThreadNum(0),
	m_waitingPerformCount(0),
	m_sessionReportingTC(0),
	m_sessionTC_time(-INFINITY),
	m_previous_sessionTC_time(-INFINITY),
	m_tc_sent_time(-INFINITY),
	m_default_session_keepalive_period(DEFAULT_KEEPALIVE_PERIOD),
	m_default_session_retransmit_limit(DEFAULT_RTX_LIMIT),
	m_default_session_idle_limit(DEFAULT_IDLE_LIMIT),
	m_shutdown(false),
	m_shutdownComplete(false)
{
	m_timers.onHowLongToSleepDidChange = [this] { m_platform->onHowLongToSleepDidChange(); };
	m_plaintextBuf = (uint8_t *)malloc(DECRYPT_BUF_LENGTH);
	m_ciphertextBuf = (uint8_t *)malloc(ENCRYPT_BUF_LENGTH + ENCRYPT_BUF_MARGIN);

	if((not m_plaintextBuf) or (not m_ciphertextBuf))
		goto fail;

	m_startupSession = share_ref(new StartupSession(this, m_crypto->getKeyForNewSession()), false);
	m_epoch = getCurrentTime();

	m_crypto->pseudoRandomBytes(m_secret, sizeof(m_secret));

	return;

fail:
#if __cpp_exceptions
	throw std::bad_alloc();
#else
	abort();
#endif
}

RTMFP::~RTMFP()
{
	if(m_plaintextBuf)
		free(m_plaintextBuf);
	m_plaintextBuf = nullptr;

	if(m_ciphertextBuf)
		free(m_ciphertextBuf);
	m_ciphertextBuf = nullptr;
}

std::shared_ptr<SendFlow> RTMFP::openFlow(const void *epd_, size_t epdLen, const void *metadataBytes_, size_t metadataLen, Priority pri)
{
	const uint8_t *epd = (const uint8_t *)epd_;
	const uint8_t *metadataBytes = (const uint8_t *)metadataBytes_;
	return openFlow(Bytes(epd, epd + epdLen), Bytes(metadataBytes, metadataBytes + metadataLen), pri);
}

std::shared_ptr<SendFlow> RTMFP::openFlow(const Bytes &epd, const Bytes &metadata, Priority pri)
{
	std::shared_ptr<SendFlow> rv;

	if(m_shutdown or metadata.size() > MAX_METADATA_LENGTH)
		return rv;

	rv = share_ref(new SendFlow(this, epd, metadata, nullptr, pri), false);
	auto session = findOpenSessionByEPD(epd);
	if(session)
	{
		rv->onSessionDidOpen(rv, session);
		return rv;
	}

	session = findOpeningSessionByEPD(epd, nullptr);
	if(not session)
	{
		session = makeSession(m_crypto->getKeyForNewSession(), HEADER_MODE_INITIATOR);
		session->initiateToEPD(session, epd);
		m_openingSessions.append(session);
	}

	rv->m_openingSession = session;
	m_openingFlows.append(rv);
	session->interestUp();

	return rv;
}

void RTMFP::shutdown(bool immediately)
{
	m_shutdown = true;
	auto myself = share_ref(this);
	m_platform->perform(0, [myself, immediately] {
		myself->m_sessions.safeValuesDo([immediately] (std::shared_ptr<Session> &session) {
			session->close(not immediately);
			return true;
		});

		myself->m_openingSessions.safeValuesDo([] (std::shared_ptr<Session> &session) {
			session->abort();
			return true;
		});

		myself->checkShutdownComplete();
	});
}

void RTMFP::sendResponderRedirect(const void *tag, size_t tagLen, const std::vector<Address> &addrs, int interfaceID, const struct sockaddr *dstAddr)
{
	PacketAssembler packet;
	uint8_t tmp[MAX_STARTUP_PACKET_LENGTH];
	packet.init(tmp, 0, sizeof(tmp));

	if(not (packet.startChunk(CHUNK_REDIRECT) and packet.pushField((const uint8_t *)tag, tagLen)))
		return;

	for(auto it = addrs.begin(); it != addrs.end(); it++)
		if(not packet.push(it->encode()))
			return;

	packet.commitChunk();

	m_startupSession->sendPacket(packet.toVector(), 0, interfaceID, dstAddr);
}

void RTMFP::setDefaultSessionKeepalivePeriod(Time keepalive)
{
	m_default_session_keepalive_period = keepalive;
}

Time RTMFP::getDefaultSessionKeepalivePeriod() const
{
	return m_default_session_keepalive_period;
}

void RTMFP::setDefaultSessionRetransmitLimit(Time limit)
{
	m_default_session_retransmit_limit = limit;
}

Time RTMFP::getDefaultSessionRetransmitLimit() const
{
	return m_default_session_retransmit_limit;;
}

void RTMFP::setDefaultSessionIdleLimit(Time limit)
{
	m_default_session_idle_limit = limit;
}

Time RTMFP::getDefaultSessionIdleLimit() const
{
	return m_default_session_idle_limit;;
}

Time RTMFP::getCurrentTime() const
{
	return m_platform->getCurrentTime();
}

Time RTMFP::getInstanceAge() const
{
	return getCurrentTime() - m_epoch;
}

Time RTMFP::howLongToSleep() const
{
	return m_timers.howLongToNextFire(getCurrentTime());
}

void RTMFP::doTimerWork()
{
	m_timers.fireDueTimers(getCurrentTime());
}

void RTMFP::addInterface(int interfaceID)
{
	m_interfaces[interfaceID] = share_ref(new Interface(interfaceID, this), false);
}

bool RTMFP::onReceivePacket(const void *bytes_, size_t len, int interfaceID, const struct sockaddr *addr, int tos)
{
	const uint8_t *bytes = (uint8_t *)bytes_;
	uint32_t sid_decode[3] = { 0, 0, 0 };

	if(len < sizeof(uint32_t))
		return false;

	memmove(&sid_decode, bytes, len < sizeof(sid_decode) ? len : sizeof(sid_decode));
	uint32_t sessionID = sid_decode[0] ^ sid_decode[1] ^ sid_decode[2];

	ISession *session = nullptr;
	if(0 == sessionID)
		session = m_startupSession.get();
	else if(m_sessions.has(sessionID))
		session = m_sessions.at(sessionID).get();

	return session ? session->onReceivePacket(bytes + sizeof(uint32_t), len - sizeof(uint32_t), interfaceID, addr, tos, m_plaintextBuf) : false;
}

bool RTMFP::scheduleWrite(int interfaceID, std::shared_ptr<ISession> session, int pri)
{
	auto it = m_interfaces.find(interfaceID);
	if(it != m_interfaces.end())
	{
		it->second->scheduleWrite(session, pri);
		return true;
	}
	return false;
}

unsigned long RTMFP::getNextThreadNum()
{
	if(0 == m_nextThreadNum)
		m_nextThreadNum++;
	return m_nextThreadNum++;
}

std::shared_ptr<Timer> RTMFP::scheduleRel(Time delta, Time recurInterval)
{
	return m_timers.schedule(delta + getCurrentTime(), recurInterval);
}

uint16_t RTMFP::getCurrentTimestamp() const
{
	uintmax_t now = (uintmax_t)(getInstanceAge() * HEADER_TIMESTAMP_SCALE);
	return now & 0xffff;
}

std::vector<uint8_t> RTMFP::makeCookie(const struct sockaddr *addr_) const
{
	std::vector<uint8_t> dough;
	std::vector<uint8_t> cookie;
	uint64_t seconds = getInstanceAge();

	dough.insert(dough.end(), m_secret, m_secret + sizeof(m_secret));

	VLU::append(seconds, dough);
	VLU::append(seconds, cookie);

	uint8_t hash[256/8];
	m_crypto->cryptoHash256(hash, dough.data(), dough.size());
	cookie.insert(cookie.end(), hash, hash + sizeof(hash));

	Address addr(addr_);
	uint8_t encodedAddr[Address::MAX_ENCODED_SIZE];
	size_t rv = addr.encode(encodedAddr);
	dough.insert(dough.end(), encodedAddr, encodedAddr + rv);

	m_crypto->cryptoHash256(hash, dough.data(), dough.size());
	cookie.insert(cookie.end(), hash, hash + sizeof(hash));

	return cookie;
}

RTMFP::CookieCheck RTMFP::checkCookie(const uint8_t *cookie, size_t cookieLen, const struct sockaddr *addr_) const
{
	uintmax_t seconds;
	size_t rv = VLU::parse(cookie, cookie + cookieLen, &seconds);
	uint8_t hash[256/8];

	if((0 == rv) or (cookieLen != rv + sizeof(hash) + sizeof(hash)))
		return COOKIE_BAD; // bad VLU or wrong size

	uintmax_t now = getInstanceAge();
	if((seconds > now) or (now - seconds > MAX_COOKIE_LIFETIME))
		return COOKIE_BAD; // too old or wrong epoch

	std::vector<uint8_t> dough;
	dough.insert(dough.end(), m_secret, m_secret + sizeof(m_secret));
	dough.insert(dough.end(), cookie, cookie + rv);
	
	m_crypto->cryptoHash256(hash, dough.data(), dough.size());
	if(0 != memcmp(cookie + rv, hash, sizeof(hash)))
		return COOKIE_BAD;

	Address addr(addr_);
	uint8_t encodedAddr[Address::MAX_ENCODED_SIZE];
	size_t encodedAddrLen = addr.encode(encodedAddr);
	dough.insert(dough.end(), encodedAddr, encodedAddr + encodedAddrLen);

	m_crypto->cryptoHash256(hash, dough.data(), dough.size());
	if(0 != memcmp(cookie + rv + sizeof(hash), hash, sizeof(hash)))
		return COOKIE_MISMATCH;

	return COOKIE_OK;
}

void RTMFP::sendCookieChange(uint32_t sessionID, const uint8_t *cookie, size_t cookieLen, int interfaceID, const struct sockaddr *addr)
{
	std::vector<uint8_t> newCookie = makeCookie(addr);
	uint8_t tmp[MAX_STARTUP_PACKET_LENGTH];
	PacketAssembler packet;
	packet.init(tmp, 0, sizeof(tmp));
	packet.startChunk(CHUNK_RHELLO_COOKIE_CHANGE);
	if( (packet.pushField(cookie, cookieLen))
	 && (packet.push(newCookie))
	)
	{
		packet.commitChunk();
		m_startupSession->sendPacket(packet.toVector(), sessionID, interfaceID, addr);
	}
}

std::shared_ptr<Session> RTMFP::makeSession(std::shared_ptr<SessionCryptoKey> key, unsigned role)
{
	std::shared_ptr<Session> rv = share_ref(new Session(this, key), false);
	rv->m_rxSessionID = m_sessions.append(rv);
	rv->m_role = role;
	return rv;
}

std::shared_ptr<Session> RTMFP::findOpeningSessionByAddress(const Address &addr)
{
	for(long name = m_openingSessions.first(); name > m_openingSessions.SENTINEL; name = m_openingSessions.next(name))
	{
		auto &each = m_openingSessions.at(name);
		if(each->isOpeningToAddress(addr))
			return each;
	}
	return std::shared_ptr<Session> (nullptr);
}

std::shared_ptr<Session> RTMFP::findOpeningSessionByEPD(const Bytes &epd, const Session *exclude)
{
	for(long name = m_openingSessions.first(); name > m_openingSessions.SENTINEL; name = m_openingSessions.next(name))
	{
		auto &each = m_openingSessions.at(name);
		if(exclude and ((Session::S_KEYING_SENT != each->m_state) or (each.get() == exclude)))
			continue;

		if(each->m_epd == epd)
			return each;
		if(each->m_cryptoCert and each->m_cryptoCert->isSelectedByEPD(epd.data(), epd.size()))
			return each;
	}
	return std::shared_ptr<Session> (nullptr);
}

std::shared_ptr<Session> RTMFP::findOpeningSessionByTag(const Bytes &tag)
{
	for(long name = m_openingSessions.first(); name > m_openingSessions.SENTINEL; name = m_openingSessions.next(name))
	{
		auto &each = m_openingSessions.at(name);
		if((Session::S_IHELLO_SENT == each->m_state) and (each->m_tag == tag))
			return each;
	}
	return std::shared_ptr<Session> (nullptr);
}

std::shared_ptr<Session> RTMFP::findOpenSessionByAddress(const Address &addr)
{
	auto it = m_openSessionsByAddress.find(addr);
	if(it != m_openSessionsByAddress.end())
		return it->second;
	return std::shared_ptr<Session>(nullptr);
}

std::shared_ptr<Session> RTMFP::findOpenSessionByEPD(const Bytes &epd)
{
	auto it = m_openSessionsByCanonicalEPD.find(epd);
	if(it != m_openSessionsByCanonicalEPD.end())
		return it->second;
	return std::shared_ptr<Session>(nullptr);
}

void RTMFP::makeRIKeyingChunk(Bytes &dst, uint32_t rsid, const Bytes &skrc, Bytes &skic, std::shared_ptr<CryptoCert> recipient)
{
	Bytes rikeyingPayload;
	const uint8_t *rsid_ptr = (uint8_t *)&rsid;
	rikeyingPayload.insert(rikeyingPayload.end(), rsid_ptr, rsid_ptr + sizeof(uint32_t));
	VLU::append(skrc.size(), rikeyingPayload);
	rikeyingPayload.insert(rikeyingPayload.end(), skrc.begin(), skrc.end());

	Bytes dough(rikeyingPayload);
	dough.insert(dough.end(), skic.begin(), skic.end());

	Bytes rsig = m_crypto->sign(dough.data(), dough.size(), recipient);
	rikeyingPayload.insert(rikeyingPayload.end(), rsig.begin(), rsig.end());

	dst.push_back(CHUNK_RIKEYING);
	dst.push_back(rikeyingPayload.size() >> 8);
	dst.push_back(rikeyingPayload.size() & 0xff);
	dst.insert(dst.end(), rikeyingPayload.begin(), rikeyingPayload.end());
}

bool RTMFP::tryRIKeyingRetransmit(int interfaceID, const Address &addr, uint32_t isid, const Bytes &skic)
{
	auto session = findOpenSessionByAddress(addr);
	if(   (session)
	  and (HEADER_MODE_RESPONDER == session->m_role)
	  and (interfaceID == session->m_destInterfaceID)
	  and (isid == session->m_txSessionID)
	  and (skic == session->m_skic)
	)
	{
		session->sendRIKeying();
		return true;
	}

	return false;
}

void RTMFP::onSessionDidOpen(std::shared_ptr<Session> session)
{
	m_openingSessions.remove(m_openingSessions.find(session));
	m_openSessionsByAddress[session->m_destAddr] = session;
	m_openSessionsByCanonicalEPD[session->m_epd] = session;
	m_openingFlows.safeValuesDo([&] (std::shared_ptr<SendFlow> each) { each->onSessionDidOpen(each, session); return true; });
}

void RTMFP::onSessionWillOpen(std::shared_ptr<Session> session)
{
	m_openingFlows.valuesDo([&] (std::shared_ptr<SendFlow> each) { each->onSessionWillOpen(session); return true; });
}

void RTMFP::onSessionDidClose(std::shared_ptr<Session> session, bool releaseSessionID)
{
	m_openingSessions.remove(m_openingSessions.find(session));
	if(findOpenSessionByAddress(session->m_destAddr) == session)
		m_openSessionsByAddress.erase(session->m_destAddr);
	if(findOpenSessionByEPD(session->m_epd) == session)
		m_openSessionsByCanonicalEPD.erase(session->m_epd);

	if(releaseSessionID and m_sessions.has(session->m_rxSessionID) and (m_sessions.at(session->m_rxSessionID) == session))
		m_sessions.remove(session->m_rxSessionID);

	m_openingFlows.safeValuesDo([&] (std::shared_ptr<SendFlow> each) { each->onSessionDidClose(session); return true; });

	checkShutdownComplete();
}

void RTMFP::onSessionAddressDidChange(std::shared_ptr<Session> session, const Address &oldAddr)
{
	if(findOpenSessionByAddress(oldAddr) == session)
		m_openSessionsByAddress.erase(oldAddr);
	m_openSessionsByAddress[session->m_destAddr] = session;
}

void RTMFP::onSessionReceivedTC(const void *session_)
{
	uintptr_t session = (uintptr_t)session_;
	Time now = getCurrentTime();

	if(session != m_sessionReportingTC)
	{
		m_previous_sessionTC_time = m_sessionTC_time;
		m_sessionReportingTC = session;
	}
	m_sessionTC_time = now;
}

bool RTMFP::shouldSessionReportTCR(const void *session_) const
{
	uintptr_t session = (uintptr_t)session_;
	Time now = getCurrentTime();

	Time tcr = (session == m_sessionReportingTC) ? m_previous_sessionTC_time : m_sessionTC_time;
	return now - tcr < TIMECRITICAL_TIMEOUT;
}

void RTMFP::sendFlowIsNotOpening(const std::shared_ptr<SendFlow> &flow)
{
	long name;
	if((name = m_openingFlows.find(flow)))
		m_openingFlows.remove(name);
}

void RTMFP::checkShutdownComplete()
{
	if(m_shutdown and m_sessions.empty() and m_startupSession->empty() and not m_shutdownComplete)
	{
		m_shutdownComplete = true;
		m_platform->perform(0, [this] { m_platform->onShutdownComplete(); });
	}
}

void RTMFP::onIHello(const uint8_t *epd, size_t epdLen, const uint8_t *tag, size_t tagLen, int interfaceID, const struct sockaddr *addr, FIHelloResponseMode mode)
{
	if(FI_IGNORE == mode)
		return;

	if(not m_crypto->isSelectedByEPD(epd, epdLen))
	{
		if(onUnmatchedIHello)
			onUnmatchedIHello(epd, epdLen, tag, tagLen, interfaceID, addr);
		return;
	}

	if(FI_SEND_REDIRECT == mode)
	{
		sendResponderRedirect(tag, tagLen, std::vector<Address>(), interfaceID, addr);
	}
	else if(FI_SEND_RHELLO == mode) // the only other choice ...for now
	{
		uint8_t tmp[MAX_STARTUP_PACKET_LENGTH];

		PacketAssembler packet;
		packet.init(tmp, 0, sizeof(tmp));

		std::vector<uint8_t> cookie = makeCookie(addr);

		if( (packet.startChunk(CHUNK_RHELLO))
		 && (packet.pushField(tag, tagLen))
		 && (packet.pushField(cookie.data(), cookie.size()))
		 && (packet.push(m_crypto->getNearEncodedCertForEPD(epd, epdLen)))
		)
		{
			packet.commitChunk();
			m_startupSession->sendPacket(packet.toVector(), 0, interfaceID, addr);
		}
	}
}

void RTMFP::onRHello(const uint8_t *tag, size_t tagLen, const uint8_t *cookie, size_t cookieLen, const uint8_t *cert, size_t certLen, int interfaceID, const struct sockaddr *addr)
{
	auto session = findOpeningSessionByTag(Bytes(tag, tag + tagLen));
	if(not session)
		return;

	session->onRHello(session, cookie, cookieLen, cert, certLen, interfaceID, addr);
}

namespace {

struct IIKeyingState {
	IIKeyingState(unsigned long threadNum, uint32_t initiatorSessionID, const uint8_t *cookie, size_t cookieLen,
			const uint8_t *cert, size_t certLen, const uint8_t *skic, size_t skicLen,
			const uint8_t *signedParams, size_t signedParamsLen, const uint8_t *sig, size_t sigLen,
			std::shared_ptr<CryptoCert> cryptoCert,
			int interfaceID, const struct sockaddr *addr) :
		m_threadNum(threadNum),
		m_isid(initiatorSessionID),
		m_cookie(cookie, cookie + cookieLen),
		m_skic(skic, skic + skicLen),
		m_signedParams(signedParams, signedParams + signedParamsLen),
		m_isignature(sig, sig + sigLen),
		m_cryptoCert(cryptoCert),
		m_interfaceID(interfaceID),
		m_addr(addr)
	{}

	unsigned long m_threadNum;
	uint32_t m_isid;
	Bytes m_cookie;
	Bytes m_skic;
	Bytes m_signedParams;
	Bytes m_isignature;
	std::shared_ptr<CryptoCert> m_cryptoCert;
	std::shared_ptr<SessionCryptoKey> m_key;
	std::shared_ptr<Session> m_session;
	Bytes m_skrc;
	Bytes m_rikeying;
	int     m_interfaceID;
	Address m_addr;
};

} // anonymous namespace

void RTMFP::onIIKeying(uint32_t initiatorSessionID, const uint8_t *cookie, size_t cookieLen,
	const uint8_t *cert, size_t certLen, const uint8_t *skic, size_t skicLen,
	const uint8_t *signedParams, size_t signedParamsLen, const uint8_t *sig, size_t sigLen,
	int interfaceID, const struct sockaddr *addr)
{
	if(m_shutdown)
		return;

	CookieCheck disposition = checkCookie(cookie, cookieLen, addr);
	if(COOKIE_BAD == disposition)
		return;

	if(COOKIE_MISMATCH == disposition)
	{
		sendCookieChange(initiatorSessionID, cookie, cookieLen, interfaceID, addr);
		return;
	}

	auto cryptoCert = m_crypto->decodeCertificate(cert, certLen);
	if(!cryptoCert)
		return;

	auto state = std::make_shared<IIKeyingState>(getNextThreadNum(), initiatorSessionID, cookie, cookieLen, cert, certLen, skic, skicLen, signedParams, signedParamsLen, sig, sigLen, cryptoCert, interfaceID, addr);

	// short-circuit check if we need to retransmit RIKeying before we do any expensive PK crypto
	if(tryRIKeyingRetransmit(state->m_interfaceID, state->m_addr, state->m_isid, state->m_skic))
		return;

	if(m_waitingPerformCount >= MAX_WAITING_PERFORM_COUNT)
		return; // we're too busy for this right now

	auto myself = share_ref(this);
	m_waitingPerformCount++;
	m_platform->perform(state->m_threadNum, [myself, state] {
		myself->m_waitingPerformCount--;

		state->m_cryptoCert->isAuthentic([myself, state] { myself->m_platform->perform(state->m_threadNum, [myself, state] {
			state->m_cryptoCert->checkSignature(state->m_signedParams.data(), state->m_signedParams.size(), state->m_isignature.data(), state->m_isignature.size(), [myself, state] { myself->m_platform->perform(state->m_threadNum, [myself, state] {
				state->m_key = myself->m_crypto->getKeyForNewSession();
				if( (not state->m_key)
				 or (not state->m_key->generateResponderKeyingComponent(state->m_cryptoCert, state->m_skic.data(), state->m_skic.size(), &state->m_skrc))
				)
					return;

				myself->m_platform->perform(0, [myself, state] {
					if(myself->m_shutdown)
						return;

					if(myself->tryRIKeyingRetransmit(state->m_interfaceID, state->m_addr, state->m_isid, state->m_skic))
						return;

					auto overrideSession = myself->findOpenSessionByAddress(state->m_addr);
					if(overrideSession)
					{
						if(not state->m_cryptoCert->doesCertOverrideSession(overrideSession->m_cryptoCert))
							return;

						overrideSession->abort(); // this session is (hopefully) stale
					}

					auto glareSession = myself->findOpeningSessionByAddress(state->m_addr);
					bool abortGlareSession = false;
					if(glareSession)
					{
						if(myself->m_crypto->checkNearWinsGlare(state->m_cryptoCert))
							return; // ignore this IIKeying.
							// TODO: should we check that glareSession's epd is selected by IIKeying's cert too?

						// they win. per RFC 7016 §3.5.1.3 abort our opening session if the IIKeying cert
						// overrides the opening session cert, which we only know in S_KEYING_SENT.
						if((Session::S_KEYING_SENT == glareSession->m_state) and state->m_cryptoCert->doesCertOverrideSession(glareSession->m_cryptoCert))
							abortGlareSession = true; // we'll wait until after the new session opens so waiting flows can bind to it
					}

					auto session = myself->makeSession(state->m_key, HEADER_MODE_RESPONDER);

					session->m_skic = state->m_skic;
					session->m_destInterfaceID = state->m_interfaceID;
					session->m_destAddr = state->m_addr;
					session->m_cryptoCert = state->m_cryptoCert;
					state->m_session = session;

					session->setOpen(session, state->m_isid);

					if(abortGlareSession)
						glareSession->abort();

					myself->m_platform->perform(state->m_threadNum, [myself, state] {
						myself->makeRIKeyingChunk(state->m_rikeying, state->m_session->m_rxSessionID, state->m_skrc, state->m_skic, state->m_cryptoCert);

						myself->m_platform->perform(0, [myself, state] {
							state->m_session->m_rikeying = state->m_rikeying;
							state->m_session->sendRIKeying();
						});
					});
				});
			}); });
		}); });
	});
}

void RTMFP::onRedirect(const uint8_t *tag, size_t tagLen, const std::vector<Address> &redirectDestinations)
{
	auto session = findOpeningSessionByTag(Bytes(tag, tag + tagLen));
	if(session)
	{
		for(auto it = redirectDestinations.begin(); it != redirectDestinations.end(); it++)
			session->addCandidateAddress(*it, 0, true);
	}
}

} } } // namespace com::zenomt::rtmfp
