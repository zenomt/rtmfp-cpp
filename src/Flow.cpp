// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "Session.hpp"
#include "../include/rtmfp/VLU.hpp"
#include "../include/rtmfp/packet.hpp"
#include "../include/rtmfp/params.hpp"
#include "../include/rtmfp/PacketAssembler.hpp"

namespace com { namespace zenomt { namespace rtmfp {

Flow::Flow(RTMFP *rtmfp) : m_rtmfp(rtmfp), m_base_isOpen(true)
{
}

std::shared_ptr<SendFlow> Flow::openFlow(const void *metadataBytes, size_t metadataLen, Priority pri)
{
	const uint8_t *metadata = (const uint8_t *)metadataBytes;
	return openFlow(Bytes(metadata, metadata + metadataLen), pri);
}

std::shared_ptr<SendFlow> Flow::openFlow(const Bytes &metadata, Priority pri)
{
	return basicOpenFlow(metadata, nullptr, pri);
}

bool Flow::isOpen() const
{
	return m_base_isOpen;
}

void Flow::close()
{
	m_base_isOpen = false;
	onFarAddressDidChange = nullptr;
}

void Flow::closeSession()
{
	if(m_session)
		m_session->close(true);
}

Bytes Flow::getNearNonce() const
{
	return m_session ? m_session->m_cryptoKey->getNearNonce() : Bytes();
}

Bytes Flow::getFarNonce() const
{
	return m_session ? m_session->m_cryptoKey->getFarNonce() : Bytes();
}

Bytes Flow::getFarCertificate() const
{
	return (m_session and m_session->m_cryptoCert) ? m_session->m_cryptoCert->encode() : Bytes();
}

Bytes Flow::getFarCanonicalEPD() const
{
	return m_session ? m_session->m_epd : Bytes();
}

Address Flow::getFarAddress() const
{
	return m_session ? m_session->m_destAddr : Address();
}

Time Flow::getSRTT() const
{
	return m_session ? m_session->m_srtt : INFINITY;
}

Time Flow::getSafeSRTT() const
{
	Time srtt = getSRTT();
	return srtt >= 0.0 ? srtt : SAFE_RTT;
}

Time Flow::getRTTVariance() const
{
	return m_session ? m_session->m_rttvar : INFINITY;
}

Time Flow::getLastRTT() const
{
	return m_session ? m_session->m_last_rtt : INFINITY;
}

Time Flow::getBaseRTT() const
{
	return m_session ? m_session->m_base_rtt : INFINITY;
}

size_t Flow::getCongestionWindow() const
{
	return m_session ? m_session->m_cwnd : 0;
}

Time Flow::getERTO() const
{
	return m_session ? m_session->m_erto : INFINITY;
}

Time Flow::getMRTO() const
{
	return m_session ? m_session->m_mrto : INFINITY;
}

void Flow::setSessionKeepalivePeriod(Time keepalive)
{
	if(m_session)
		m_session->setKeepalivePeriod(keepalive);
}

Time Flow::getSessionKeepalivePeriod() const
{
	return m_session ? m_session->getKeepalivePeriod() : INFINITY;
}

void Flow::setSessionRetransmitLimit(Time limit)
{
	if(m_session)
		m_session->setRetransmitLimit(limit);
}

Time Flow::getSessionRetransmitLimit() const
{
	return m_session ? m_session->getRetransmitLimit() : INFINITY;
}

void Flow::setSessionIdleLimit(Time limit)
{
	if(m_session)
		m_session->setIdleLimit(limit);
}

Time Flow::getSessionIdleLimit() const
{
	return m_session ? m_session->getIdleLimit() : INFINITY;
}

void Flow::setSessionTrafficClass(int tos)
{
	if(m_session)
		m_session->setTrafficClass(tos);
}

int Flow::getSessionTrafficClass() const
{
	return m_session ? m_session->getTrafficClass() : 0;
}

bool Flow::forwardIHello(const void *epd, size_t epdLen, const Address &replyAddress, const void *tag, size_t tagLen)
{
	if((not m_session) or (m_session->m_state != Session::S_OPEN))
		return false;

	uint8_t buf[MAX_SESSION_PACKET_LENGTH];
	PacketAssembler fihello;
	fihello.init(buf, 0, sizeof(buf));

	if(  fihello.startChunk(CHUNK_FIHELLO)
	 and fihello.pushField(epd, epdLen)
	 and fihello.push(replyAddress.encode())
	 and fihello.push(tag, tagLen)
	)
	{
		fihello.commitChunk();
		m_session->sendPacket(fihello.toVector());
		return true;
	}

	return false;
}

void Flow::setSessionFIHelloMode(FIHelloResponseMode mode)
{
	if(m_session)
		m_session->m_fihelloMode = mode;
}

FIHelloResponseMode Flow::getSessionFIHelloMode() const
{
	return m_session ? m_session->m_fihelloMode : FI_IGNORE;
}

void Flow::setSessionCongestionDelay(Time delay)
{
	if(m_session)
		m_session->m_delaycc_congestion_delay = delay;
}

Time Flow::getSessionCongestionDelay() const
{
	return m_session ? m_session->m_delaycc_congestion_delay : INFINITY;
}

// ---

std::shared_ptr<SendFlow> Flow::basicOpenFlow(const Bytes &metadata, RecvFlow *assoc, Priority pri)
{
	std::shared_ptr<SendFlow> rv;

	if((not m_session) or (Session::S_OPEN != m_session->m_state) or (metadata.size() > MAX_METADATA_LENGTH))
		return rv;

	rv = share_ref(new SendFlow(m_rtmfp, m_session->m_epd, metadata, assoc, pri), false);
	rv->onSessionDidOpen(rv, m_session);

	return rv;
}

} } } // namespace com::zenomt::rtmfp
