// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cstring>

#include "../include/rtmfp/RedirectorClient.hpp"
#include "../include/rtmfp/VLU.hpp"

namespace {

const uint8_t signature[] = "http://zenomt.com/ns/rtmfp#redirector";
const com::zenomt::Time minimumReconnectIntervalLimit = 5.0;

}

namespace com { namespace zenomt { namespace rtmfp {

RedirectorClient::RedirectorClient(RTMFP *rtmfp, const Bytes &epd) : m_rtmfp(rtmfp), m_epd(epd)
{}

RedirectorClient::~RedirectorClient()
{
	close();
}

void RedirectorClient::connect()
{
	if(STATUS_IDLE == m_status)
		doConnect();
}

bool RedirectorClient::isConnected() const
{
	return STATUS_CONNECTED == getStatus();
}

void RedirectorClient::close()
{
	m_status = STATUS_CLOSED;
	m_active = false;
	if(m_reconnectTimer)
		m_reconnectTimer->cancel();
	m_reconnectTimer.reset();
	if(m_loadFactorUpdateTimer)
		m_loadFactorUpdateTimer->cancel();
	m_loadFactorUpdateTimer.reset();

	closeFlows();

	onStatus = nullptr;
	onReflexiveAddress = nullptr;
	onUserData = nullptr;
}

void RedirectorClient::setRetransmitLimit(Time t)
{
	m_retransmitLimit = t;
	if(isConnected())
		m_send->setSessionRetransmitLimit(m_retransmitLimit);
}

Time RedirectorClient::getRetransmitLimit() const
{
	return m_retransmitLimit;
}

void RedirectorClient::setKeepalivePeriod(Time t)
{
	m_keepalivePeriod = t;
	if(isConnected())
		m_send->setSessionKeepalivePeriod(m_keepalivePeriod);
}

void RedirectorClient::setActive(bool active)
{
	bool update = active != m_active;
	m_active = active;

	if(update)
	{
		sendSettingsIfActive();
		sendDrainingIfInactive();
	}
}

bool RedirectorClient::isActive() const
{
	return m_active;
}

void RedirectorClient::setPaused(bool paused)
{
	m_paused = paused;
	if(not m_paused)
		sendSettingsIfActive();
}

void RedirectorClient::setLoadFactor(uintmax_t factor)
{
	bool update = factor != m_loadFactor;
	m_loadFactor = factor;

	if(update)
	{
		m_loadFactorChanged = true;
		scheduleSendLoadFactor();
	}
}

uintmax_t RedirectorClient::getLoadFactor() const
{
	return m_loadFactor;
}

void RedirectorClient::setLoadFactorUpdateInterval(Time t)
{
	m_loadFactorUpdateInterval = std::max(t, Time(0.0));;
	if(m_loadFactorUpdateTimer)
		m_loadFactorUpdateTimer->setNextFireTime(m_rtmfp->getCurrentTime());
}

Time RedirectorClient::getLoadFactorUpdateInterval() const
{
	return m_loadFactorUpdateInterval;
}

void RedirectorClient::addRedirectorAddress(const Address &addr)
{
	m_redirectorAddresses.insert(addr);
	if(m_send)
		m_send->addCandidateAddress(addr);
}

Address RedirectorClient::getRedirectorAddress() const
{
	if(m_send)
		return m_send->getFarAddress();
	return Address();
}

void RedirectorClient::addSimpleAuth(const char *keyID, const char *password)
{
	addSimpleAuth(Bytes(keyID, keyID + strlen(keyID)), Bytes(password, password + strlen(password)));
}

void RedirectorClient::addSimpleAuth(const Bytes &keyID, const Bytes &password)
{
	m_simpleAuth[keyID] = password;
}

void RedirectorClient::setFIHelloMode(FIHelloResponseMode mode)
{
	m_responseMode = mode;
	if(m_send)
		m_send->setSessionFIHelloMode(mode);
}

FIHelloResponseMode RedirectorClient::getFIHelloMode() const
{
	return m_responseMode;
}

void RedirectorClient::setAdvertiseReflexiveAddress(bool advertise)
{
	bool update = advertise != m_advertiseReflexiveAddress;
	m_advertiseReflexiveAddress = advertise;

	if(update)
		sendSettingsIfActive();
}

bool RedirectorClient::getAdvertiseReflexiveAddress() const
{
	return m_advertiseReflexiveAddress;
}

Address RedirectorClient::getReflexiveAddress() const
{
	return m_reflexiveAddress;
}

bool RedirectorClient::isReflexiveAddressValid() const
{
	return m_reflexiveAddressValid;
}

void RedirectorClient::addAdditionalAddress(const Address &addr)
{
	m_additionalAddresses.insert(addr);
	sendSettingsIfActive();
}

void RedirectorClient::removeAdditionalAddress(const Address &addr)
{
	m_additionalAddresses.erase(addr);
	sendSettingsIfActive();
}

void RedirectorClient::clearAdditionalAddresses()
{
	m_additionalAddresses.clear();
	sendSettingsIfActive();
}

std::shared_ptr<WriteReceipt> RedirectorClient::sendUserData(const void *data, size_t len)
{
	const uint8_t *bytes = (const uint8_t *)data;

	if(not isConnected())
		return nullptr;

	Bytes msg;
	msg.push_back(CMD_USER_DATA);
	msg.insert(msg.end(), bytes, bytes + len);

	return m_send->write(msg);
}

RedirectorClient::Status RedirectorClient::getStatus() const
{
	return m_status;
}

Bytes RedirectorClient::makeFlowMetadata()
{
	return Bytes(signature, signature + sizeof(signature) - 1);
}

bool RedirectorClient::checkFlowMetadata(const Bytes &metadata)
{
	if(metadata.size() >= sizeof(signature))
		return 0 == memcmp(signature, metadata.data(), sizeof(signature));
	if(metadata.size() < sizeof(signature) - 1)
		return false;
	return 0 == memcmp(signature, metadata.data(), sizeof(signature) - 1);
}

// ---

void RedirectorClient::closeFlows()
{
	if(m_send)
		m_send->close();
	m_send.reset();
	if(m_recv)
		m_recv->close();
	m_recv.reset();
	m_reflexiveAddressValid = false;
}

void RedirectorClient::setStatus(Status status)
{
	m_status = status;
	if(onStatus)
		onStatus(m_status);
}

void RedirectorClient::doConnect()
{
	m_lastConnectAttempt = m_rtmfp->getCurrentTime();

	m_send = m_rtmfp->openFlow(m_epd, makeFlowMetadata());
	if(not m_send)
	{
		onException(0);
		return;
	}

	for(auto it = m_redirectorAddresses.begin(); it != m_redirectorAddresses.end(); it++)
		m_send->addCandidateAddress(*it);

	m_send->onException = [this] (uintmax_t reason) { onException(reason); };
	m_send->onRecvFlow = [this] (std::shared_ptr<RecvFlow> flow) { onRecvFlow(flow); };
	m_send->onWritable = [this] { onConnected(); return false; };

	m_send->notifyWhenWritable();

	setStatus(STATUS_CONNECTING);
}

void RedirectorClient::sendAuth()
{
	Bytes nonce = m_send->getFarNonce();

	for(auto it = m_simpleAuth.begin(); it != m_simpleAuth.end(); it++)
	{
		Bytes msg;
		msg.push_back(CMD_SIMPLE_AUTH);

		uint8_t md[32];
		hmacSHA256(md, it->second.data(), it->second.size(), nonce.data(), nonce.size());

		msg.insert(msg.end(), md, md + sizeof(md));
		msg.insert(msg.end(), it->first.begin(), it->first.end());

		m_send->write(msg);
	}
}

void RedirectorClient::sendSettingsIfActive()
{
	if(isConnected() and isActive() and not m_paused)
	{
		Bytes msg;
		msg.push_back(CMD_SETTINGS);
		if(m_advertiseReflexiveAddress)
			Option::append(SETTINGS_OPT_INCLUDE_REFLEXIVE, msg);
		for(auto it = m_additionalAddresses.begin(); it != m_additionalAddresses.end(); it++)
			Option::append(SETTINGS_OPT_ADD_ADDRESS, it->encode(), msg);
		m_send->write(msg);
	}
}

void RedirectorClient::sendDrainingIfInactive()
{
	if(isConnected() and not isActive())
	{
		uint8_t msg[] = { CMD_DRAINING };
		m_send->write(msg, sizeof(msg));
	}
}

void RedirectorClient::scheduleSendLoadFactor()
{
	if(not m_loadFactorUpdateTimer)
	{
		sendLoadFactor();
		m_loadFactorUpdateTimer = scheduleTimer(m_rtmfp->getCurrentTime() + m_loadFactorUpdateInterval);
		m_loadFactorUpdateTimer->action = [this] (const std::shared_ptr<Timer> &sender, Time now) {
			m_loadFactorUpdateTimer.reset();
			if(m_loadFactorChanged)
				scheduleSendLoadFactor();
		};
	}
}

void RedirectorClient::sendLoadFactor()
{
	if(isConnected())
	{
		Bytes msg;
		msg.push_back(CMD_LOAD_FACTOR);
		VLU::append(m_loadFactor, msg);
		m_send->write(msg);
	}
	m_loadFactorChanged = false;
}

void RedirectorClient::onConnected()
{
	setStatus(STATUS_CONNECTED);
	if(isConnected()) // still, could have changed during callback
	{
		m_send->setSessionKeepalivePeriod(m_keepalivePeriod);
		m_send->setSessionRetransmitLimit(m_retransmitLimit);
		m_send->setSessionFIHelloMode(m_responseMode);
		sendAuth();
		sendSettingsIfActive();
		sendDrainingIfInactive();
		sendLoadFactor();
	}
}

void RedirectorClient::onException(uintmax_t reason)
{
	closeFlows();

	setStatus(EXCEPTION_BAD_AUTH == reason ? STATUS_DISCONNECTED_BAD_AUTH : STATUS_DISCONNECTED);
	if(m_status < STATUS_CLOSED) // could have closed from onStatus
	{
		// timers set for the past should fire immediately
		m_reconnectTimer = scheduleTimer(m_lastConnectAttempt + std::max(minimumReconnectInterval, minimumReconnectIntervalLimit));
		m_reconnectTimer->action = [this] (const std::shared_ptr<Timer> &sender, Time now) {
			m_reconnectTimer.reset();
			doConnect();
		};
	}
}

void RedirectorClient::onRecvFlow(std::shared_ptr<RecvFlow> flow)
{
	if(m_recv or not checkFlowMetadata(flow->getMetadata()))
		return; // only one return flow allowed

	m_recv = flow;
	m_recv->accept();
	m_recv->onMessage = [this] (const uint8_t *bytes, size_t len, uintmax_t sequenceNumber, size_t fragmentCount) { onMessage(bytes, len); };
}

void RedirectorClient::onMessage(const uint8_t *bytes, size_t len)
{
	const uint8_t *cursor = bytes;
	const uint8_t *limit = cursor + len;

	if(len)
	{
		switch(*cursor++)
		{
		case CMD_REFLEXIVE_ADDR_REPORT:
			m_reflexiveAddressValid = m_reflexiveAddress.setFromEncoding(cursor, limit);
			if(m_reflexiveAddressValid and onReflexiveAddress)
				onReflexiveAddress(m_reflexiveAddress);
			break;

		case CMD_USER_DATA:
			if(onUserData)
				onUserData(cursor, limit - cursor);
			break;

		default:
			break;
		}
	}
}

} } } // namespace com::zenomt::rtmfp
