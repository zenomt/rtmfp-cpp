#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

// Sample client implementation for the http://zenomt.com/ns/rtmfp#redirector protocol.

#include "rtmfp.hpp"
#include "RunLoop.hpp"
#include "FlashCryptoAdapter.hpp"

namespace com { namespace zenomt { namespace rtmfp {

class RedirectorClient : public Object {
public:
	RedirectorClient(RTMFP *rtmfp, const Bytes &epd);
	~RedirectorClient();

	void connect();
	bool isConnected() const;
	void close();

	Time minimumReconnectInterval { 30.0 };
	Time retransmitLimit { 10.0 };
	Time keepalivePeriod { 10.0 };

	void setActive(bool active); // default true, set to false to unregister
	bool isActive() const;

	void setPaused(bool paused); // suspend sending settings if paused, to allow an atomic reconfiguration.

	void setLoadFactor(uintmax_t factor);
	uintmax_t getLoadFactor() const;

	void addRedirectorAddress(const Address &addr);

	Address getRedirectorAddress() const; // answer only valid if STATUS_CONNECTED

	void addSimpleAuth(const char *keyID, const char *password);
	void addSimpleAuth(const Bytes &keyID, const Bytes &password);

	void setFIHelloMode(FIHelloResponseMode mode); // default FI_SEND_RHELLO
	FIHelloResponseMode getFIHelloMode() const;

	void    setAdvertiseReflexiveAddress(bool advertise); // default true
	bool    getAdvertiseReflexiveAddress() const;
	Address getReflexiveAddress() const;
	bool    isReflexiveAddressValid() const;

	// these methods will send an update immediately. use setAdditionalAddresses() to make an atomic change.
	void addAdditionalAddress(const Address &addr);
	void removeAdditionalAddress(const Address &addr);
	void clearAdditionalAddresses();

	std::shared_ptr<WriteReceipt> sendUserData(const void *data, size_t len); // answer empty if not connected

	enum Status {
		STATUS_IDLE,
		STATUS_CONNECTING,
		STATUS_CONNECTED,
		STATUS_DISCONNECTED,
		STATUS_DISCONNECTED_BAD_AUTH,
		STATUS_CLOSED
	};

	Status getStatus() const;

	std::function<void(Status status)> onStatus;
	std::function<void(const Address &addr)> onReflexiveAddress;
	std::function<void(const uint8_t *bytes, size_t len)> onUserData;

	virtual std::shared_ptr<Timer> scheduleTimer(Time when) = 0;
	virtual void hmacSHA256(void *dst, const void *key, size_t keyLen, const void *msg, size_t msgLen) = 0;

	// utility and convenience functions
	static Bytes makeFlowMetadata(); // make a basic rtmfp:redirector metadata blob
	static bool checkFlowMetadata(const Bytes &metadata); // answer true if metadata is for a rtmfp:redirector flow
	static bool parseRedirectorSpec(const std::string &spec, std::string &outName, std::vector<Address> &outAddresses);

	enum {
		// to server
		CMD_SIMPLE_AUTH           = 0x1d, // <hmac[32](pw, server-nonce)> <keyid>
		CMD_SETTINGS              = 0x05, // [options...]
		CMD_DRAINING              = 0x00,
		CMD_LOAD_FACTOR           = 0x0f, // <vlu factor>

		// from server
		CMD_REFLEXIVE_ADDR_REPORT = 0x0d, // <addr>

		// either direction
		CMD_USER_DATA             = 0x10  // [opaque data...]
	};

	enum {
		SETTINGS_OPT_INCLUDE_REFLEXIVE = 0x0d, // (default don't)
		SETTINGS_OPT_ADD_ADDRESS       = 0x0a  // <addr> (zero or more times)
	};

	enum {
		EXCEPTION_BAD_AUTH = 0x0a
	};

protected:
	void closeFlows();
	void setStatus(Status status);
	void doConnect();
	void sendAuth();
	void sendSettingsIfActive();
	void sendDrainingIfInactive();
	void sendLoadFactorIfActive();

	void onConnected();
	void onException(uintmax_t reason);
	void onRecvFlow(std::shared_ptr<RecvFlow> flow);
	void onMessage(const uint8_t *bytes, size_t len);

	RTMFP                    *m_rtmfp;
	Bytes                     m_epd;
	Status                    m_status { STATUS_IDLE };
	bool                      m_active { true };
	bool                      m_paused { false };
	FIHelloResponseMode       m_responseMode { FI_SEND_RHELLO };
	bool                      m_advertiseReflexiveAddress { true };
	uintmax_t                 m_loadFactor { 0 };
	std::set<Address>         m_redirectorAddresses;
	std::set<Address>         m_additionalAddresses;
	Address                   m_reflexiveAddress;
	bool                      m_reflexiveAddressValid { false };
	std::map<Bytes, Bytes>    m_simpleAuth;

	std::shared_ptr<SendFlow> m_send;
	std::shared_ptr<RecvFlow> m_recv;
	std::shared_ptr<Timer>    m_reconnectTimer;
	Time                      m_lastConnectAttempt { -INFINITY };
};

class RunLoopRedirectorClient : public RedirectorClient {
public:
	RunLoopRedirectorClient(RTMFP *rtmfp, const Bytes &epd, RunLoop *runloop) :
		RedirectorClient(rtmfp, epd),
		m_runloop(runloop)
	{}

	std::shared_ptr<Timer> scheduleTimer(Time when) override { return m_runloop->schedule(when); }

protected:
	RunLoop *m_runloop;
};

class FlashCryptoRunLoopRedirectorClient : public RunLoopRedirectorClient {
public:
	FlashCryptoRunLoopRedirectorClient(RTMFP *rtmfp, const Bytes &epd, RunLoop *runloop, FlashCryptoAdapter *crypto) :
		RunLoopRedirectorClient(rtmfp, epd, runloop),
		m_crypto(crypto)
	{}

	void hmacSHA256(void *dst, const void *key, size_t keyLen, const void *msg, size_t msgLen) override
	{
		m_crypto->hmacSHA256(dst, key, keyLen, msg, msgLen);
	}

protected:
	FlashCryptoAdapter *m_crypto;
};

} } } // namespace com::zenomt::rtmfp
