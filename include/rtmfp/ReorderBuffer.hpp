#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "rtmfp.hpp"
#include "RunLoop.hpp"

namespace com { namespace zenomt { namespace rtmfp {

class ReorderBuffer : public Object {
public:
	ReorderBuffer();
	~ReorderBuffer();

	void close();

	void setReorderWindowPeriod(Time val);
	Time getReorderWindowPeriod() const;

	void insert(const uint8_t *bytes, size_t len, uintmax_t sequenceNumber, size_t fragmentCount);
	void deliverThrough(uintmax_t sequenceNumber);
	void flush();

	std::function<void(const uint8_t *bytes, size_t len, uintmax_t sequenceNumber, size_t fragmentCount, bool isLate)> onMessage;

	virtual Time getCurrentTime() const = 0;
	virtual std::shared_ptr<Timer> scheduleTimer(Time when) = 0;

protected:
	struct Message : public Object {
		Message(const uint8_t *payload, size_t len, uintmax_t sequenceNumber, size_t fragmentCount, Time now);

		Bytes     m_payload;
		uintmax_t m_sequenceNumber;
		size_t    m_fragmentCount;
		Time      m_rxTime;
	};

	void clearTimer();
	bool shouldDeliverNow(uintmax_t sequenceNumber) const;
	bool isLate(uintmax_t sequenceNumber) const;
	void deliverMessage(const uint8_t *payload, size_t len, uintmax_t sequenceNumber, size_t fragmentCount);
	void tryDeliver();
	void queueMessage(const uint8_t *payload, size_t len, uintmax_t sequenceNumber, size_t fragmentCount);
	void scheduleDelivery();
	void findCSN(Time now);

	Time m_reorderPeriod;
	uintmax_t m_csn;
	uintmax_t m_deliveredThrough;
	uintmax_t m_highestSeen;
	std::shared_ptr<Timer> m_deliveryTimer;
	std::map<uintmax_t, std::shared_ptr<Message>> m_messagesBySequence;
	List<std::shared_ptr<Message>> m_messagesByTime;
};

class RunLoopReorderBuffer : public ReorderBuffer {
public:
	RunLoopReorderBuffer(RunLoop *runloop) : m_runloop(runloop) {}

	Time getCurrentTime() const override { return m_runloop->getCurrentTime(); }
	std::shared_ptr<Timer> scheduleTimer(Time when) override { return m_runloop->schedule(when); }

protected:
	RunLoop *m_runloop;
};

} } } // namespace com::zenomt::rtmfp
