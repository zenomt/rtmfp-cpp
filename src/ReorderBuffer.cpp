// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cassert>

#include "../include/rtmfp/ReorderBuffer.hpp"

namespace com { namespace zenomt { namespace rtmfp {

static uintmax_t _lastSN(uintmax_t sequenceNumber, size_t fragmentCount)
{
	return sequenceNumber + fragmentCount - (fragmentCount ? 1 : 0);
}

ReorderBuffer::Message::Message(const uint8_t *payload, size_t len, uintmax_t sequenceNumber, size_t fragmentCount, Time now) :
	m_payload(payload, payload + len),
	m_sequenceNumber(sequenceNumber),
	m_fragmentCount(fragmentCount),
	m_rxTime(now)
{}

ReorderBuffer::ReorderBuffer() :
	m_reorderPeriod(INFINITY),
	m_csn(0),
	m_deliveredThrough(0)
{}

ReorderBuffer::~ReorderBuffer()
{
	clearTimer();
}

void ReorderBuffer::close()
{
	retain();

	clearTimer();
	onMessage = nullptr;

	m_messagesBySequence.clear();
	m_messagesByTime.clear();

	release();
}

void ReorderBuffer::setReorderWindowPeriod(Time val)
{
	if(val < 0.0)
		val = 0;

	if(m_reorderPeriod != val)
	{
		m_reorderPeriod = val;
		clearTimer();
		scheduleDelivery();
	}
}

Time ReorderBuffer::getReorderWindowPeriod() const
{
	return m_reorderPeriod;
}

void ReorderBuffer::insert(const uint8_t *bytes, size_t len, uintmax_t sequenceNumber, size_t fragmentCount)
{
	m_highestSeen = std::max(m_highestSeen, _lastSN(sequenceNumber, fragmentCount));

	if(shouldDeliverNow(sequenceNumber))
	{
		deliverMessage(bytes, len, sequenceNumber, fragmentCount);
		tryDeliver();
	}
	else
		queueMessage(bytes, len, sequenceNumber, fragmentCount);
}

void ReorderBuffer::deliverThrough(uintmax_t sequenceNumber)
{
	if(sequenceNumber > m_csn)
	{
		m_csn = sequenceNumber;
		tryDeliver();
	}
}

void ReorderBuffer::flush()
{
	deliverThrough(m_highestSeen);
}

// ---

void ReorderBuffer::clearTimer()
{
	if(m_deliveryTimer)
		m_deliveryTimer->cancel();
	m_deliveryTimer.reset();
}

bool ReorderBuffer::shouldDeliverNow(uintmax_t sequenceNumber) const
{
	return sequenceNumber <= m_csn + 1;
}

bool ReorderBuffer::isLate(uintmax_t sequenceNumber) const
{
	return sequenceNumber < m_deliveredThrough;
}

void ReorderBuffer::deliverMessage(const uint8_t *payload, size_t len, uintmax_t sequenceNumber, size_t fragmentCount)
{
	uintmax_t lastSequenceNumber = _lastSN(sequenceNumber, fragmentCount);

	if(onMessage)
		onMessage(payload, len, sequenceNumber, fragmentCount, isLate(lastSequenceNumber));

	m_csn = std::max(m_csn, lastSequenceNumber);
	m_deliveredThrough = std::max(m_deliveredThrough, lastSequenceNumber);
}

void ReorderBuffer::tryDeliver()
{
	Time now = getCurrentTime();
	findCSN(now); // advance m_csn for old messages
	
	while(not m_messagesBySequence.empty())
	{
		auto it = m_messagesBySequence.begin();
		if(shouldDeliverNow(it->first))
		{
			auto &message_ptr = it->second;
			deliverMessage(message_ptr->m_payload.data(), message_ptr->m_payload.size(), message_ptr->m_sequenceNumber, message_ptr->m_fragmentCount);
			m_messagesBySequence.erase(it);
		}
		else
			break;
	}

	findCSN(now); // also trim delivered ones from m_messagesByTime

	scheduleDelivery();

	assert(m_messagesBySequence.empty() == m_messagesByTime.empty());
}

void ReorderBuffer::queueMessage(const uint8_t *payload, size_t len, uintmax_t sequenceNumber, size_t fragmentCount)
{
	auto message = share_ref(new Message(payload, len, sequenceNumber, fragmentCount, getCurrentTime()), false);
	m_messagesBySequence[sequenceNumber] = message;
	m_messagesByTime.append(message);
	scheduleDelivery();
}

void ReorderBuffer::scheduleDelivery()
{
	if((not m_messagesByTime.empty()) and (m_reorderPeriod < INFINITY) and not m_deliveryTimer)
	{
		m_deliveryTimer = scheduleTimer(m_messagesByTime.firstValue()->m_rxTime + m_reorderPeriod);
		m_deliveryTimer->action = [this] (const std::shared_ptr<Timer> &sender, Time now) {
			clearTimer();
			tryDeliver();
		};
	}
}

// advance the CSN to the highest sequence number seen in the reorder period
void ReorderBuffer::findCSN(Time now)
{
	Time deadline = now - m_reorderPeriod;

	while(not m_messagesByTime.empty())
	{
		auto &first = m_messagesByTime.firstValue();
		if(shouldDeliverNow(first->m_sequenceNumber) or (first->m_rxTime <= deadline))
		{
			m_csn = std::max(m_csn, _lastSN(first->m_sequenceNumber, first->m_fragmentCount));
			m_messagesByTime.removeFirst();
		}
		else
			break;
	}
}

// --- RunLoopReorderBuffer !! maybe move to a separate translation unit to avoid necessarily linking RunLoop

RunLoopReorderBuffer::RunLoopReorderBuffer(RunLoop *runloop) : m_runloop(runloop)
{}

Time RunLoopReorderBuffer::getCurrentTime() const
{
	return m_runloop->getCurrentTime();
}

std::shared_ptr<Timer> RunLoopReorderBuffer::scheduleTimer(Time when)
{
	return m_runloop->schedule(when);
}

} } } // namespace com::zenomt::rtmfp
