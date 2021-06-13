// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cstring>

#include "Session.hpp"
#include "../include/rtmfp/VLU.hpp"
#include "../include/rtmfp/packet.hpp"
#include "../include/rtmfp/params.hpp"
#include "../include/rtmfp/PacketAssembler.hpp"

namespace com { namespace zenomt { namespace rtmfp {

struct RecvFlow::RecvFrag : public Object {
	uintmax_t m_sequence_number;
	long      m_segmentStart;
	long      m_segmentEnd;
	uint8_t   m_fra;
	Bytes     m_data;

	RecvFrag(uintmax_t sequenceNumber, uint8_t fra, const uint8_t *bytes, size_t len) :
		m_sequence_number(sequenceNumber),
		m_segmentStart(-1),
		m_segmentEnd(-1),
		m_fra(fra),
		m_data(bytes, bytes + len)
	{}

	size_t size() const
	{
		return m_data.size() + FRAGMENT_SIZE_BIAS;
	}

	static size_t size_frag(const std::shared_ptr<RecvFrag>& value)
	{
		return value ? value->size() : 0;
	}
};


RecvFlow::RecvFlow(std::shared_ptr<Session> session, uintmax_t flowID, const uint8_t *metadata, size_t metadataLen, std::shared_ptr<SendFlow> associatedFlow) :
	Flow(session->m_rtmfp),
	m_flow_id(flowID),
	m_metadata(metadata, metadata + metadataLen),
	m_accepted(false),
	m_rxOrder(RO_SEQUENCE),
	m_forward_sn(0),
	m_final_sn(0),
	m_final_sn_seen(false),
	m_recv_buffer(RecvFrag::size_frag),
	m_buffer_capacity(INITIAL_RECV_BUFFER),
	m_window_limit(~0), // unlimited
	m_prev_rwnd(0),
	m_should_ack(false),
	m_exception_code(0),
	m_state(RF_OPEN),
	m_associatedFlow(associatedFlow)
{
	m_session = session;
}

RecvFlow::~RecvFlow()
{
}

bool RecvFlow::isOpen() const
{
	return Flow::isOpen() and m_accepted;
}

void RecvFlow::close()
{
	retain();

	if(RF_OPEN == m_state)
	{
		m_state = RF_REJECTED;
		scheduleAck(true);
	}

	m_recv_buffer.clear();

	onMessage = nullptr;
	onComplete = nullptr;
	onCumulativeAckDidMerge = nullptr;

	Flow::close();

	release();
}

void RecvFlow::close(uintmax_t reason)
{
	m_exception_code = reason;
	close();
}

void RecvFlow::accept()
{
	m_accepted = true;
}

void RecvFlow::setReceiveOrder(ReceiveOrder order)
{
	bool wasHold = m_rxOrder == RO_HOLD;
	m_rxOrder = order;
	if(wasHold and (RO_HOLD != order))
	{
		auto myself = share_ref(this);
		m_rtmfp->m_platform->perform(0, [myself] { myself->tryDelivery(-1); });
	}
}

ReceiveOrder RecvFlow::getReceiveOrder() const
{
	return m_rxOrder;
}

size_t RecvFlow::getBufferCapacity() const
{
	return m_buffer_capacity;
}

void RecvFlow::setBufferCapacity(size_t len)
{
	m_buffer_capacity = len;
	scheduleAck(true);
}

size_t RecvFlow::getBufferedSize() const
{
	return m_recv_buffer.sum();
}

size_t RecvFlow::getWindowLimit() const
{
	return m_window_limit;
}

void RecvFlow::setWindowLimit(size_t len)
{
	m_window_limit = len;
	scheduleAck(true);
}

Bytes RecvFlow::getMetadata() const
{
	return m_metadata;
}

uintmax_t RecvFlow::getForwardSequenceNumber() const
{
	return m_forward_sn;
}

uintmax_t RecvFlow::getCumulativeAckSequenceNumber() const
{
	return m_sequence_set.firstRange().end;
}

std::shared_ptr<SendFlow> RecvFlow::getAssociatedSendFlow() const
{
	return m_associatedFlow;
}

std::shared_ptr<SendFlow> RecvFlow::openReturnFlow(const void *metadata_, size_t metadataLen, Priority pri)
{
	const uint8_t *metadata = (const uint8_t *)metadata_;
	return openReturnFlow(Bytes(metadata, metadata + metadataLen), pri);
}

std::shared_ptr<SendFlow> RecvFlow::openReturnFlow(const Bytes &metadata, Priority pri)
{
	return basicOpenFlow(metadata, this, pri);
}

// ---

void RecvFlow::abort()
{
	closeAndNotify(true);
	m_state = RF_CLOSED;
	if(m_complete_linger_alarm)
		m_complete_linger_alarm->cancel();
	m_complete_linger_alarm.reset();
}

void RecvFlow::closeAndNotify(bool error)
{
	bool wasOpen = isOpen();
	std::function<void(bool error)> complete_f;
	swap(complete_f, onComplete);
	close();
	if(wasOpen and complete_f)
		complete_f(error);
}

void RecvFlow::onData(uint8_t flags, uintmax_t sequenceNumber, uintmax_t fsn, const uint8_t *data, size_t len)
{
	bool ack_now = false;

	bool fresh = not m_sequence_set.contains(sequenceNumber);
	bool abandoned = flags & USERDATA_FLAG_ABN;

	size_t preRangeCount = m_sequence_set.countRanges();

	// RFC 7016 §3.6.3.2 session.ACK_NOW checks
	if( (m_prev_rwnd < 2)
	 or (abandoned)
	 or (preRangeCount != 1)
	 or (not fresh)
	)
		ack_now = true;

	if(  (fresh)
	 and (flags & USERDATA_FLAG_FIN)
	 and (not m_final_sn_seen)
	)
	{
		m_final_sn = sequenceNumber;
		m_final_sn_seen = true;
		ack_now = true;
	}

	if(fsn > m_forward_sn)
		m_forward_sn = fsn;

	uintmax_t preCSN = getCumulativeAckSequenceNumber();

	m_sequence_set.add(0, fsn);
	m_sequence_set.add(sequenceNumber);

	size_t postRangeCount = m_sequence_set.countRanges();

	long deliveryHint = -1;
	if(fresh and (not abandoned) and (RF_OPEN == m_state))
		deliveryHint = insertFragment(sequenceNumber, flags, data, len);

	if(m_final_sn_seen and (m_state < RF_COMPLETE_LINGER) and (m_sequence_set.countRanges() == 1))
	{
		m_state = RF_COMPLETE_LINGER;
		ack_now = true;
		auto myself = share_ref(this);
		m_complete_linger_alarm = m_rtmfp->scheduleRel(RF_COMPLETE_LINGER_PERIOD);
		m_complete_linger_alarm->action = Timer::makeAction([myself] {
			if(myself->m_state < RF_CLOSED)
			{
				myself->m_state = RF_CLOSED;
				myself->m_session->unbindFlow(myself->m_flow_id, myself.get());
			}
			myself->m_complete_linger_alarm.reset();
		});
	}

	tryDelivery(deliveryHint);

	if(preRangeCount != postRangeCount)
	{
		ack_now = true;

		if(  (postRangeCount < preRangeCount)
		 and (RO_NETWORK == m_rxOrder)
		 and (RF_OPEN == m_state)
		 and (preCSN < getCumulativeAckSequenceNumber())
		 and onCumulativeAckDidMerge
		)
			onCumulativeAckDidMerge();
	}

	if(RF_OPEN != m_state)
		ack_now = true;

	scheduleAck(ack_now);
}

long RecvFlow::insertFragment(uintmax_t sequenceNumber, uint8_t flags, const uint8_t *data, size_t len)
{
	uint8_t fra = flags & USERDATA_FLAG_FRA_MASK;

	long name;
	for(name = m_recv_buffer.last(); name > m_recv_buffer.SENTINEL; name = m_recv_buffer.prev(name))
	{
		if(m_recv_buffer.at(name)->m_sequence_number < sequenceNumber)
			break;
	}

	auto fragment = share_ref(new RecvFrag(sequenceNumber, fra, data, len), false);
	name = fragment->m_segmentStart = fragment->m_segmentEnd = m_recv_buffer.addAfter(fragment, name);

	if(USERDATA_FRA_WHOLE == fra)
		return name;

	// try to connect new fragment to existing segment
	long prevName;
	long nextName;
	bool hasBegin = USERDATA_FRA_BEGIN == fra;
	bool hasEnd = USERDATA_FRA_END == fra;

	if((USERDATA_FRA_BEGIN != fra) and ((prevName = m_recv_buffer.prev(name)) > 0))
	{
		auto prevFragment = m_recv_buffer.at(prevName);
		if(prevFragment->m_sequence_number == sequenceNumber - 1)
			fragment->m_segmentStart = prevFragment->m_segmentStart;
	}

	if((USERDATA_FRA_END != fra) and ((nextName = m_recv_buffer.next(name)) > 0))
	{
		auto nextFragment = m_recv_buffer.at(nextName);
		if(nextFragment->m_sequence_number == sequenceNumber + 1)
			fragment->m_segmentEnd = nextFragment->m_segmentEnd;
	}

	if(fragment->m_segmentStart != name)
	{
		auto startFragment = m_recv_buffer.at(fragment->m_segmentStart);
		startFragment->m_segmentEnd = fragment->m_segmentEnd;
		hasBegin = startFragment->m_fra == USERDATA_FRA_BEGIN;
	}

	if(fragment->m_segmentEnd != name)
	{
		auto endFragment = m_recv_buffer.at(fragment->m_segmentEnd);
		endFragment->m_segmentStart = fragment->m_segmentStart;
		hasEnd = endFragment->m_fra == USERDATA_FRA_END;
	}

	return (hasBegin and hasEnd) ? fragment->m_segmentStart : -1;
}

void RecvFlow::deliverMessage(long start)
{
	if(m_prev_rwnd < 2)
		scheduleAck(true);

	auto fragment = m_recv_buffer.at(start);
	uintmax_t sequenceNumber = fragment->m_sequence_number;
	if(USERDATA_FRA_WHOLE == fragment->m_fra)
	{
		if(onMessage)
			onMessage(fragment->m_data.data(), fragment->m_data.size(), sequenceNumber, 1);
		m_recv_buffer.remove(start);
		return;
	}

	size_t len = 0;
	size_t fragmentCount = 0;

	long name = start;
	while(true)
	{
		auto each = m_recv_buffer.at(name);
		len += each->m_data.size();
		fragmentCount++;
		if(USERDATA_FRA_END == each->m_fra)
			break;
		name = m_recv_buffer.next(name);
	}

	Bytes buf(len);
	uint8_t *cursor = buf.data();
	name = start;
	while(true)
	{
		long nextName = m_recv_buffer.next(name);
		auto each = m_recv_buffer.at(name);
		size_t eachLen = each->m_data.size();
		memmove(cursor, each->m_data.data(), eachLen);
		cursor += eachLen;
		m_recv_buffer.remove(name);
		if(USERDATA_FRA_END == each->m_fra)
			break;
		name = nextName;
	}

	if(onMessage)
		onMessage(buf.data(), len, sequenceNumber, fragmentCount);
}

void RecvFlow::tryDelivery(long hint)
{
	if((hint > 0) and (RO_NETWORK == m_rxOrder) and isOpen())
		deliverMessage(hint);

	// deliver complete messages
	uintmax_t csn = getCumulativeAckSequenceNumber();
	while((RO_HOLD != m_rxOrder) and isOpen() and m_recv_buffer.size())
	{
		long name = m_recv_buffer.first();
		auto fragment = m_recv_buffer.at(name);

		if(fragment->m_sequence_number > csn)
			break;

		if(USERDATA_FRA_WHOLE == fragment->m_fra)
			deliverMessage(name);
		else if(USERDATA_FRA_BEGIN != fragment->m_fra)
			m_recv_buffer.remove(name);
		else
		{
			auto endFrag = m_recv_buffer.at(fragment->m_segmentEnd);
			if(USERDATA_FRA_END == endFrag->m_fra)
				deliverMessage(name);
			else if(endFrag->m_sequence_number < csn)
				m_recv_buffer.remove(name);
			else
				break; // in progress
		}
	}

	if(m_final_sn_seen and (m_final_sn <= csn) and m_recv_buffer.empty())
		closeAndNotify(false);
}

void RecvFlow::scheduleAck(bool now)
{
	// do this first to avoid scheduling the delack alarm just to cancel it immediately
	if(now)
		m_session->ackNow();

	if(not m_should_ack)
	{
		m_should_ack = true;
		m_session->scheduleAck(share_ref(this));
	}
}

bool RecvFlow::assembleAck(PacketAssembler *packet, bool truncateAllowed)
{
	uint8_t *checkpoint = packet->m_cursor; // we might roll back over a committed exception chunk
	bool didTruncate = false;
	uintmax_t ackCursor = getCumulativeAckSequenceNumber();
	size_t advertise_bytes;
	size_t buffered_size = m_recv_buffer.sum();

	if(buffered_size >= m_buffer_capacity)
		advertise_bytes = 0;
	else
		advertise_bytes = std::min(m_buffer_capacity - buffered_size, m_window_limit);
	size_t advertise_blocks = (advertise_bytes + 1023) / 1024;

	if((0 == advertise_blocks) and (m_buffer_capacity > 0) and (m_window_limit > 0) and (RO_HOLD != m_rxOrder))
		advertise_blocks = 1;

	if(RF_REJECTED == m_state)
	{
		if(packet->startChunk(CHUNK_EXCEPTION) and packet->pushVLU(m_flow_id) and packet->pushVLU(m_exception_code))
			packet->commitChunk();
		else
			goto fail;
	}

	if( (not packet->startChunk(CHUNK_ACK_RANGES))
	 or (not packet->pushVLU(m_flow_id))
	 or (not packet->pushVLU(advertise_blocks))
	 or (not packet->pushVLU(ackCursor))
	)
		goto fail; // need up to here even if we can truncate

	m_sequence_set.extentsDo([packet, &ackCursor, &didTruncate] (uintmax_t from, uintmax_t to) {
		if(0 == from) // first range, handled already
			return true;
		uintmax_t holesMinusOne = from - ackCursor - 2;
		uintmax_t receivedMinusOne = to - from;
		ackCursor = to;

		if((not packet->pushVLU(holesMinusOne)) or (not packet->pushVLU(receivedMinusOne)))
			didTruncate = true;

		return not didTruncate;
	});

	if(didTruncate and not truncateAllowed)
		goto fail;

	packet->commitChunk();
	m_should_ack = false;
	m_prev_rwnd = advertise_blocks;
	return true;

fail:
	packet->m_cursor = checkpoint;
	return false;
}

} } } // namespace com::zenomt::rtmfp
