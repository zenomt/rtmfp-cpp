// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "Session.hpp"
#include "../include/rtmfp/VLU.hpp"
#include "../include/rtmfp/packet.hpp"
#include "../include/rtmfp/params.hpp"
#include "SendFrag.hpp"
#include "../include/rtmfp/PacketAssembler.hpp"

namespace com { namespace zenomt { namespace rtmfp {

SendFlow::SendFrag::SendFrag(SendFlow *owner, const uint8_t *data, size_t len, uintmax_t sequenceNumber, uint8_t fra, const std::shared_ptr<IssuerWriteReceipt> &receipt) :
	m_owner(owner),
	m_sequence_number(sequenceNumber),
	m_fra(fra),
	m_sent_abandoned(false),
	m_nak_count(0),
	m_in_flight(false),
	m_ever_sent(false),
	m_transmit_size(0),
	m_tsn(0),
	m_session_outstanding_name(-1),
	m_data(data, data + len),
	m_receipt(receipt)
{
}

size_t SendFlow::SendFrag::size_queue(const std::shared_ptr<SendFrag>& value)
{
	return value ? value->m_data.size() + FRAGMENT_SIZE_BIAS : 0;
}

size_t SendFlow::SendFrag::size_outstanding(const std::shared_ptr<SendFrag>& value)
{
	return value ? value->m_transmit_size : 0;
}

// ---

SendFlow::SendFlow(RTMFP *rtmfp, const Bytes &epd, const Bytes &metadata, RecvFlow *assoc, Priority pri) :
	Flow(rtmfp),
	m_flow_id(-1),
	m_epd(epd),
	m_writablePending(false),
	m_trimPending(false),
	m_shouldNotifyWhenWritable(false),
	m_priority(pri),
	m_buffer_capacity(INITIAL_SEND_BUFFER),
	m_outstanding_bytes(0),
	m_rx_buffer_size(INITIAL_RECV_BUFFER),
	m_next_sn(1),
	m_final_sn(0),
	m_exception(false),
	m_last_send_queue_name(0),
	m_state(F_OPEN),
	m_send_queue(SendFrag::size_queue)
{
	Option::append(USERDATA_OPTION_METADATA, metadata.data(), metadata.size(), m_startup_options);
	if(assoc)
	{
		Option::append(USERDATA_OPTION_RETURN_ASSOCIATION, assoc->m_flow_id, m_startup_options);
		m_tmp_association = share_ref(assoc);
	}
	Option::append(m_startup_options);
}

SendFlow::~SendFlow()
{
}

void SendFlow::addCandidateAddress(const Address &addr, Time delay)
{
	if(m_openingSession)
		m_openingSession->addCandidateAddress(addr, delay, false);
}

void SendFlow::addCandidateAddress(const struct sockaddr *addr, Time delay)
{
	addCandidateAddress(Address(addr), delay);
}

bool SendFlow::isWritable() const
{
	if( (not m_session)
	 or (Session::S_OPEN != m_session->m_state)
	 or (not isOpen())
	 or (getBufferedSize() >= getBufferCapacity())
	)
		return false;

	// TODO: unsent thresh/low watermark?

	return true;
}

void SendFlow::notifyWhenWritable()
{
	m_shouldNotifyWhenWritable = true;
	queueWritableNotify();
}

void SendFlow::setBufferCapacity(size_t len)
{
	m_buffer_capacity = len;
}

size_t SendFlow::getBufferCapacity() const
{
	return m_buffer_capacity;
}

size_t SendFlow::getBufferedSize() const
{
	return m_send_queue.sum();
}

size_t SendFlow::getRecvBufferBytesAvailable() const
{
	return m_rx_buffer_size;
}

size_t SendFlow::getOutstandingBytes() const
{
	return m_outstanding_bytes;
}

std::shared_ptr<WriteReceipt> SendFlow::write(const void *message, size_t len, Time startWithin, Time finishWithin)
{
	if(not isOpen())
		return std::shared_ptr<WriteReceipt>();

	return basicWrite(message, len, startWithin, finishWithin);
}

std::shared_ptr<WriteReceipt> SendFlow::write(const Bytes &message, Time startWithin, Time finishWithin)
{
	return write(message.data(), message.size(), startWithin, finishWithin);
}

void SendFlow::close()
{
	auto myself = share_ref(this);

	onWritable = nullptr;
	onException = nullptr;
	onRecvFlow = nullptr;

	Flow::close();

	if(F_OPEN == m_state)
	{
		if(m_session and (Session::S_OPEN == m_session->m_state) and (m_next_sn > 1))
		{
			if( (m_send_queue.empty())
			 or (m_send_queue.lastValue()->m_ever_sent)
			 or (m_send_queue.lastValue()->m_sequence_number != m_next_sn - UINTMAX_C(1))
			)
				basicWrite(nullptr, 0, -1, -1);

			m_final_sn = m_send_queue.lastValue()->m_sequence_number;

			m_state = F_CLOSING;
		}
		else
			gotoStateClosed();
	}

	if(m_session and (Session::S_OPEN != m_session->m_state))
		gotoStateClosed();

	m_rtmfp->sendFlowIsNotOpening(myself);
}

Priority SendFlow::getPriority() const
{
	return m_priority;
}

void SendFlow::setPriority(Priority pri)
{
	bool changed = pri != m_priority;
	m_priority = pri;

	if(changed)
		scheduleForTransmission();
}

// ---

std::shared_ptr<WriteReceipt> SendFlow::basicWrite(const void *message, size_t len, Time startWithin, Time finishWithin)
{
	Time now = m_rtmfp->getCurrentTime();
	auto rv = share_ref(new IssuerWriteReceipt(now, startWithin, finishWithin), false);

	const uint8_t *cursor = (const uint8_t *)message;
	size_t remaining = len;
	size_t maxFragmentLength = MAX_DATA_FRAG_LENGTH - m_startup_options.size();

	uint8_t fra = USERDATA_FRA_WHOLE;
	do
	{
		size_t fragSize = remaining;
		if(fragSize > maxFragmentLength)
		{
			fragSize = maxFragmentLength;
			if(USERDATA_FRA_WHOLE == fra)
				fra = USERDATA_FRA_BEGIN;
			else
				fra = USERDATA_FRA_MIDDLE;
		}
		else
		{
			if(USERDATA_FRA_WHOLE != fra)
				fra = USERDATA_FRA_END;
		}

		auto fragment = share_ref(new SendFrag(this, cursor, fragSize, m_next_sn, fra, rv), false);
		m_send_queue.append(fragment);
		rv->useCountUp();

		m_next_sn++;
		cursor += fragSize;
		remaining -= fragSize;
	} while(remaining);

	if(m_session and (Session::S_OPEN == m_session->m_state))
		scheduleForTransmission();

	scheduleTrimSendQueue(); // keep buffer under control in case we never get scheduled for transmit

	return rv;
}

void SendFlow::onSessionDidOpen(std::shared_ptr<SendFlow> myself, std::shared_ptr<Session> session)
{
	if(m_session)
		return;

	if( (not m_openingSession)
	 or (session == m_openingSession)
	 or (session->m_cryptoCert->isSelectedByEPD(m_epd.data(), m_epd.size()))
	)
	{
		m_session = session;
		m_session->bindFlow(myself);

		if(m_openingSession)
		{
			m_openingSession->interestDown();
			m_openingSession.reset();
		}

		scheduleForTransmission();
		queueWritableNotify();
	}
}

void SendFlow::onSessionWillOpen(std::shared_ptr<Session> session)
{
	if(m_session)
		return;

	if(  (m_openingSession)
	 and (session != m_openingSession)
	 and (Session::S_IHELLO_SENT == m_openingSession->m_state)
	)
	{
		std::shared_ptr<Session> previousSession = m_openingSession;
		m_openingSession = session;
		session->interestUp();
		previousSession->interestDown();
	}
}

void SendFlow::onSessionDidClose(std::shared_ptr<Session> session)
{
	if((m_session == session) or ((not m_session) and (m_openingSession == session)))
		onExceptionReport(0);
}

void SendFlow::queueWritableNotify()
{
	if(m_shouldNotifyWhenWritable and not m_writablePending)
	{
		auto myself = share_ref(this);
		m_rtmfp->m_platform->perform(0, [myself] { myself->doWritable(); });
		m_writablePending = true;
	}
}

void SendFlow::doWritable()
{
	m_writablePending = false;
	while(m_shouldNotifyWhenWritable and isWritable())
		m_shouldNotifyWhenWritable = onWritable ? onWritable() : false;
}

void SendFlow::scheduleForTransmission()
{
	if(isMaybeReadyForTransmission())
		m_session->scheduleFlowForTransmission(share_ref(this), m_priority);
}

bool SendFlow::isMaybeReadyForTransmission()
{
	if(m_send_queue.empty())
		return false;

	return m_exception or (m_rx_buffer_size > m_outstanding_bytes);
}

void SendFlow::trimSendQueue(Time now)
{
	bool anyTrimmed = false;
	while(true)
	{
		if(m_send_queue.size() < 2)
			break;
		auto &first = m_send_queue.firstValue();
		if(first->m_in_flight)
			break;
		first->m_receipt->abandonIfNeeded(now);
		if(not first->m_receipt->isAbandoned())
			break;
		first->m_receipt->useCountDown();
		m_send_queue.removeFirst();
		anyTrimmed = true;
	}

	if(anyTrimmed)
		queueWritableNotify();
}

void SendFlow::scheduleTrimSendQueue()
{
	if(not m_trimPending)
	{
		auto myself = share_ref(this);
		m_trimPending = true;
		m_rtmfp->m_platform->perform(0, [myself] {
			myself->trimSendQueue(myself->m_rtmfp->getCurrentTime());
			myself->m_trimPending = false;
		});
	}
}

uintmax_t SendFlow::findForwardSequenceNumber(Time now)
{
	auto &first = m_send_queue.firstValue();

	if(not first->m_in_flight)
		first->m_receipt->abandonIfNeeded(now);

	if(not first->m_receipt->isAbandoned())
		return first->m_sequence_number - 1;
	else if(first->m_in_flight and not first->m_sent_abandoned)
		return first->m_sequence_number - 1;
	return first->m_sequence_number;
}

bool SendFlow::assembleData(PacketAssembler *packet, int pri)
{
	if(pri != m_priority)
		return false;

	if(not isMaybeReadyForTransmission())
		return false;

	Time now = m_rtmfp->getCurrentTime();
	trimSendQueue(now);
	uintmax_t fsn = findForwardSequenceNumber(now);
	bool firstChunk = true;
	uintmax_t previousSN = 0;

	// maybe we can pick up where we left off instead of scanning the send queue from
	// the beginning for each packet. can make a difference in high bandwidth × delay.
	long startName = m_last_send_queue_name;
	if(not (m_send_queue.has(startName) and m_send_queue.at(startName)->m_in_flight))
		startName = m_send_queue.first();

	// handle a (hopefully rare) case where we are associated in return to a flow that
	// has completely closed (so the other end has forgotten the flow ID), but we're still
	// starting up.
	if(m_startup_options.size() and m_tmp_association and (m_tmp_association->m_state >= RecvFlow::RF_COMPLETE_LINGER))
	{
		// clear the startup options. it's possible that the other end has already
		// seen our startup options, so things are fine. if not and this ends up being the
		// first one, the other end will reject the flow because now there's no metadata either.
		// this protects against accidentally associating to a new different flow with
		// the old flow's ID.
		m_startup_options.clear();
		m_tmp_association.reset();
	}

	// fill up a packet
	for(long name = startName; name > 0; name = m_send_queue.next(name))
	{
		if(m_outstanding_bytes >= m_rx_buffer_size)
			break;

		auto &frag = m_send_queue.at(name);
		if(frag->m_in_flight)
			continue;

		uint8_t flag_fin = frag->m_sequence_number == m_final_sn ? USERDATA_FLAG_FIN : 0;

		if(frag->m_ever_sent and not frag->m_receipt->retransmit)
			frag->m_receipt->abandon();
		frag->m_receipt->abandonIfNeeded(now);
		uint8_t flag_abn = frag->m_receipt->isAbandoned() ? USERDATA_FLAG_ABN : 0;

		// departure from §3.6.2.3: we send a fragment even if abandoned (though with
		// the ABN flag set and no data), so the receiver can potentially save an RTT
		// for in-order delivery with gaps. the cost of each abandoned fragment is
		// only 4 bytes.

		uint8_t chunkType = CHUNK_USERDATA;
		if((not firstChunk) and (frag->m_sequence_number == previousSN + 1))
			chunkType = CHUNK_NEXT_USERDATA;

		size_t remainingBeforeChunk = packet->remaining();

		if(not packet->startChunk(chunkType))
			break;

		uint8_t flag_opt = (firstChunk and m_startup_options.size()) ? USERDATA_FLAG_OPT : 0;
		uint8_t flags = flag_opt | frag->m_fra | flag_abn | flag_fin;

		if(not packet->push(flags))
			goto overrun;

		if(CHUNK_USERDATA == chunkType)
		{
			if( (not packet->pushVLU(m_flow_id))
			 or (not packet->pushVLU(frag->m_sequence_number))
			 or (not packet->pushVLU(frag->m_sequence_number - fsn))
			)
				goto overrun;
		}

		if(flag_opt and not packet->push(m_startup_options))
			goto overrun;

		if((not flag_abn) and not packet->push(frag->m_data))
			goto overrun;

		packet->commitChunk();

		firstChunk = false;
		previousSN = frag->m_sequence_number;

		frag->m_receipt->start();
		frag->m_sent_abandoned = flag_abn;
		frag->m_transmit_size = remainingBeforeChunk - packet->remaining();
		frag->m_tsn = m_session->m_next_tsn;
		frag->m_in_flight = true;
		frag->m_ever_sent = true;
		frag->m_nak_count = 0;
		frag->m_session_outstanding_name = m_session->m_outstandingFrags.append(frag);

		m_outstanding_bytes += frag->m_transmit_size;
		m_last_send_queue_name = name;

		continue;

overrun:
		packet->rollbackChunk();
		break;
	}

	if(not firstChunk)
	{
		if(m_priority > PRI_ROUTINE)
			packet->setTimeCriticalFlag();

		m_session->rescheduleTimeoutAlarm();

		return true;
	}

	return false;
}

void SendFlow::ackRange(long &name, uintmax_t ackFrom, uintmax_t ackTo)
{
	while(name > 0)
	{
		long next = m_send_queue.next(name);

		auto &frag = m_send_queue.at(name);

		if(frag->m_sequence_number < ackFrom)
		{
			name = next;
			continue;
		}

		if(frag->m_sequence_number > ackTo)
			break;

		if(frag->m_in_flight)
		{
			if(frag->m_tsn > m_session->m_max_tsn_ack)
				m_session->m_max_tsn_ack = frag->m_tsn;
			m_session->m_outstandingFrags.remove(frag->m_session_outstanding_name);
			m_outstanding_bytes -= frag->m_transmit_size;
		}

		frag->m_receipt->useCountDown();

		m_send_queue.remove(name);

		name = next;
	}
}

void SendFlow::onAck(uint8_t chunkType, size_t bufferBytesAvailable, uintmax_t cumulativeAck, const uint8_t *disjointed, const uint8_t *limit)
{
	if(m_state >= F_COMPLETE_LINGER)
		return;

	if(not m_startup_options.empty())
	{
		m_startup_options.clear();
		m_tmp_association.reset();
	}

	m_rx_buffer_size = bufferBytesAvailable;

	if(0 == m_rx_buffer_size)
		setPersistTimer();
	else if(m_persistTimer)
	{
		m_persistTimer->cancel();
		m_persistTimer.reset();
	}

	long name = m_send_queue.first();
	ackRange(name, 0, cumulativeAck);

	if(CHUNK_ACK_RANGES == chunkType)
	{
		const uint8_t *cursor = disjointed;
		uintmax_t ackCursor = cumulativeAck;
		while(cursor < limit)
		{
			uintmax_t holesMinusOne;
			uintmax_t receivedMinusOne;
			size_t rv;

			if(0 == (rv = VLU::parse(cursor, limit, &holesMinusOne)))
				break; // truncations allowed
			cursor += rv;

			if(0 == (rv = VLU::parse(cursor, limit, &receivedMinusOne)))
				break; // truncations allowed
			cursor += rv;

			ackCursor++;
			uintmax_t rangeFrom = ackCursor + holesMinusOne + 1;
			uintmax_t rangeTo = rangeFrom + receivedMinusOne;
			ackRange(name, rangeFrom, rangeTo);

			ackCursor = rangeTo;
		}
	}
	else if(CHUNK_ACK_BITMAP == chunkType)
	{
		// TODO: nobody actually sends these yet
	}

	if((F_CLOSING == m_state) and m_send_queue.empty())
	{
		m_state = F_COMPLETE_LINGER;
		auto myself = share_ref(this);
		m_rtmfp->scheduleRel(F_COMPLETE_LINGER_PERIOD)->action = Timer::makeAction([myself] { myself->gotoStateClosed(); });
	}
	else
	{
		scheduleForTransmission();
		queueWritableNotify();
	}
}

void SendFlow::onExceptionReport(uintmax_t exceptionCode)
{
	retain();

	m_exception = true;

	std::function<void(uintmax_t reason)> exception_f;
	swap(exception_f, onException);
	close();
	if(exception_f)
		exception_f(exceptionCode);

	m_send_queue.valuesDo([] (std::shared_ptr<SendFrag> &frag) { frag->m_receipt->abandon(); return true; });

	release();
}

void SendFlow::setPersistTimer()
{
	if(m_persistTimer)
		return;

	Time interval = std::max(F_PERSIST_INITIAL_PERIOD, m_session->m_erto);
	m_persistTimer = m_rtmfp->scheduleRel(interval, interval);
	auto myself = share_ref(this);
	m_persistTimer->action = [myself] (const std::shared_ptr<Timer> &sender, Time now) { myself->onPersistTimer(sender, now); };
}

void SendFlow::onPersistTimer(const std::shared_ptr<Timer> &sender, Time now)
{
	if(m_state > F_CLOSING)
	{
		sender->cancel();
		m_persistTimer.reset();
		return;
	}

	uint8_t buf[VLU::MAX_VLU_SIZE + 3];
	PacketAssembler probe;
	probe.init(buf, 0, sizeof(buf));

	probe.startChunk(CHUNK_BUFFERPROBE);
	probe.pushVLU(m_flow_id);
	probe.commitChunk();
	m_session->sendPacket(probe.toVector());

	Time nextInterval = sender->getRecurInterval();
	nextInterval = std::min(nextInterval * F_PERSIST_BACKOFF_FACTOR, F_PERSIST_MAX_PERIOD);
	nextInterval = std::max(nextInterval, m_session->m_erto);
	sender->setRecurInterval(nextInterval);
}

void SendFlow::onLoss(size_t amount)
{
	m_outstanding_bytes -= amount;
	m_last_send_queue_name = m_send_queue.SENTINEL;
	scheduleForTransmission();
}

void SendFlow::gotoStateClosed()
{
	if(m_state < F_CLOSED)
	{
		m_state = F_CLOSED;

		if(m_session)
		{
			m_session->unbindFlow(m_flow_id, this);
			m_flow_id = -1;
			m_session.reset();
		}
		if(m_openingSession)
		{
			m_openingSession->interestDown();
			m_openingSession.reset();
		}
		if(m_persistTimer)
		{
			m_persistTimer->cancel();
			m_persistTimer.reset();
		}
		m_tmp_association.reset();
	}
}

} } } // namespace com::zenomt::rtmfp
