// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "../include/rtmfp/rtmfp.hpp"

namespace com { namespace zenomt { namespace rtmfp {

WriteReceipt::WriteReceipt(Time origin, Time startWithin, Time finishWithin) :
	startBy(origin + startWithin),
	finishBy(origin + finishWithin),
	retransmit(true),
	m_origin(origin),
	m_started(false),
	m_abandoned(false),
	m_useCount(0)
{
}

void WriteReceipt::abandon()
{
	if(m_useCount and not m_abandoned)
	{
		m_abandoned = true;
		parent.reset();
		if(onFinished)
			onFinished(true);
		onFinished = nullptr;
	}
}

void WriteReceipt::setStartWithin(Time age)
{
	startBy = m_origin + age;
}

void WriteReceipt::setFinishWithin(Time age)
{
	finishBy = m_origin + age;
}

Time WriteReceipt::createdAt() const
{
	return m_origin;
}

bool WriteReceipt::isAbandoned() const
{
	return m_abandoned;
}

bool WriteReceipt::isStarted() const
{
	return m_started;
}

bool WriteReceipt::isDelivered() const
{
	return isFinished() and not isAbandoned();
}

bool WriteReceipt::isFinished() const
{
	return 0 == m_useCount;
}

void WriteReceipt::useCountUp()
{
	m_useCount++;
}

void WriteReceipt::useCountDown()
{
	if(0 == --m_useCount)
	{
		parent.reset();
		if(onFinished)
			onFinished(false);
		onFinished = nullptr;
	}
}

void WriteReceipt::start()
{
	m_started = true;
}

void WriteReceipt::abandonIfNeeded(Time now)
{
	if(m_abandoned)
		return;

	if( (now > finishBy)
	 or ((not m_started) and (now > startBy))
	 or (parent and parent->isAbandoned())
	)
		abandon();
}

} } } // namespace com::zenomt::rtmfp
