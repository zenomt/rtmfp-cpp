// Copyright © 2023 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "../include/rtmfp/RateTracker.hpp"

#include <algorithm>
#include <cmath>

namespace com { namespace zenomt {

RateTracker::RateTracker(Time windowPeriod) :
	m_windowPeriod(windowPeriod),
	m_windowBegin(-INFINITY),
	m_count(0),
	m_previousRate(0.0)
{ }

void RateTracker::update(size_t count, Time now)
{
	Time delta = now - m_windowBegin;
	if(delta < 0)
		return;

	if(delta >= m_windowPeriod)
	{
		m_previousRate = getRate(now);
		m_windowBegin = now; // m_previousRate accounts for decayed portion up to now
		m_count = 0;
	}

	m_count += count;
}

double RateTracker::getRate(Time now) const
{
	Time delta = now - m_windowBegin;
	if(delta < 0)
		delta = 0;

	const Time twoWindows = m_windowPeriod * 2.0;

	if(delta >= twoWindows)
		return 0.0;

	if(delta >= m_windowPeriod)
	{
		long double decay = (twoWindows - delta) / m_windowPeriod;
		return m_count * decay / m_windowPeriod;
	}

	// else 0 ≤ delta < m_windowPeriod
	if(m_previousRate > 0.0)
	{
		long double previousPortion = 1.0 - delta / m_windowPeriod;
		return (m_count / m_windowPeriod) + (m_previousRate * previousPortion);
	}
	else
		return m_count / m_windowPeriod;
}

void RateTracker::setWindowPeriod(Time windowPeriod)
{
	m_windowPeriod = std::max(windowPeriod, Time(0.000001)); // 1 µs
}

Time RateTracker::getWindowPeriod() const
{
	return m_windowPeriod;
}

void RateTracker::reset()
{
	m_windowBegin = -INFINITY;
	m_count = 0;
	m_previousRate = 0;
}

} } // namespace com::zenomt
