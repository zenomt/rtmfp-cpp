// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <algorithm>
#include <cmath>

#include "../include/rtmfp/Timer.hpp"

namespace com { namespace zenomt {

// --- Timer


Timer::Timer(Time when, Duration recurInterval, bool catchup) :
	m_when(when),
	m_timerList(nullptr),
	m_canceled(false),
	m_rescheduled(false),
	m_catchup(catchup),
	m_firing(false)
{
	setRecurInterval(recurInterval);
}

bool Timer::isDue(Time now) const
{
	return m_when <= now;
}

Time Timer::getNextFireTime() const
{
	return m_when;
}

void Timer::setNextFireTime(Time when)
{
	if(isCanceled())
		return;

	if(m_timerList)
	{
		std::shared_ptr<Timer> myself = share_ref(this);
		TimerList *timerList = m_timerList;
		timerList->removeTimer(myself);
		m_when = when;
		timerList->addTimer(myself);
	}
	else
		m_when = when;

	m_rescheduled = true;
}

Duration Timer::getRecurInterval() const
{
	return m_recurInterval;
}

void Timer::setRecurInterval(Duration interval)
{
	if((interval > 0) and (interval < MIN_RECUR_INTERVAL))
		interval = MIN_RECUR_INTERVAL;
	m_recurInterval = interval;
}

bool Timer::doesRecur() const
{
	return (m_recurInterval > 0.0) and not isCanceled();
}

void Timer::cancel()
{
	m_canceled = true;
	if(not m_firing)
		action = nullptr; // in case any circular references

	if(m_timerList)
		m_timerList->removeTimer(share_ref(this));
	m_timerList = nullptr;
}

bool Timer::isCanceled() const
{
	return m_canceled;
}

void Timer::fire(const std::shared_ptr<Timer> &timer, Time now)
{
	timer->basicFire(timer, now);
}

bool Timer::operator< (const Timer &rhs) const
{
	if(m_when == rhs.m_when)
		return this < &rhs;
	return m_when < rhs.m_when;
}

void Timer::setTimerList(TimerList *timerList)
{
	m_timerList = timerList;
}

TimerList * Timer::getTimerList() const
{
	return m_timerList;
}

Timer::Action Timer::makeAction(const std::function<void(Time now)> &fn)
{
	return [=] (const std::shared_ptr<Timer> &, Time now) { fn(now); };
}

Timer::Action Timer::makeAction(const Task &fn)
{
	return [=] (const std::shared_ptr<Timer> &, Time) { fn(); };
}

void Timer::basicFire(const std::shared_ptr<Timer> &myself, Time now)
{
	if(isCanceled())
		return;

	m_rescheduled = false;

	m_firing = true;
	if(action)
		action(myself, now);
	m_firing = false;

	if(doesRecur() or m_rescheduled)
	{
		if(not m_rescheduled)
		{
			// we're being fired from the timer list, so we've already been removed from it.
			// therefore it's safe to change our sort key.
			if((now > m_when) and m_catchup)
				m_when += ceill((now - m_when) / m_recurInterval) * m_recurInterval;
			else
				m_when += m_recurInterval; // called exactly on time

			if(m_timerList)
				m_timerList->addTimer(myself);
		}
		// otherwise was rescheduled during action, so don't use the recur interval
	}
	else
	{
		m_timerList = nullptr; // i'm not in it anyway, this saves an unnecessary attempt to remove myself
		cancel();
	}
}

// --- TimerList

TimerList::TimerList() : m_running(false)
{ }

TimerList::~TimerList()
{
	// cancel all timers in the list to clear potential circular references
	while(not m_timers.empty())
	{
		auto it = m_timers.begin();
		auto each = *it;
		each->setTimerList(nullptr);
		each->cancel();
		m_timers.erase(it);
	}
}

std::shared_ptr<Timer> TimerList::schedule(Time when, Duration recurInterval, bool catchup)
{
	auto rv = share_ref<Timer>(new Timer(when, recurInterval, catchup), false);
	addTimer(rv);
	return rv;
}

std::shared_ptr<Timer> TimerList::schedule(const Timer::Action &action, Time when, Duration recurInterval, bool catchup)
{
	auto rv = schedule(when, recurInterval, catchup);
	rv->action = action;
	return rv;
}

Duration TimerList::howLongToNextFire(Time now, Duration maxInterval) const
{
	if(m_timers.empty())
		return maxInterval;

	return std::min(maxInterval, (*m_timers.begin())->getNextFireTime() - now);
}

size_t TimerList::fireDueTimers(Time now)
{
	size_t rv = 0;

	m_running = true;

	while(true)
	{
		if(m_timers.empty())
			break;

		auto it = m_timers.begin();
		std::shared_ptr<Timer> each = *it;

		if(not each->isDue(now))
			break;

		m_timers.erase(it);

		Timer::fire(each, now);
		rv++;
	}

	m_running = false;

	return rv;
}

void TimerList::addTimer(const std::shared_ptr<Timer> &timer)
{
	if(not timer)
		return;

	bool willFireEarlier = m_timers.empty() or (timer->getNextFireTime() < (*m_timers.begin())->getNextFireTime());

	timer->setTimerList(this);
	m_timers.insert(timer);

	if(willFireEarlier and onHowLongToSleepDidChange and not m_running)
		onHowLongToSleepDidChange();
}

void TimerList::removeTimer(const std::shared_ptr<Timer> &timer)
{
	if(not timer)
		return;

	timer->setTimerList(nullptr);
	m_timers.erase(timer);
}

void TimerList::clear()
{
	m_timers.clear();
}

} } // namespace com::zenomt
