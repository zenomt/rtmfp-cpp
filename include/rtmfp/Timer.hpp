#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <set>

#include "Object.hpp"

// inspired by MObjTimer & MObjTimerList from amicima

namespace com { namespace zenomt {

class TimerList;
using Time = long double;

class Timer : public Object {
public:
	const Time MIN_RECUR_INTERVAL = 0.000001; // 1 µs, esp important for catchup=false

	Timer(Time when, Time recurInterval, bool catchup);
	Timer() = delete;

	using Action = std::function<void(const std::shared_ptr<Timer> &sender, Time now)>;
	Action action;

	bool isDue(Time now) const;
	Time getNextFireTime() const;
	void setNextFireTime(Time when);

	Time getRecurInterval() const;
	void setRecurInterval(Time interval);
	bool doesRecur() const;

	void cancel();
	bool isCanceled() const;

	static Action makeAction(const std::function<void(Time now)> &fn);
	static Action makeAction(const Task &fn);

	bool operator< (const Timer &rhs) const;

protected:
	friend class TimerList;

	void         setTimerList(TimerList *timerList);
	TimerList   *getTimerList() const;
	static void  fire(const std::shared_ptr<Timer> &timer, Time now);
	void         basicFire(const std::shared_ptr<Timer> &myself, Time now);

	Time       m_when;
	Time       m_recurInterval;
	TimerList *m_timerList;
	bool       m_canceled    :1;
	bool       m_rescheduled :1; // to override recurInterval
	bool       m_catchup     :1;
	bool       m_firing      :1;
};

class TimerList : public Object {
public:
	TimerList();
	~TimerList();

	std::shared_ptr<Timer> schedule(Time when, Time recurInterval = 0, bool catchup = true);
	std::shared_ptr<Timer> schedule(const Timer::Action &action, Time when, Time recurInterval = 0, bool catchup = true);

	Time howLongToNextFire(Time now, Time maxInterval = 5) const;

	size_t fireDueTimers(Time now); // answer number of timers fired

	void addTimer(const std::shared_ptr<Timer> &timer);
	void removeTimer(const std::shared_ptr<Timer> &timer);

	void clear();

	Task onHowLongToSleepDidChange;

protected:
	bool m_running;
	std::set<std::shared_ptr<Timer>, deref_less<std::shared_ptr<Timer> > > m_timers;
};

} } // namespace com::zenomt
