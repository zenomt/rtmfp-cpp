#pragma once

// Copyright © 2023 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "Timer.hpp"

namespace com { namespace zenomt {

class RateTracker : public Object {
public:
	RateTracker(Duration windowPeriod = 1.0);

	void update(size_t count, Time now);

	double getRate(Time now) const;

	void setWindowPeriod(Duration windowPeriod);
	Time getWindowPeriod() const;

	void reset();

protected:
	Duration m_windowPeriod;
	Time m_windowBegin;
	size_t m_count;
	double m_previousRate;
};

} } // namespace com::zenomt
