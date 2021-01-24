#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "Session.hpp"
#include "../include/rtmfp/List.hpp"

namespace com { namespace zenomt { namespace rtmfp {

class Interface : public Object {
public:
	void scheduleWrite(std::shared_ptr<ISession> isession, int pri);

protected:
	friend class RTMFP;
	Interface(int interfaceID, RTMFP *rtmfp);
	Interface() = delete;

	bool onWritable();

	bool   m_writeScheduled;
	int    m_id;
	RTMFP *m_rtmfp; // weak back pointer
	List<std::shared_ptr<ISession> > m_sessions[NUM_PRIORITIES];
};


} } } // namespace com::zenomt::rtmfp
