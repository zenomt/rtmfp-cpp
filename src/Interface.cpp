// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "Interface.hpp"
#include "Session.hpp"

namespace com { namespace zenomt { namespace rtmfp {

Interface::Interface(int interfaceID, RTMFP *rtmfp) :
	m_writeScheduled(false),
	m_id(interfaceID),
	m_rtmfp(rtmfp)
{
}

bool Interface::onWritable()
{
	for(int pri = PRI_HIGHEST; pri >= PRI_LOWEST; pri--)
	{
		long name;
		auto &q = m_sessions[pri];

		while((name = q.first()))
		{
			if(q.at(name)->onInterfaceWritable(m_id, pri))
			{
				q.moveNameToTail(name);
				return true;
			}

			q.remove(name);
		}
	}

	m_writeScheduled = false;
	return false;
}

void Interface::scheduleWrite(std::shared_ptr<ISession> isession, int pri)
{
	auto &q = m_sessions[pri];

	if(not q.find(isession))
	{
		q.append(isession);

		if(not m_writeScheduled)
		{
			m_writeScheduled = true;
			m_rtmfp->m_platform->notifyWhenInterfaceWritable(m_id, [this] { return this->onWritable(); });
		}
	}
}

} } } // namespace com::zenomt::rtmfp
