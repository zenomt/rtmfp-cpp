// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "../include/rtmfp/FlowSyncManager.hpp"

namespace com { namespace zenomt { namespace rtmfp {

using namespace com::zenomt::rtmp;

FlowSyncManager::Barrier::~Barrier()
{
	while(not m_flows.empty())
	{
		auto &each = m_flows.back();
		if(each and (RO_HOLD == each->getReceiveOrder()))
			each->setReceiveOrder(RO_SEQUENCE);
		m_flows.pop_back();
	}
}

FlowSyncManager::FlowSyncManager() : m_nextSyncID(0)
{
}

bool FlowSyncManager::sync(uint32_t syncID, size_t count, const std::shared_ptr<RecvFlow> &flow)
{
	auto &barrier = m_barriers[syncID];

	if(count <= barrier.m_flows.size() + 1)
	{
		reset(syncID);
		return true;
	}

	barrier.m_flows.push_back(flow);

	if(flow and (RO_SEQUENCE == flow->getReceiveOrder()))
		flow->setReceiveOrder(RO_HOLD); // don't hold RO_NETWORK

	return false;
}

void FlowSyncManager::reset(uint32_t syncID)
{
	m_barriers.erase(syncID);
}

Bytes FlowSyncManager::makeSyncMessage(size_t count)
{
	Bytes rv = TCMessage::message(TCMSG_USER_CONTROL, 0, nullptr, 0);

	rv.push_back((TC_USERCONTROL_FLOW_SYNC >> 8) & 0xff);
	rv.push_back((TC_USERCONTROL_FLOW_SYNC     ) & 0xff);

	rv.push_back((m_nextSyncID >> 24) & 0xff);
	rv.push_back((m_nextSyncID >> 16) & 0xff);
	rv.push_back((m_nextSyncID >>  8) & 0xff);
	rv.push_back((m_nextSyncID      ) & 0xff);

	rv.push_back((count >> 24) & 0xff);
	rv.push_back((count >> 16) & 0xff);
	rv.push_back((count >>  8) & 0xff);
	rv.push_back((count      ) & 0xff);

	m_nextSyncID++;

	return rv;
}

size_t FlowSyncManager::parse(const uint8_t *tcmessage, size_t len, uint32_t &syncID, size_t &count)
{
	if( (len < 15)
	 or (TCMSG_USER_CONTROL != tcmessage[0])
	 or (((TC_USERCONTROL_FLOW_SYNC >> 8) & 0xff) != tcmessage[5])
	 or (((TC_USERCONTROL_FLOW_SYNC     ) & 0xff) != tcmessage[6])
	)
		return 0;

	const uint8_t *limit = tcmessage + len;
	size_t rv = parseUserCommandPayload(tcmessage + 7, limit, syncID, count);
	return rv ? 7 + rv : 0;
}

size_t FlowSyncManager::parseUserCommandPayload(const uint8_t *payload, const uint8_t *limit, uint32_t &syncID, size_t &count)
{
	if((limit - payload) < 8)
		return 0;

	syncID = (payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3];
	count = (payload[4] << 24) | (payload[5] << 16) | (payload[6] << 8) | payload[7];

	return 8;
}

} } } // namespace com::zenomt::rtmfp
