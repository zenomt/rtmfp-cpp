#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

// This module provides helpers for Flow Synchronization as described in
// RFC 7425 §5.2.

#include "TCMessage.hpp"

namespace com { namespace zenomt { namespace rtmfp {

class FlowSyncManager : public Object {
public:
	FlowSyncManager();

	// synchronize flow on barrier syncID of count flows.
	// answer true if all flows are synced and resumed, false if sync is still pending
	bool sync(uint32_t syncID, size_t count, const std::shared_ptr<RecvFlow> &flow);

	// resume any flows holding on syncID.
	void reset(uint32_t syncID);

	// answer a Flow Synchronization User Control TC message (type 4, eventType 34, timestamp 0).
	Bytes makeSyncMessage(size_t count);

	static Bytes makeSyncMessage(uint32_t syncID, size_t count);

	// answer the number of bytes parsed if this is a Flow Synchronization message (15),
	// or 0 if it is not. tcmessage points to the beginning of a full TC message (including type
	// and timestamp).
	static size_t parse(const uint8_t *tcmessage, size_t len, uint32_t &syncID, size_t &count);

	// extract the syncID and count from the payload of a Flow Sync User Control event.
	// payload points to the first byte after the eventType field. answer 0 if there aren't
	// enough bytes, or the number of bytes parsed for the fields (8).
	static size_t parseUserCommandPayload(const uint8_t *payload, const uint8_t *limit, uint32_t &syncID, size_t &count);

protected:
	struct Barrier {
		~Barrier();
		std::vector<std::shared_ptr<RecvFlow>> m_flows;
	};

	uint32_t m_nextSyncID;
	std::map<uint32_t, Barrier> m_barriers;
};

} } } // namespace com::zenomt::rtmfp
