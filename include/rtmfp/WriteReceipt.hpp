#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "List.hpp"
#include "Timer.hpp"

namespace com { namespace zenomt {

class WriteReceipt : public Object {
public:
	WriteReceipt(Time origin, Time startWithin, Time finishWithin);

	void abandon(); // Abandon the message if not finished already.

	void abandonIfNeeded(Time now); // Abandon the message if now is past deadline.

	// The (platform) times by which transmission of this message must be started,
	// and by which delivery of it must finish, to not be automatically abandoned.
	Time startBy;
	Time finishBy;

	// Whether any fragment of this message should be retransmitted
	// if it is lost. Default true. Set to false for "best effort"
	// delivery, where each fragment will be sent at most once.
	bool retransmit;

	// If set, this message will be abandoned if the parent is abandoned. Useful for
	// chaining dependent messages together (such as a predictive-coded video frame that
	// can't be decoded if the previous one is not received).
	std::shared_ptr<WriteReceipt> parent;

	void setStartWithin(Time age); // Set startBy to createdAt() + age.
	void setFinishWithin(Time age); // Set finishBy to createdAt() + age.

	Time createdAt()   const; // The time at which this message was queued.
	bool isAbandoned() const; // True if this message was abandoned before finishing.
	bool isStarted()   const; // True if any part of this message has been transmitted at least once.
	bool isDelivered() const; // True if the entire message was successfully sent to the far end.
	bool isFinished()  const; // True if the message was delivered or abandoned.

	std::function<void(bool wasAbandoned)> onFinished;

protected:
	WriteReceipt() = delete;

	Time   m_origin;
	bool   m_started;
	bool   m_abandoned;
	size_t m_useCount;
};

class IssuerWriteReceipt : public WriteReceipt {
public:
	using WriteReceipt::WriteReceipt;

	void useCountUp();
	void useCountDown();
	void start();
};

class WriteReceiptChain : public Object {
public:
	// Helper for the common pattern of chaining together a sequence of writes where
	// each message depends on the previous (for example, an AVC Group of Pictures).

	// Set receipt's parent to the previously chained receipt, if any, and append to the chain.
	void append(std::shared_ptr<WriteReceipt> receipt);

	// Update each chained receipt to startBy/finishBy the earlier of deadline or its current
	// values, then clear the chain. A deadline of INFINITY clears the chain but doesn't
	// change any startBy or finishBy times.
	void expire(Time deadline);

protected:
	List<std::shared_ptr<WriteReceipt>> m_receipts;
};

} } // namespace com::zenomt
