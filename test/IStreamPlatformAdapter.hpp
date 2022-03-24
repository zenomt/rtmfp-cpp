#pragma once

// Copyright © 2022 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "../include/rtmfp/Timer.hpp"

namespace com { namespace zenomt {

class IStreamPlatformAdapter {
public:
	virtual ~IStreamPlatformAdapter() {}

	virtual Time getCurrentTime() = 0;

	// callback will be called while stream is writable until callback returns false.
	using onwritable_f = std::function<bool(void)>;
	virtual void notifyWhenWritable(const onwritable_f &onwritable) = 0;

	// callback will be called when there is new data until callback returns false.
	using onreceivebytes_f = std::function<bool(const void *bytes, size_t len)>;
	virtual void setOnReceiveBytesCallback(const onreceivebytes_f &onreceivebytes) = 0;

	virtual void setOnStreamDidCloseCallback(const Task &onstreamdidclose) = 0;

	// perform a task "later", as long as onClosed() was not called, or
	// as long as the platform otherwise knows the RTMP is still operating.
	virtual void doLater(const Task &task) = 0;

	// only called (and at most once) from onwritable(). answer true on success,
	// false on failure (like no longer open). implementation MUST support receiving
	// (and if necessary buffering) any length of write.
	virtual bool writeBytes(const void *bytes, size_t len) = 0;

	// Called when the protocol has concluded and has no more data to send, including
	// on error or flush of all messages.
	virtual void onClientClosed() = 0;
};

} } // namespace com::zenomt
