#pragma once

// Copyright © 2022 Michael Thornburgh
// SPDX-License-Identifier: MIT

// Consolidated include file for all available RunLoop implementations.
// Use the PreferredRunLoop alias for the RunLoop optimized for the target
// OS (currently EPollRunLoop for Linux or SelectRunLoop for all others).

#include "SelectRunLoop.hpp"
#include "EPollRunLoop.hpp"

namespace com { namespace zenomt {

#ifdef __linux__

using PreferredRunLoop = EPollRunLoop;

#else

using PreferredRunLoop = SelectRunLoop;

#endif

} } // namespace com::zenomt
