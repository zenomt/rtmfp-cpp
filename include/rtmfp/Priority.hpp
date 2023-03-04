#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

namespace com { namespace zenomt {

const int NUM_PRIORITIES = 8;
enum Priority {
	// Priorities 4 and higher are considered Time Critical. Currently implemented as precedence.
	PRI_0 = 0, PRI_1, PRI_2, PRI_3, PRI_4, PRI_5, PRI_6, PRI_7,

	PRI_LOWEST        = PRI_0,
	PRI_HIGHEST       = NUM_PRIORITIES - 1,

	PRI_BACKGROUND    = PRI_LOWEST,
	PRI_BULK          = PRI_1,
	PRI_DATA          = PRI_2,
	PRI_ROUTINE       = PRI_3,
	PRI_PRIORITY      = PRI_4,
	PRI_IMMEDIATE     = PRI_5,
	PRI_FLASH         = PRI_6,
	PRI_FLASHOVERRIDE = PRI_7
};

} } // namespace com::zenomt
