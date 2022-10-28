#pragma once

// Copyright © 2022 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <string>

namespace com { namespace zenomt {

struct URIParse {
	URIParse(const std::string &uri_);

	URIParse() = default;
	void parse(const std::string &uri_);

	std::string uri;
	std::string publicUri;
	std::string schemePart;
	std::string scheme;
	std::string canonicalScheme;
	std::string hierpart;
	std::string queryPart;
	std::string query;
	std::string fragmentPart;
	std::string fragment;
	std::string authorityPart;
	std::string authority;
	std::string path;
	std::string userinfoPart;
	std::string userinfo;
	std::string hostinfo;
	std::string host;
	std::string port;
	std::string effectivePort;
	std::string origin;
};

} } // namespace com::zenomt
