#pragma once

// Copyright © 2022 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <string>

namespace com { namespace zenomt {

struct URIParse {
	URIParse(const std::string &uri_);

	URIParse() = default;
	void parse(const std::string &uri_);

	// RFC 3986 §5.2.1
	std::string transformRelativeReference(const std::string &relativeUri) const;

	// RFC 3986 §5.2.3
	std::string mergedRelativePath(const std::string &relativePath) const;

	// RFC 3986 §5.2.4
	static std::string removeDotSegments(const std::string &path);

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
	std::string user;
	std::string passwordPart;
	std::string password;
	std::string hostinfo;
	std::string host;
	std::string port;
	std::string effectivePort;
	std::string origin;

	// subdivide the fragment (ABNF):
	// secondary-path = *( pchar / "/" )
	// secondary-params = *( pchar / "/" / "?" )
	// secondary-params-part = "?" secondary-params
	// fragment-subdivided = secondary-path [ secondary-params-part ]
	std::string secondaryPath;
	std::string secondaryParamsPart;
	std::string secondaryParams;
};

} } // namespace com::zenomt
