// Copyright © 2022 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cctype>
#include <regex>

#include "../include/rtmfp/URIParse.hpp"

static std::string lowercase(const std::string &s)
{
	std::string rv;
	for(auto it = s.begin(); it != s.end(); it++)
		rv.push_back(::tolower(*it)); // OK for URIs, but not IRIs
	return rv;
}

namespace com { namespace zenomt {

URIParse::URIParse(const std::string &uri_)
{
	parse(uri_);
}

void URIParse::parse(const std::string &uri_)
{
	uri = uri_;

	std::smatch parts;
	std::regex_match(uri_, parts, std::regex("^(([a-zA-Z][^:/?#]*):)?([^?#]*)?(\\?([^#]*))?(#(.*))?"));
	schemePart = parts[1];
	scheme = parts[2];
	canonicalScheme = lowercase(scheme);
	hierpart = parts[3];
	queryPart = parts[4];
	query = parts[5];
	fragmentPart = parts[6];
	fragment = parts[7];

	std::smatch hierparts;
	std::regex_match(hierpart, hierparts, std::regex("^(//([^/]*))?(.*)"));
	authorityPart = hierparts[1];
	authority = hierparts[2];
	path = hierparts[3];

	std::smatch authparts;
	std::regex_match(authority, authparts, std::regex("^((([^:@]*)(:([^@]*))?)@)?(.*)"));
	userinfoPart = authparts[1];
	userinfo = authparts[2];
	user = authparts[3];
	passwordPart = authparts[4];
	password = authparts[5];
	hostinfo = authparts[6];

	std::smatch hostparts;
	std::regex_match(hostinfo, hostparts, std::regex("^((\\[([0-9a-fA-Fv:.]*)?\\]))?([^:]*)?(:([0-9]+))?"));
	host = std::string(hostparts[3]).empty() ? hostparts[4] : hostparts[3];
	port = hostparts[6];
	effectivePort = port;

	if((not scheme.empty()) and not hostinfo.empty())
		origin = scheme + "://" + hostinfo;
	else
		origin = "";

	if(effectivePort.empty() and not hostinfo.empty())
	{
		if((canonicalScheme == "http") or (canonicalScheme == "ws"))
			effectivePort = "80";
		else if((canonicalScheme == "https") or (canonicalScheme == "wss") or (canonicalScheme == "rtmps"))
			effectivePort = "443";
		else if((canonicalScheme == "rtmfp") or (canonicalScheme == "rtmp"))
			effectivePort = "1935";
	}

	publicUri = schemePart + (authorityPart.empty() ? std::string("") : std::string("//") + hostinfo) + path + queryPart;
}

} } // namespace com::zenomt
