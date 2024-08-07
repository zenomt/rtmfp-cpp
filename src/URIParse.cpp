// Copyright © 2022 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cctype>
#include <cstring>

#include <regex>

#include "../include/rtmfp/Hex.hpp"
#include "../include/rtmfp/URIParse.hpp"

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
	std::regex_match(hostinfo, hostparts, std::regex("^((\\[([^\\]]*)?\\]))?([^:]*)?(:([0-9]+))?"));
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

std::string URIParse::transformRelativeReference(const std::string &relativeUri) const
{
	URIParse rel(relativeUri);
	std::string targetSchemePart;
	std::string targetAuthorityPart;
	std::string targetPath;
	std::string targetQueryPart;

	if(not rel.schemePart.empty())
	{
		targetSchemePart = rel.schemePart;
		targetAuthorityPart = rel.authorityPart;
		targetPath = removeDotSegments(rel.path);
		targetQueryPart = rel.queryPart;
	}
	else
	{
		targetSchemePart = schemePart;
		if(not rel.authorityPart.empty())
		{
			targetAuthorityPart = rel.authorityPart;
			targetPath = removeDotSegments(rel.path);
			targetQueryPart = rel.queryPart;
		}
		else
		{
			targetAuthorityPart = authorityPart;
			if(rel.path.empty())
			{
				targetPath = path;
				targetQueryPart = rel.queryPart.empty() ? queryPart : rel.queryPart;
			}
			else
			{
				targetQueryPart = rel.queryPart;
				if('/' == rel.path[0])
					targetPath = removeDotSegments(rel.path);
				else
					targetPath = removeDotSegments(mergedRelativePath(rel.path));
			}
		}
	}

	return targetSchemePart + targetAuthorityPart + targetPath + targetQueryPart + rel.fragmentPart;
}

std::string URIParse::mergedRelativePath(const std::string &relativePath) const
{
	if(relativePath.empty() or (relativePath[0] == '/'))
		return relativePath;

	if((not authorityPart.empty()) and path.empty())
		return std::string("/") + relativePath;

	size_t lastSlash = path.rfind('/');
	if(std::string::npos == lastSlash)
		lastSlash = 0;
	else
		lastSlash++;

	return path.substr(0, lastSlash) + relativePath;
}

std::string URIParse::removeDotSegments(const std::string &path_)
{
	// a transliteration of RFC 3986 §5.2.4, not the most efficient way to do this

	std::string inputBuffer(path_);
	std::vector<std::string> outputBuffer;

	while(not inputBuffer.empty())
	{
		if(0 == strncmp("../", inputBuffer.c_str(), 3))
			inputBuffer.erase(0, 3);
		else if(0 == strncmp("./", inputBuffer.c_str(), 2))
			inputBuffer.erase(0, 2);
		else if((0 == strncmp("/./", inputBuffer.c_str(), 3)) or (inputBuffer == "/."))
			inputBuffer.replace(0, 3, "/");
		else if((0 == strncmp("/../", inputBuffer.c_str(), 4)) or (inputBuffer == "/.."))
		{
			inputBuffer.replace(0, 4, "/");
			if(not outputBuffer.empty())
				outputBuffer.pop_back();
		}
		else if((inputBuffer == "..") or (inputBuffer == "."))
			inputBuffer.clear();
		else
		{
			size_t rpos = inputBuffer.find('/', 1);
			outputBuffer.push_back(inputBuffer.substr(0, rpos));
			inputBuffer.erase(0, rpos);
		}
	}

	std::string rv;
	rv.reserve(path_.size());
	for(auto it = outputBuffer.begin(); it != outputBuffer.end(); it++)
		rv += *it;

	return rv;
}

std::vector<std::string> URIParse::split(const std::string &str, char sep, size_t maxParts)
{
	return split(str, std::string(1, sep), maxParts);
}

std::vector<std::string> URIParse::split(const std::string &str, const std::string &seps, size_t maxParts)
{
	if(seps.empty())
		return {};

	std::vector<std::string> rv;

	size_t cursor = 0;
	while((--maxParts) and (cursor < str.size()))
	{
		size_t found = str.find_first_of(seps, cursor);
		if(std::string::npos == found)
			break;

		rv.push_back(str.substr(cursor, found - cursor));
		cursor = found + 1;
	}

	if(cursor <= str.size())
		rv.push_back(str.substr(cursor));

	return rv;
}

std::string URIParse::percentDecode(const std::string &str)
{
	std::string rv;
	rv.reserve(str.size());

	int ch;
	const char *cursor = str.data();
	while((ch = *cursor++))
	{
		if('%' == ch)
		{
			int b = Hex::decodeByte(cursor);
			if(b < 1) // reject errors and NUL in strings
				return "";
			rv.push_back(uint8_t(b));
			cursor += 2;
		}
		else
			rv.push_back(ch);
	}

	return rv;
}

std::string URIParse::safePercentDecode(const std::string &str)
{
	std::string rv = percentDecode(str);
	return rv.empty() ? str : rv;
}

std::string URIParse::lowercase(const std::string &s)
{
	std::string rv;
	for(auto it = s.begin(); it != s.end(); it++)
		rv.push_back(::tolower(*it)); // OK for URIs, but not IRIs
	return rv;
}

} } // namespace com::zenomt
