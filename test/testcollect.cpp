#include <cassert>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>

#include "rtmfp/Algorithm.hpp"
#include "rtmfp/AMF.hpp"

using namespace com::zenomt;
using namespace com::zenomt::rtmp;

int main(int, char **)
{
	std::set<std::string> vals { "hi", "there", "jack" };

	auto result = collect<std::shared_ptr<AMF0>>(AMF0::String, collect<std::string>([] (const std::string &v) { return v; }, vals));

	assert(result.size() == 3);

	assert(0 == strcmp("hi", result[0]->stringValue()));
	assert(0 == strcmp("jack", result[1]->stringValue()));
	assert(0 == strcmp("there", result[2]->stringValue()));
	// sets are ordered, so the inner iteration should result in ["hi", "jack", "there"]

	return 0;
}
