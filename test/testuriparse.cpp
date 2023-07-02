#include <cassert>
#include <cstdio>

#include "../include/rtmfp/URIParse.hpp"

using namespace com::zenomt;

static void printUri(const char *msg, const com::zenomt::URIParse &p)
{
	if(msg)
		printf("%s\n", msg);

	printf("uri: %s\n", p.uri.c_str());
	printf("publicUri: %s\n", p.publicUri.c_str());
	printf("schemePart: %s\n", p.schemePart.c_str());
	printf("scheme: %s\n", p.scheme.c_str());
	printf("canonicalScheme: %s\n", p.canonicalScheme.c_str());
	printf("hierpart: %s\n", p.hierpart.c_str());
	printf("queryPart: %s\n", p.queryPart.c_str());
	printf("query: %s\n", p.query.c_str());
	printf("fragmentPart: %s\n", p.fragmentPart.c_str());
	printf("fragment: %s\n", p.fragment.c_str());
	printf("  secondaryPath: %s\n", p.secondaryPath.c_str());
	printf("  secondaryParamsPart: %s\n", p.secondaryParamsPart.c_str());
	printf("  secondaryParams: %s\n", p.secondaryParams.c_str());
	printf("authorityPart: %s\n", p.authorityPart.c_str());
	printf("authority: %s\n", p.authority.c_str());
	printf("path: %s\n", p.path.c_str());
	printf("userinfoPart: %s\n", p.userinfoPart.c_str());
	printf("userinfo: %s\n", p.userinfo.c_str());
	printf("  user: %s\n", p.user.c_str());
	printf("  passwordPart: %s\n", p.passwordPart.c_str());
	printf("  password: %s\n", p.password.c_str());
	printf("hostinfo: %s\n", p.hostinfo.c_str());
	printf("host: %s\n", p.host.c_str());
	printf("port: %s\n", p.port.c_str());
	printf("effectivePort: %s\n", p.effectivePort.c_str());
	printf("origin: %s\n", p.origin.c_str());
	printf("\n");
}

static void checkRel(const com::zenomt::URIParse &baseUri, const char *rel, const char *expected)
{
	std::string target = baseUri.transformRelativeReference(rel);
	printf("base: %s rel: %s target: %s expected: %s\n", baseUri.uri.c_str(), rel, target.c_str(), expected);
	assert(target == expected);
}

int main(int argc, char *argv[])
{
	if(argc > 1)
	{
		URIParse baseUri(argv[1]);
		printUri("baseUri", baseUri);

		for(int x = 2; x < argc; x++)
			printUri(argv[x], URIParse(baseUri.transformRelativeReference(argv[x])));

		return 0;
	}

	URIParse u0;
	printUri("u0 empty", u0);
	assert(u0.uri.empty());
	u0.parse("rtmfp:");
	printUri("u0", u0);
	assert(not u0.uri.empty());
	assert(not u0.publicUri.empty());
	assert(not u0.schemePart.empty());
	assert(not u0.scheme.empty());

	URIParse u1("rtmfp");
	printUri("u1", u1);
	assert(u1.scheme.empty());
	assert(u1.hierpart == "rtmfp");
	assert(u1.authority.empty());
	assert(u1.path == "rtmfp");

	URIParse u2("RTMFP:");
	printUri("u2", u2);
	assert(u2.scheme == "RTMFP");
	assert(u2.canonicalScheme == "rtmfp");
	assert(u2.hierpart.empty());
	assert(u2.effectivePort.empty());

	URIParse u3("//foo/bar");
	printUri("u3", u3);
	assert(u3.scheme.empty());
	assert(u3.hierpart == "//foo/bar");
	assert(u3.authority == "foo");
	assert(u3.path == "/bar");
	assert(u3.host == "foo");

	URIParse u4("/foo/bar");
	printUri("u4", u4);
	assert(u4.path == "/foo/bar");
	assert(u4.hostinfo.empty());

	URIParse u5("rtmfp://foo");
	printUri("u5", u5);
	assert(u5.host == "foo");
	assert(u5.port.empty());
	assert(u5.effectivePort == "1935");
	assert(u5.userinfo.empty());

	URIParse u6("rtmfp://user:pw@foo:1936");
	printUri("u6", u6);
	assert(u6.userinfo == "user:pw");
	assert(u6.user == "user");
	assert(u6.passwordPart == ":pw");
	assert(u6.password == "pw");
	assert(u6.host == "foo");
	assert(u6.port == "1936");
	assert(u6.effectivePort == "1936");
	assert(u6.origin == "rtmfp://foo:1936");

	URIParse u7("rtmfp://[2001:db8::1]:1234/foo?bar#baz");
	printUri("u7", u7);
	assert(u7.query == "bar");
	assert(u7.fragment == "baz");
	assert(u7.hostinfo == "[2001:db8::1]:1234");
	assert(u7.host == "2001:db8::1");
	assert(u7.port == "1234");
	assert(u7.origin == "rtmfp://[2001:db8::1]:1234");

	URIParse u8("rtmfp://198.51.100.33:5678/foo");
	printUri("u8", u8);
	assert(u8.host == "198.51.100.33");
	assert(u8.port == "5678");
	assert(u8.path == "/foo");

	URIParse u9("rtmp://foo");
	assert(u9.effectivePort == "1935");

	URIParse u10("https://foo");
	assert(u10.effectivePort == "443");

	URIParse u11("wss://foo");
	assert(u11.effectivePort == "443");

	URIParse u12("http://foo");
	assert(u12.effectivePort == "80");

	URIParse u13("ws://foo");
	assert(u13.effectivePort == "80");

	URIParse u14("rtmfp://user:pw@[2001:db8::2]:4567/foo?bar#baz");
	printUri("u14", u14);
	assert(u14.query == "bar");
	assert(u14.fragment == "baz");
	assert(u14.secondaryPath == "baz");
	assert(u14.secondaryParamsPart.empty());
	assert(u14.secondaryParams.empty());
	assert(u14.path == "/foo");
	assert(u14.userinfo == "user:pw");
	assert(u14.passwordPart == ":pw");
	assert(u14.host == "2001:db8::2");
	assert(u14.port == "4567");
	assert(u14.effectivePort == "4567");
	assert(u14.origin == "rtmfp://[2001:db8::2]:4567");

	URIParse u15("rtmfp:///bar?#");
	printUri("u15", u15);
	assert(not u15.authorityPart.empty());
	assert(u15.authority.empty());
	assert(not u15.queryPart.empty());
	assert(u15.query.empty());
	assert(not u15.fragmentPart.empty());
	assert(u15.fragment.empty());
	assert(u15.secondaryParamsPart.empty());
	assert(u15.secondaryParams.empty());
	assert(u15.secondaryPath.empty());

	URIParse u16("6://foo/bar/baz");
	printUri("u16", u16);
	assert(u16.schemePart.empty());
	assert(u16.hostinfo.empty());
	assert(u16.path == u16.uri);

	URIParse u17("rtmfp://[2001:db8::10.0.1.2]:1234");
	printUri("u17", u17);
	assert(u17.host == "2001:db8::10.0.1.2");
	assert(u17.port == "1234");
	assert(u17.hostinfo == "[2001:db8::10.0.1.2]:1234");

	URIParse u18("rtmp://host.example/foo?bar#fragment?fragmentQuery?more");
	printUri("u18", u18);
	assert(u18.fragment == "fragment?fragmentQuery?more");
	assert(u18.secondaryPath == "fragment");
	assert(u18.secondaryParamsPart == "?fragmentQuery?more");
	assert(u18.secondaryParams == "fragmentQuery?more");

	// test cases from RFC 3986 §5.4.1
	URIParse baseUri("http://a/b/c/d;p?q");
	checkRel(baseUri, "g:h",        "g:h");
	checkRel(baseUri, "g",          "http://a/b/c/g");
	checkRel(baseUri, "./g",        "http://a/b/c/g");
	checkRel(baseUri, "g/",         "http://a/b/c/g/");
	checkRel(baseUri, "/g",         "http://a/g");
	checkRel(baseUri, "//g",        "http://g");
	checkRel(baseUri, "?y",         "http://a/b/c/d;p?y");
	checkRel(baseUri, "g?y",        "http://a/b/c/g?y");
	checkRel(baseUri, "#s",         "http://a/b/c/d;p?q#s");
	checkRel(baseUri, "g#s",        "http://a/b/c/g#s");
	checkRel(baseUri, "g?y#s",      "http://a/b/c/g?y#s");
	checkRel(baseUri, ";x",         "http://a/b/c/;x");
	checkRel(baseUri, "g;x",        "http://a/b/c/g;x");
	checkRel(baseUri, "g;x?y#s",    "http://a/b/c/g;x?y#s");
	checkRel(baseUri, "",           "http://a/b/c/d;p?q");
	checkRel(baseUri, ".",          "http://a/b/c/");
	checkRel(baseUri, "./",         "http://a/b/c/");
	checkRel(baseUri, "..",         "http://a/b/");
	checkRel(baseUri, "../",        "http://a/b/");
	checkRel(baseUri, "../g",       "http://a/b/g");
	checkRel(baseUri, "../..",      "http://a/");
	checkRel(baseUri, "../../",     "http://a/");
	checkRel(baseUri, "../../g",    "http://a/g");

	// test cases from RFC 3986 §5.4.2
	checkRel(baseUri, "../../../g", "http://a/g");
	checkRel(baseUri, "../../../../g", "http://a/g");
	checkRel(baseUri, "/./g",       "http://a/g");
	checkRel(baseUri, "/../g",      "http://a/g");
	checkRel(baseUri, "g.",         "http://a/b/c/g.");
	checkRel(baseUri, ".g",         "http://a/b/c/.g");
	checkRel(baseUri, "g..",        "http://a/b/c/g..");
	checkRel(baseUri, "..g",        "http://a/b/c/..g");
	checkRel(baseUri, "./../g",     "http://a/b/g");
	checkRel(baseUri, "./g/.",      "http://a/b/c/g/");
	checkRel(baseUri, "g/./h",      "http://a/b/c/g/h");
	checkRel(baseUri, "g/../h",     "http://a/b/c/h");
	checkRel(baseUri, "g;x=1/./y",  "http://a/b/c/g;x=1/y");
	checkRel(baseUri, "g;x=1/../y", "http://a/b/c/y");
	checkRel(baseUri, "g?y/./x",    "http://a/b/c/g?y/./x");
	checkRel(baseUri, "g?y/../x",   "http://a/b/c/g?y/../x");
	checkRel(baseUri, "g#s/./x",    "http://a/b/c/g#s/./x");
	checkRel(baseUri, "g#s/../x",   "http://a/b/c/g#s/../x");
	checkRel(baseUri, "http:g",     "http:g"); // we're strict

	return 0;
}
