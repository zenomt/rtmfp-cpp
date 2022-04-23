#include <cassert>
#include <cstdio>
#include "rtmfp/Media.hpp"
#include "rtmfp/Hex.hpp"
#include "rtmfp/VLU.hpp"

using namespace com::zenomt::rtmfp;
using namespace com::zenomt;

static void check_message(const Media &media, const Bytes &message, bool isRAI, int messageType, Time dts, Time pts, Time slop, size_t optionListLen, size_t payloadLen)
{
	bool actualRAI = false;
	int actualMessageType = -1;
	Time actualDTS = -1;
	Time actualPTS = -1;
	size_t optionListOffset = 0;
	size_t rv;

	rv = media.parseHeader(message.data(), message.size(), &actualRAI, &actualMessageType, &actualDTS, &actualPTS, &optionListOffset);

	assert(rv);
	assert(actualRAI == isRAI);
	assert(actualMessageType == messageType);
	printf("actualDTS: %.8Lf expected: %.8Lf  actualPTS: %.8Lf expected: %.8Lf\n", actualDTS, dts, actualPTS, pts);
	assert(std::fabs(actualDTS - dts) <= slop);
	assert(std::fabs(actualPTS - pts) <= slop);

	size_t actualOptionListLen = rv - optionListOffset;
	assert(actualOptionListLen == optionListLen);

	assert(message.size() - rv == payloadLen);
}

int main(int argc, char **argv)
{
	Media m1;
	m1.streamID = 1;
	m1.codec = "avc1";

	Hex::print("m1", m1.toMetadata());

	auto m2 = Media::fromMetadata(m1.toMetadata());
	Hex::print("m2", m2->toMetadata());
	printf("m2 tick duration: %Lf\n", m2->getTickDuration());

	assert(1 == m2->streamID);
	assert(0 == m2->getOrigin());
	assert(0 == m2->codec.compare("avc1"));
	assert(0 == m2->mediaType.compare(""));
	assert(m2->getTickDuration() < 1./999.);
	assert(m2->getTickDuration() > 1./1001.);
	assert(m2->reorderSuggestion < 0);

	m2->setTimescale(90000, 1);
	m2->mediaType = "video";
	auto m3 = Media::fromMetadata(m2->toMetadata());
	printf("m3 tick duration %.8Lf should be %.8Lf\n", m3->getTickDuration(), Time(1.0/90000.0));
	Hex::print("m3", m3->toMetadata());
	assert(m3->getTickDuration() < 1./89999);
	assert(m3->getTickDuration() > 1./90001);
	assert(0 == m3->mediaType.compare("video"));

	m3->setOrigin(5000.5);
	auto m4 = Media::fromMetadata(m3->toMetadata());
	Hex::print("m4", m4->toMetadata());
	printf("m4 origin: %.8Lf should be %.8Lf\n", m4->getOrigin(), Time(5000.5));
	assert(m4->getOrigin() < 5000.5001);
	assert(m4->getOrigin() > 5000.4999);
	assert(RO_SEQUENCE == m4->getReceiveIntent());

	m4->trackName = "Front";
	m4->reorderSuggestion = 5.3;
	m4->setTrackID(13);
	m4->setReceiveIntent(RO_NETWORK);

	auto m5 = Media::fromMetadata(m4->toMetadata());
	auto m5md = m5->toMetadata();
	Hex::print("m5", m5md);
	printf("m5 trackName %s\n", m5->trackName.c_str());
	printf("m5 reorderSuggestion %.8Lf should be %.8Lf\n", m5->reorderSuggestion, Time(5.3));
	printf("m5 trackID %lu\n", (unsigned long)m5->getTrackID());
	printf("m5 receiveIntent: %s\n", m5->getReceiveIntent() == RO_NETWORK ? "RO_NETWORK" : "RO_SEQUENCE");
	assert(0 == m5->trackName.compare("Front"));
	assert(13 == m5->getTrackID());
	assert(m5->reorderSuggestion < 5.301);
	assert(m5->reorderSuggestion > 5.299);
	assert(RO_NETWORK == m5->getReceiveIntent());

	m5md.pop_back();
	assert(not Media::fromMetadata(m5md));

	// ---

	Bytes optionList;
	Option::append(16, optionList);
	Option::append(32, "hi", 2, optionList);
	Option::append(optionList);
	uint8_t payload_bytes[] = "payload";
	Bytes payload(payload_bytes, payload_bytes + sizeof(payload_bytes));

	Media m6;
	m6.setTimescale(90000, 1);

	auto message1 = m6.makeMessage(true, Media::MSG_MEDIA, 0, 0, payload);
	Hex::print("message1", message1);
	check_message(m6, message1, true, Media::MSG_MEDIA, 0, 0, 0.000001, 0, payload.size());

	auto message2 = m6.makeMessage(false, 3, 1, 1, optionList, payload);
	Hex::print("message2", message2);
	check_message(m6, message2, false, 3, 1, 1, 0.000001, optionList.size(), payload.size());

	auto message3 = m6.makeMessage(false, 4, 2, 2.0333, payload);
	Hex::print("message3", message3);
	check_message(m6, message3, false, 4, 2, 2.0333, 0.001, 0, payload.size());

	m6.setOrigin(10.5);
	auto message4 = m6.makeMessage(false, 1, 11.5, 10.5, nullptr, 0);
	Hex::print("message4", message4);
	check_message(m6, message4, false, 1, 11.5, 10.5, 0.001, 0, 0);

	m6.setTimescale(1000, 1);
	auto message5 = m6.makeMessage(false, 1, 10.501, 10.503, Bytes());
	Hex::print("message5", message5);
	check_message(m6, message5, false, 1, 10.501, 10.503, 0.0005, 0, 0);

	m6.setOrigin(0);
	m6.setTimescale(128, 1);
	auto message6 = m6.makeMessage(false, 1, 1, 3.03, optionList, Bytes());
	Hex::print("message6", message6);
	check_message(m6, message6, false, 1, 1, 3.03, 1.5/256.0, optionList.size(), 0);

	optionList.pop_back(); // remove list terminator
	auto message7 = m6.makeMessage(false, 1, 1, 1, optionList, Bytes());
	Hex::print("bad message7", message7);
	assert(0 == m6.parseHeader(message7.data(), message7.size(), nullptr, nullptr, nullptr, nullptr, nullptr));

	auto message8 = m6.makeMessage(false, 1, 1, 2, nullptr, 0);
	message8.pop_back();
	Hex::print("bad message8", message8);
	assert(0 == m6.parseHeader(message8.data(), message8.size(), nullptr, nullptr, nullptr, nullptr, nullptr));

	message8.pop_back();
	Hex::print("worse message8", message8);
	assert(0 == m6.parseHeader(message8.data(), message8.size(), nullptr, nullptr, nullptr, nullptr, nullptr));

	auto message9 = m6.makeMessage(false, 1, 1, 1, nullptr, 0);
	message9.pop_back();
	Hex::print("bad message9", message9);
	assert(0 == m6.parseHeader(message9.data(), message9.size(), nullptr, nullptr, nullptr, nullptr, nullptr));

	uint8_t emptyOptions[] = { 0 };
	auto message10 = m6.makeMessage(false, 1, 1, 1, emptyOptions, sizeof(emptyOptions), nullptr, 0);
	message10.pop_back();
	Hex::print("bad message10 OPT but no options", message10);
	assert(0 == m6.parseHeader(message10.data(), message10.size(), nullptr, nullptr, nullptr, nullptr, nullptr));

	return 0;
}
