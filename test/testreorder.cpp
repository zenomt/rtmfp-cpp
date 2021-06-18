#include <cassert>
#include <cstdio>

#include "rtmfp/SelectRunLoop.hpp"
#include "rtmfp/ReorderBuffer.hpp"

using namespace com::zenomt;
using namespace com::zenomt::rtmfp;

int main(int argc, char **argv)
{
	SelectRunLoop rl;
	size_t lateCount = 0;
	size_t receivedCount = 0;

	RunLoopReorderBuffer reorder(&rl, 1);
	reorder.onMessage = [&] (const uint8_t *bytes, size_t len, uintmax_t sequenceNumber, size_t fragmentCount, bool isLate) {
		uintmax_t highest = sequenceNumber + fragmentCount - 1;
		printf("onMessage %lu to %lu%s at %f\n", (unsigned long)sequenceNumber, (unsigned long)highest, isLate ? " late" : "", (double)rl.getCurrentTime());
		if(isLate)
			lateCount++;
		receivedCount++;
	};

	uint8_t msg[] = "hi there";

	reorder.insert(msg, sizeof(msg), 4, 2);
	reorder.insert(msg, sizeof(msg), 3, 1);
	assert(0 == receivedCount);

	reorder.insert(msg, sizeof(msg), 1, 2);
	assert(3 == receivedCount);

	reorder.insert(msg, sizeof(msg), 6, 1);
	assert(4 == receivedCount);

	reorder.insert(msg, sizeof(msg), 10, 1);
	reorder.insert(msg, sizeof(msg), 8, 2);
	assert(4 == receivedCount);
	assert(0 == lateCount);

	rl.schedule(0.5)->action = [&] (const std::shared_ptr<Timer> &sender, Time now) {
		reorder.insert(msg, sizeof(msg), 12, 1);
		reorder.insert(msg, sizeof(msg), 14, 1);
	};

	rl.schedule(0.7)->action = [&] (const std::shared_ptr<Timer> &sender, Time now) {
		reorder.insert(msg, sizeof(msg), 15, 1); // should be delivered with 12 & 14
	};

	rl.schedule(1.1)->action = [&] (const std::shared_ptr<Timer> &sender, Time now) {
		assert(6 == receivedCount);
		assert(0 == lateCount);
		reorder.insert(msg, sizeof(msg), 7, 1);
		assert(7 == receivedCount);
		assert(1 == lateCount);
	};

	rl.schedule(1.6)->action = [&] (const std::shared_ptr<Timer> &sender, Time now) {
		assert(10 == receivedCount);
		assert(1 == lateCount);
	};

	rl.schedule(1.8)->action = [&] (const std::shared_ptr<Timer> &sender, Time now) {
		reorder.insert(msg, sizeof(msg), 18, 1);
	};

	rl.run(2);

	assert(10 == receivedCount);
	reorder.flush();
	assert(11 == receivedCount);
	assert(1 == lateCount);

	return 0;
}
