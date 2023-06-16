#include "rtmfp/RateTracker.hpp"

#include <cstdio>
#include <cassert>
#include <cmath>

using namespace com::zenomt;

static void testRate(const RateTracker &tracker, Time t, double expected, double slop = 0.01)
{
	printf("rate at %Lf: %f expected %f\n", t, tracker.getRate(t), expected);
	assert(std::fabs(tracker.getRate(t) - expected) <= slop);
}

int main(int argc, char **argv)
{
	RateTracker tracker;

	tracker.update(1, 0);
	tracker.update(1, 0);
	tracker.update(1, 0);

	testRate(tracker, 0.0, 3);
	testRate(tracker, 0.5, 3);
	testRate(tracker, 0.9999, 3);

	testRate(tracker, 1.5, 1.5);
	testRate(tracker, 1.66666666, 1.0);
	testRate(tracker, 2, 0);

	tracker.update(1, 1);
	testRate(tracker, 1.5, 2.5);

	tracker.update(1, 1.5);
	tracker.update(1, 1.9);
	testRate(tracker, 1.99999, 3);
	testRate(tracker, 2, 3);
	testRate(tracker, 2.5, 1.5);
	testRate(tracker, 3, 0);

	tracker.reset();
	testRate(tracker, 2, 0);

	tracker.update(1, 0);
	tracker.update(1, 1);
	tracker.update(1, 2);
	testRate(tracker, 2, 2);
	testRate(tracker, 2.25, 1.75);
	testRate(tracker, 2.5, 1.5);
	testRate(tracker, 3, 1);
	testRate(tracker, 3.5, 0.5);
	testRate(tracker, 4, 0);

	tracker.reset();

	tracker.update(1, 0);
	tracker.update(1, 1.5);
	testRate(tracker, 1.5, 1.5);
	testRate(tracker, 2.0, 1.25);
	testRate(tracker, 2.5, 1.0);

	tracker.setWindowPeriod(2);
	tracker.reset();
	Time interval = 1024.0/48000.0;
	for(Time now = 0; now < 5; now += interval)
	{
		tracker.update(342, now);
		if(now > 4)
			testRate(tracker, now, 16031.25, 342);
	}

	return 0;
}
