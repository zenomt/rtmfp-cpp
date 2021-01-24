#include <cstdio>

#include "rtmfp/SelectRunLoop.hpp"
#include "rtmfp/Performer.hpp"

using namespace com::zenomt;

void worker(std::shared_ptr<RunLoop> rl)
{
	printf("starting worker run loop\n");
	rl->run();
	printf("worker runloop and thread end\n");
}

int main(int argc, char *argv[])
{
	auto rl = share_ref<RunLoop>(new SelectRunLoop(), false);
	auto performer = share_ref<Performer>(new Performer(rl.get()), false);

	auto workerRL = share_ref<RunLoop>(new SelectRunLoop(true), false);
	auto workerPerformer = share_ref<Performer>(new Performer(workerRL.get()), false);

	workerPerformer->perform([] { printf("worker perform async before thread start\n"); });

	std::thread workerThread = std::thread(worker, workerRL);

	workerPerformer->perform([] { printf("worker perform sync after thread start and before main rl start\n"); }, true);
	printf("in main thread after sync perform on worker\n");

	workerPerformer->perform([=] {
		workerRL->scheduleRel(Timer::makeAction([=] (Time now) {
			printf("queuing async perform from worker at %Lf\n", now);
			performer->perform([] { printf("doing async worker perform\n"); });
			printf("after async worker perform\n");

			Time before = workerRL->getCurrentTimeNoCache();
			printf("queuing sync perform from worker\n");
			performer->perform([] { printf("doing sync worker perform\n"); }, true);
			printf("after sync worker perform took %.9Lf\n\n", workerRL->getCurrentTimeNoCache() - before);
		}), 1, 1);
	});

	rl->schedule(Timer::makeAction([performer] (Time now) {
		printf("queuing async perform from main at %Lf\n", now);
		performer->perform([] { printf("doing async perform from main\n"); });
		printf("after async perform from main\n");
	}), 1./3., 1);

	rl->schedule(Timer::makeAction([performer, rl] (Time now) {
		printf("queuing sync perform from main at %Lf\n", now);
		Time before = rl->getCurrentTimeNoCache();
		performer->perform([] { printf("doing sync perform from main\n"); }, true);
		printf("after sync perform from main took %.9Lf\n\n", rl->getCurrentTimeNoCache() - before);
	}), 2./3., 1);

	rl->scheduleRel(Timer::makeAction([=] {
		// this can't be sync because worker does sync performs to the main thread,
		// and so this could deadlock.
		printf("trying to stop worker thread and then main thread\n");
		workerPerformer->perform([=] {
			printf("perform stop in worker thread sent from main thread\n");
			workerRL->stop();

			printf("perform stop from worker to main thread.\n");
			performer->perform([=] {
				printf("stopping main runloop from perform sent from worker.\n");
				rl->stop();
			});
		});
	}), 5);

	rl->run();

	// now we can join
	printf("wait for worker thread to stop\n");
	workerThread.join();
	printf("worker thread stopped.\n");

	workerPerformer->close();
	workerRL->clear();

	performer->close();
	rl->clear();

	printf("end.\n");

	return 0;
}
