#include <cstdio>
#include <unistd.h>

#include "rtmfp/IndexSet.hpp"
#include "rtmfp/List.hpp"
#include "rtmfp/Timer.hpp"
#include "rtmfp/SelectRunLoop.hpp"

using namespace com::zenomt;

class Foo : public Object
{
public:
	~Foo()
	{
		printf("~Foo %p\n", (void *)this);
	}

	static void timerAction(std::shared_ptr<Timer> sender, double now)
	{
		printf("Foo static timerAction now %f timer %p\n", now, (void *)sender.get());
	}
};

void printIndexSet(IndexSet *i)
{
	i->extentsDo([] (uintmax_t a, uintmax_t b) { printf("%lu to %lu\n", a, b); return true; });
	printf("count: %lu ranges: %lu has-10: %d\n\n", i->size(), i->countRanges(), i->contains(10));
}

int main(int argc, char *argv[])
{
	IndexSet i;

	Foo *foo = new Foo();
	std::shared_ptr<Foo> ooo = share_ref<Foo>(foo, false);
	std::shared_ptr<Foo> oob = ooo;
	std::shared_ptr<Foo> ooc = share_ref<Foo>(foo);
	ooo = nullptr;
	oob = ooc;

	printIndexSet(&i);

	i.add(11);
	i.add(1);
	i.add(3, 9);
	i.add(0);

	printIndexSet(&i);

	i.add(2);
	printIndexSet(&i);

	i.add(2);
	printIndexSet(&i);

	i.add(5,10);
	printIndexSet(&i);

	i.remove(5);
	printIndexSet(&i);

	i.remove(4,6);
	printIndexSet(&i);

	i.remove(0);
	printIndexSet(&i);

	i.remove(11);
	printIndexSet(&i);

	i.indicesDo([] (uintmax_t anIndex) { printf("%ld ", anIndex); return true; });
	printf("\n\n");

	IndexSet j = IndexSet();
	j.add(i);
	printIndexSet(&j);

	IndexSet k = j;
	k.remove(10);
	printIndexSet(&k);
	printIndexSet(&j);

	k.clear();
	k.add(2, -2);
	printIndexSet(&k);

	k.add(-1);
	printIndexSet(&k);

	k.add(1);
	printIndexSet(&k);

	k.add(0);
	printIndexSet(&k);

	k.remove(-1);
	printIndexSet(&k);

	k.remove(1000000000);
	Range r = k.firstRange();
	printf("rf: %lu to %lu\n", r.start, r.end);

	r = k.lastRange();
	printf("rl: %lu to %lu\n", r.start, r.end);

	printf("k %lu to %lu\n", k.lowestIndex(), k.highestIndex());

	uintmax_t val = -1;
	printf("val: %lu >0: %d\n", val, val > 0);

	val = 0;
	printf("val: %lu >0: %d\n", val, val > 0);

	val = 4294967296;
	printf("val: %lu >0: %d\n", val, val > 0);

	printf("-----\n\n");

	List<std::shared_ptr<IndexSet> > l2;
	l2.append(std::make_shared<IndexSet>());
	l2.append(share_ref(new IndexSet(), false));
	l2.firstValue()->add(5,10);
	printIndexSet(l2.firstValue().get());
	l2.clear();

	printf("---\n");

	int count = 0;
	Timer::Action action = [count] (std::shared_ptr<Timer> sender, double now) mutable { count++; printf("runloop action %.20Lf @%.7f %p times %d\n", sender->getNextFireTime(), now, (void *)sender.get(), count); };
	RunLoop::Action rlAction = [] (RunLoop *sender, int fd, RunLoop::Condition cond) { printf("%d activated for %d! unregistering.\n", fd, cond); sender->unregisterDescriptor(fd); };
	SelectRunLoop rl;
	rl.schedule(action, rl.getCurrentTime() + 1, 1.0L + 1.0L / 576460752303423488.0L);
	rl.registerDescriptor(0, RunLoop::READABLE, rlAction);
	rl.registerDescriptor(1, RunLoop::WRITABLE, rlAction);
	rl.registerDescriptor(99, RunLoop::READABLE, rlAction);

	rl.schedule(9)->action = action;
	rl.schedule(2)->action = Foo::timerAction;
	rl.schedule(1)->action = action;
	rl.schedule(3, 1.5)->action = action;
	rl.schedule(Timer::Action(), 5);
	rl.schedule(6.5);
	rl.schedule(12, 0.9, false)->action = [] (const std::shared_ptr<Timer> &sender, double now) { printf("non-catchup %Lf @ %f\n", sender->getNextFireTime(), now); };

	rl.schedule([] (const std::shared_ptr<Timer> &sender, double now) { printf("firing now! %f\n", now); }, 5.25);
	rl.schedule([] (std::shared_ptr<Timer> sender, double now) { printf("firing %Lf @ %f and manually rescheduling %p\n", sender->getNextFireTime(), now, (void *)sender.get()); sender->setNextFireTime(sender->getNextFireTime() + 1.25); }, 5.75);
	rl.schedule(Timer::makeAction([] (double now) { printf("simplified action firing now! %f\n", now); }), 0.5, 3);
	rl.schedule(Timer::makeAction([] { printf("even simpler action firing sometime!\n"); }), 1, 3);
	rl.schedule(7)->action = [] (std::shared_ptr<Timer> sender, double now) { printf("firing at %f for late action assignment %p\n", now, (void *)sender.get()); };

	rl.schedule(1, 0.5, false)->action = [] (const std::shared_ptr<Timer> &sender, Time now) { printf("backoff timer now %Lf\n", now); sender->setRecurInterval(sender->getRecurInterval() * 1.1); };

	rl.doLater([] { printf("doing the first doLater\n"); });
	rl.schedule(5)->action = Timer::makeAction([&] { rl.doLater([&] { printf("doing a doLater set from a timer, at %Lf\n", rl.getCurrentTime()); }); });

	printf("run(0)\n");
	rl.run(0);

	printf("run(15)\n");
	rl.run(15);

	printf("run(5, 5)\n");
	rl.run(5, 5);

	size_t times = 0;
	rl.schedule([&] (std::shared_ptr<Timer> sender, double now) { times++; if(sender->getNextFireTime() >= 22) sender->cancel(); }, 21, 0.00000001, false);
	printf("run(5) with a tight timer\n");
	rl.run(5);
	printf("times: %lu\n", times);

	printf("\n\ntesting onHowLongToSleepDidChange\n");
	TimerList tl;
	tl.onHowLongToSleepDidChange = [] { printf("onHowLongToSleepDidChange!\n"); };
	tl.schedule(5)->action = action;
	tl.schedule(7)->action = action;
	tl.schedule(4)->action = action;
	tl.schedule(6)->action = Timer::makeAction([&] { printf("make one more while running\n"); tl.schedule(3)->action = action; });

	tl.fireDueTimers(20);
	tl.schedule(21);

	return 0;
}
