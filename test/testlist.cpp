#include <cstdio>
#include <cassert>
#include "rtmfp/List.hpp"

using namespace com::zenomt;

static size_t mysize(const int& val)
{
	return 2 * (val < 0 ? -val : val);
}

int main(int argc, char *argv[])
{
	SumList<int> l(mysize, 0);

	printf("%ld ", l.prepend(1));
	printf("%ld ", l.prepend(2));
	printf("%ld ", l.prepend(3));

	printf("%ld ", l.append(6));
	printf("%ld ", l.append(7));
	printf("%ld ", l.append(8));
	printf("sum: %lu\n", l.sum());

	assert(l.sum() == 54); // times two

	printf("find 6: %ld\n", l.find(6));

	long name = l.SENTINEL;
	while((name = l.next(name)) > l.SENTINEL)
	{
		printf("%ld=%d ", name, l.at(name));
	}
	printf("\n");
	printf("size: %lu\n", l.size());
	l.clear();
	printf("size: %lu\n", l.size());

	for(int x = 0; x < 50; x++)
		printf("%ld ", l.append(x));
	printf("\n");

	l.rotateNameToHead(30);
	l.moveNameToHead(35);

	printf("safeValuesDo: ");
	l.safeValuesDo([] (int v) { printf("%d ", v); return true; });
	printf(" sum: %lu\n", l.sum());

	while(not l.empty())
	{
		printf("%d ", l.firstValue());
		l.removeFirst();
	}
	printf("sum: %lu\n", l.sum());
	assert(0 == l.sum());

	printf("---\n");
	for(int x = 0; x < 10000000; x++)
		l.append(x);
	printf("size: %lu sum: %lu\n", l.size(), l.sum());
	l.clear();
	printf("size: %lu sum: %lu\n", l.size(), l.sum());
	for(int x = 0; x < 10000000; x++)
		l.append(x);
	printf("size: %lu sum: %lu\n", l.size(), l.sum());

	printf("---\n");

	return 0;
}
