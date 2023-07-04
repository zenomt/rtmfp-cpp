#include <algorithm>
#include <cassert>
#include <cstdio>

#include "rtmfp/Object.hpp"
#include "rtmfp/Retainer.hpp"

using namespace com::zenomt;

namespace {

class Test : public Object {
public:
	long getRefcount() const
	{
		return m_refcount;
	}

	void release() override
	{
		assert(m_refcount > 0);
		Object::release();
	}
};

class SubTest : public Test
{
};

Retainer<Test> returnEmpty()
{
	return nullptr;
}

}

int main(int, char **)
{
	auto t1 = claim_ref(new Test());
	assert(t1);

	{
		auto t2 = t1;
		auto t3(t1);

		assert(3 == t1->getRefcount());
		assert(3 == (*t2).getRefcount());
		assert(3 == t3.get()->getRefcount());
		assert(t1 == t2);
		assert(t2 == t3);
		assert(t1 <= t2);
		assert(t1 >= t2);
	}
	assert(1 == t1->getRefcount());

	{
		auto t2 = t1;
		assert(2 == t1->getRefcount());
		t2.reset();
		assert(t2.empty());
		assert(not t2);
		assert(1 == t1->getRefcount());
		assert(t2 < t1);
		assert(t1 > t2);
		assert(t1 >= t2);
		assert(t2 <= t1);
		assert(nullptr < t1);
		assert(t1 > nullptr);
		assert(nullptr <= t1);
		assert(t1 >= nullptr);
		assert(t1 != nullptr);
		assert(t2 == nullptr);
	}
	assert(1 == t1->getRefcount());

	{
		auto t2 = t1;
		t1.reset();
		assert(1 == t2->getRefcount());
		t1 = t2;
		assert(2 == t2->getRefcount());
	}

	{
		Retainer<Test> t2;
		std::swap(t1, t2);

		assert(t1.empty());
		assert(1 == t2->getRefcount());
		std::swap(t1, t2);
	}
	assert(1 == t1->getRefcount());

	{
		Retainer<Test> t2;
		t1.swap(t2);

		assert(t1.empty());
		assert(1 == t2->getRefcount());
		t1.swap(t2);
	}
	assert(1 == t1->getRefcount());

	{
		Retainer<Test> t2;
		t2 = std::move(t1);

		assert(t1.empty());
		assert(1 == t2->getRefcount());
		t1 = t2;
		assert(2 == t1->getRefcount());
	}

	auto s1 = claim_ref(new SubTest());

	{
		auto tmp = t1;
		t1 = s1;

		assert(1 == tmp->getRefcount());
		assert(2 == s1->getRefcount());
		assert(s1 == t1);
		assert(s1 != tmp);
		assert((s1 < tmp) or (s1 > tmp));

		t1 = tmp;
	}

	{
		auto t2 = Retainer<Test>(t1);
		assert(2 == t2->getRefcount());

		t2 = retain_ref(s1.get());
		assert(2 == t2->getRefcount());
		assert(2 == s1->getRefcount());
		assert(t2 == s1);
		assert(1 == t1->getRefcount());
		assert(t2 != t1);
	}

	{
		auto t2 = returnEmpty();
		assert(t2.empty());
	}

	{
		auto t2 = t1;
		assert(t2);
		t2 = nullptr;
		assert(not t2);
	}

	{
		auto t2 = t1;
		t1 = t2;
		assert(2 == t1->getRefcount());
		assert(t1 == t2);
	}

	// ---

	assert(1 == t1->getRefcount());
	assert(1 == s1->getRefcount());

	return 0;
}
