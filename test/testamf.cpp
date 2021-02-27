#include <cstdio>

#include "rtmfp/AMF.hpp"
#include "rtmfp/Hex.hpp"

using namespace com::zenomt;
using namespace com::zenomt::rtmp;
using Bytes = AMF0::Bytes;

static void _print(const std::shared_ptr<AMF0> &amf)
{
	printf("%s\n", amf->repr().c_str());
}

int main(int argc, char **argv)
{
	Bytes dst;

	auto number = AMF0::Number(3);
	auto str = AMF0::String("hello world");
	auto boolean = AMF0::True();
	auto amf_null = AMF0::Null();
	auto amf_undefined = AMF0::Undefined();
	auto amf_obj = AMF0::Object();
	auto amf_typed_obj = AMF0::TypedObject("typed");
	auto amf_array = AMF0::Array();

	amf_obj->putValueAtKey(str, "str")->putValueAtKey(boolean, "bool")->putValueAtKey(number, "num");

	amf_typed_obj
		->putValueAtKey(amf_obj, "obj")
		->putValueAtKey(AMF0::Array(), "empty array")
		->putValueAtKey(AMF0::Object(), "empty object")
		->putValueAtKey(AMF0::TypedObject("empty typed object"), "empty typed object")
		;

	amf_array
		->appendValue(AMF0::Object()
			->putValueAtKey(AMF0::String("inner value"), "inner key")
			->putValueAtKey(AMF0::Null(), "null key")
			->putValueAtKey(AMF0::Array()
				->appendValue(AMF0::Number(1))
				->appendValue(AMF0::String("two"))
				, "array value")
			)
		->appendValue(amf_typed_obj)
		->appendValue(boolean)
		->putValueAtIndex(number, 5)
		->appendValue(AMF0::String("appending anonymous"))
		->appendValue(AMF0::Null())
		;

	_print(number);
	number->encode(dst);

	_print(str);
	str->encode(dst);

	_print(boolean);
	boolean->encode(dst);

	_print(amf_null);
	amf_null->encode(dst);

	_print(amf_undefined);
	amf_undefined->encode(dst);

	dst.push_back(AMF0_UNSUPPORTED_MARKER);

	_print(amf_obj);
	amf_obj->encode(dst);

	_print(amf_typed_obj);
	amf_typed_obj->encode(dst);

	_print(amf_array);
	amf_array->encode(dst);

	Hex::print("encoding", dst);

	std::vector<std::shared_ptr<AMF0>> values;
	bool rv = AMF0::decode(dst.data(), dst.data() + dst.size(), values);
	if(rv)
	{
		printf("decoded to:\n");
		for(auto it = values.begin(); it != values.end(); it++)
			_print(*it);
	}
	else
		printf("did not decode\n");

	printf("amf_array[0][\"array value\"][1]: %s\n", amf_array->getValueAtIndex(0)->getValueAtKey("array value")->getValueAtIndex(1)->stringValue());
	printf("amf_array[0][\"array value 2\"][1]: %s\n", amf_array->getValueAtIndex(0)->getValueAtKey("array value 2")->getValueAtIndex(2)->stringValue());
	printf("amf_array[1][\"array value 2\"][1]: %s\n", amf_array->getValueAtIndex(1)->getValueAtKey("array value 2")->getValueAtIndex(2)->stringValue());
	printf("amf_array[1][\"obj\"][\"num\"]: %f\n", amf_array->getValueAtIndex(1)->getValueAtKey("obj")->getValueAtKey("num")->doubleValue());
	printf("isNumber? amf_array[2][\"obj\"][\"num\"]: %d\n", amf_array->getValueAtIndex(2)->getValueAtKey("obj")->getValueAtKey("num")->isNumber());

	printf("\n\n");
	auto remove_array = AMF0::Array();
	for(int i = 0; i < 10; i++)
		remove_array->appendValue(AMF0::Number(i));
	_print(remove_array);
	printf("removing [1..2]\n");
	remove_array->remove(1, 2);
	_print(remove_array);
	printf("removing final two\n");
	remove_array->remove(remove_array->size() - 2, 2);
	_print(remove_array);

	return 0;
}
