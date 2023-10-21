// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <algorithm>
#include <cassert>
#include <cfloat>
#include <cmath>
#include <cstdint>
#include <cstring>

#include "../include/rtmfp/AMF.hpp"

static void _indent(std::string &dst, size_t indent, size_t depth)
{
	if(indent)
		dst.push_back('\n');
	dst.append(depth * indent, ' ');
}

static std::string toBase10(uintmax_t val)
{
	char buf[40]; // big enough for 2^128 - 1 with null terminator
	char *cursor = buf + sizeof(buf);
	const char *limit = buf;
	uintmax_t remaining = val;

	*--cursor = 0; // null terminate
	do {
		unsigned digit = remaining % 10;
		*--cursor = '0' + digit;
		remaining /= 10;
	} while(remaining and (cursor > limit));

	return cursor;
}

static std::string fractionToBase10NoTrailingZeros(double fractionPart, size_t maxDigits)
{
	// Finite-Precision Fixed-Point Fraction Printout ((FP)3)
	// adapted from "How to Print Floating-Point Numbers Accurately"
	// by Guy L. Steele Jr. and Jon L White, Proceedings of the ACM
	// SIGPLAN'90 Conference on Programming Language Design and
	// Implementation.

	double error_M = pow(10, 0.0 - maxDigits) / 2.0;
	double remainder_R = fractionPart;
	std::string rv;
	double digit_U;

	assert(remainder_R < 1.0);
	if(remainder_R >= 1.0) // safety
		remainder_R = 1.0 - DBL_EPSILON;

	for(;;)
	{
		digit_U = floor(remainder_R * 10.0);
		remainder_R = fmod(remainder_R * 10.0, 1.0);
		error_M *= 10.0;

		if((remainder_R < error_M) or (remainder_R > 1.0 - error_M))
			break;

		rv.push_back('0' + int(digit_U));
	}

	if(remainder_R >= 0.5)
		digit_U += 1.0;

	if(digit_U > 9.0)
		return fractionToBase10NoTrailingZeros(fractionPart, maxDigits + 1);

	rv.push_back('0' + int(digit_U));

	return rv;
}

// this function is needed because C and C++11 don't provide a
// locale-independent floating point conversion function. C++17
// has std::to_chars but we're targeting C++11. someday we can
// switch to std::to_chars and remove these functions.
static bool dtoa(std::string &dst, double val, bool isJSON)
{
	if(val != val)
		dst.append(isJSON ? "null" : "nan"); // no nan in JSON
	else if(std::signbit(val))
	{
		dst.append("-");
		return dtoa(dst, -val, isJSON);
	}
	else if(std::isinf(val))
		dst.append(isJSON ? "1e5000" : "inf"); // will still be INFINITY if decoded to IEEE 754 quad-precision (15-bit exponent)
	else if((val >= UINTMAX_MAX) or ((val > 0.0) and (val < 0.0001)))
	{
		// use long double's (hopefully) greater precision to maintain good-enough
		// precision through log10 and pow.
		long double logarithm = log10l(val);
		long double exponent = floorl(logarithm);
		long double logremainder = logarithm - exponent;
		double shifted = powl(10.0, logremainder < 0.0 ? logremainder + 1.0 : logremainder);
		if(shifted >= 10.0)
		{
			shifted /= 10.0;
			exponent += 1.0;
		}
		if(!dtoa(dst, shifted, isJSON))
			return false;
		dst.append("e");
		return dtoa(dst, exponent, isJSON);
	}
	else
	{
		double integerPart = floor(val);
		std::string integerDigits = toBase10(uintmax_t(integerPart));
		dst.append(integerDigits);

		if(integerPart != val)
		{
			double fractionPart = val - integerPart;
			size_t bonusDigits = 1;
			if(val < 1.0)
				bonusDigits++;
			if(val < 0.1)
				bonusDigits++;
			if(val < 0.01)
				bonusDigits++;
			if(val < 0.001)
				bonusDigits++;

			dst.append(".");
			dst.append(fractionToBase10NoTrailingZeros(fractionPart, bonusDigits + DBL_DIG - std::min(size_t(DBL_DIG), integerDigits.size())));
		}
	}

	return true;
}

// we assume strings are UTF-8
static void jsonString(std::string &dst, const std::string &s)
{
	const uint8_t *cursor = (const uint8_t *)s.data();
	const uint8_t *limit = cursor + s.size();

	dst.push_back('"');

	while(cursor < limit)
	{
		uint8_t each = *cursor++;

		if((0x5c == each) or ('"' == each))
		{
			dst.push_back(0x5c);
			dst.push_back(each);
		}
		else if(0x08 == each)
			dst.append("\\b");
		else if(0x0c == each)
			dst.append("\\f");
		else if(0x0a == each)
			dst.append("\\n");
		else if(0x0d == each)
			dst.append("\\r");
		else if(0x09 == each)
			dst.append("\\t");
		else if((each < 0x20) or (each == 0x7f))
		{
			char hexdigits[] = "0123456789ABCDEF";
			dst.append("\\u00");
			dst.push_back(hexdigits[(each >> 4) & 0x0f]);
			dst.push_back(hexdigits[(each     ) & 0x0f]);
		}
		else
			dst.push_back(each);
	}

	dst.push_back('"');
}

namespace com { namespace zenomt { namespace rtmp {

std::shared_ptr<AMF0Number> AMF0::Number(double v) { return share_ref(new AMF0Number(v), false); }
std::shared_ptr<AMF0String> AMF0::String(const std::string &v) { return share_ref(new AMF0String(v), false); }
std::shared_ptr<AMF0Boolean> AMF0::Boolean(bool v) { return share_ref(new AMF0Boolean(v), false); }
std::shared_ptr<AMF0Boolean> AMF0::True() { return Boolean(true); }
std::shared_ptr<AMF0Boolean> AMF0::False() { return Boolean(false); }
std::shared_ptr<AMF0Null> AMF0::Null() { return share_ref(new AMF0Null(), false); }
std::shared_ptr<AMF0Undefined> AMF0::Undefined() { return share_ref(new AMF0Undefined(), false); }
std::shared_ptr<AMF0Object> AMF0::Object() { return share_ref(new AMF0Object(), false); }
std::shared_ptr<AMF0TypedObject> AMF0::TypedObject(const char *class_name) { return share_ref(new AMF0TypedObject(class_name), false); }
std::shared_ptr<AMF0ECMAArray> AMF0::ECMAArray() { return share_ref(new AMF0ECMAArray(), false); }
std::shared_ptr<AMF0Array> AMF0::Array() { return share_ref(new AMF0Array(), false); }

bool AMF0::isNumber() const { return false; }
AMF0Number *AMF0::asNumber() { return nullptr; }
AMF0Number *AMF0::asNumber(AMF0 *amf) { return amf ? amf->asNumber() : nullptr; }
double AMF0::doubleValue() const { return NAN; }

bool AMF0::isBoolean() const { return false; }
AMF0Boolean *AMF0::asBoolean() { return nullptr; }
AMF0Boolean *AMF0::asBoolean(AMF0 *amf) { return amf ? amf->asBoolean() : nullptr; }
bool AMF0::booleanValue() const { return false; }
bool AMF0::isTruthy() const { return false; }

bool AMF0::isString() const { return false; }
AMF0String *AMF0::asString() { return nullptr; }
AMF0String *AMF0::asString(AMF0 *amf) { return amf ? amf->asString() : nullptr; }
const char *AMF0::stringValue() const { return nullptr; }

bool AMF0::isObject() const { return false; }
AMF0Object *AMF0::asObject() { return nullptr; }
AMF0Object *AMF0::asObject(AMF0 *amf) { return amf ? amf->asObject() : nullptr; }
std::shared_ptr<AMF0> AMF0::getValueAtKey(const char *key) const { return getValueAtKey(std::string(key)); }
std::shared_ptr<AMF0> AMF0::getValueAtKey(const std::string &key) const { return Undefined(); }

bool AMF0::isNull() const { return false; }
AMF0Null *AMF0::asNull() { return nullptr; }
AMF0Null *AMF0::asNull(AMF0 *amf) { return amf ? amf->asNull() : nullptr; }

bool AMF0::isUndefined() const { return false; }
AMF0Undefined *AMF0::asUndefined() { return nullptr; }
AMF0Undefined *AMF0::asUndefined(AMF0 *amf) { return amf ? amf->asUndefined() : nullptr; }

bool AMF0::isECMAArray() const { return false; }
AMF0ECMAArray *AMF0::asECMAArray() { return nullptr; }
AMF0ECMAArray *AMF0::asECMAArray(AMF0 *amf) { return amf ? amf->asECMAArray() : nullptr; }

bool AMF0::isArray() const { return false; }
AMF0Array *AMF0::asArray() { return nullptr; }
AMF0Array *AMF0::asArray(AMF0 *amf) { return amf ? amf->asArray() : nullptr; }
std::shared_ptr<AMF0> AMF0::getValueAtIndex(uint32_t index) const { return Undefined(); }

bool AMF0::isDate() const { return false; }
AMF0Date *AMF0::asDate() { return nullptr; }
AMF0Date *AMF0::asDate(AMF0 *amf) { return amf ? amf->asDate() : nullptr; }

bool AMF0::isXMLDocument() const { return false; }
AMF0XMLDocument *AMF0::asXMLDocument() { return nullptr; }
AMF0XMLDocument *AMF0::asXMLDocument(AMF0 *amf) { return amf ? amf->asXMLDocument() : nullptr; }

bool AMF0::isTypedObject() const { return false; }
AMF0TypedObject *AMF0::asTypedObject() { return nullptr; }
AMF0TypedObject *AMF0::asTypedObject(AMF0 *amf) { return amf ? amf->asTypedObject() : nullptr; }

bool AMF0::decode(const uint8_t *cursor_, const uint8_t *limit, std::vector<std::shared_ptr<AMF0>> &dst)
{
	const uint8_t *cursor = cursor_;

	while(cursor < limit)
	{
		auto each = decode(&cursor, limit);
		if(not each)
			return false;
		dst.push_back(each);
	}

	return true;
}

std::shared_ptr<AMF0> AMF0::decode(const uint8_t **cursor_ptr, const uint8_t *limit)
{
	return decode(cursor_ptr, limit, 0);
}

std::shared_ptr<AMF0> AMF0::decode(const uint8_t **cursor_ptr, const uint8_t *limit, size_t depth)
{
	std::shared_ptr<AMF0> rv;
	const uint8_t *cursor = *cursor_ptr;

	if(depth > MAX_DEPTH)
		return rv;

	if(cursor < limit)
	{
		uint8_t typeMarker = *cursor++;
		switch(typeMarker)
		{
		case AMF0_NUMBER_MARKER:
			rv = Number();
			break;

		case AMF0_BOOLEAN_MARKER:
			rv = False();
			break;

		case AMF0_STRING_MARKER:
		case AMF0_LONG_STRING_MARKER:
			rv = String();
			break;

		case AMF0_OBJECT_MARKER:
			rv = Object();
			break;

		case AMF0_NULL_MARKER:
			rv = Null();
			break;

		case AMF0_UNDEFINED_MARKER:
		case AMF0_UNSUPPORTED_MARKER:
			rv = Undefined();
			break;

		case AMF0_REFERENCE_MARKER:
			// no good approach for references without garbage collection
			break;

		case AMF0_ECMAARRAY_MARKER:
			rv = ECMAArray();
			break;

		case AMF0_STRICT_ARRAY_MARKER:
			rv = Array();
			break;

		case AMF0_DATE_MARKER:
			break; // no reason for these

		case AMF0_XML_DOCUMENT_MARKER:
			break; // TODO

		case AMF0_TYPED_OBJECT_MARKER:
			rv = share_ref(new AMF0TypedObject(), false);
			break;

		default:
			break;
		}

		if(rv and rv->setFromEncoding(typeMarker, &cursor, limit, depth))
			*cursor_ptr = cursor;
		else
			rv.reset();
	}
	return rv;
}

AMF0::Bytes AMF0::encode(const AMF0 *v)
{
	Bytes rv;
	if(v)
		v->encode(rv);
	return rv;
}

AMF0::Bytes AMF0::encode(const std::vector<std::shared_ptr<AMF0>> &values)
{
	Bytes rv;
	encode(values, rv);
	return rv;
}

void AMF0::encode(const std::vector<std::shared_ptr<AMF0>> &values, Bytes &dst)
{
	for(auto it = values.begin(); it != values.end(); it++)
		if(*it)
			(*it)->encode(dst);
}

std::string AMF0::repr(size_t indent) const
{
	std::string rv;
	repr(rv, 0, indent, false);
	return rv;
}

void AMF0::repr(std::string &dst, size_t depth) const
{
	repr(dst, depth, 4, false);
}

std::string AMF0::toJSON(size_t indent) const
{
	std::string rv;
	repr(rv, 0, indent, true);
	return rv;
}

std::shared_ptr<AMF0> AMF0::duplicate() const
{
	Bytes tmp;
	encode(tmp);
	const uint8_t *cursor = tmp.data();
	const uint8_t *limit = cursor + tmp.size();
	return decode(&cursor, limit);
}

// --- AMF0Number

AMF0Number::AMF0Number() : m_value(0) { }
AMF0Number::AMF0Number(double v) : m_value(v) { }
AMF0::Type AMF0Number::getType() const { return AMF0_NUMBER; }
bool AMF0Number::isNumber() const { return true; }
AMF0Number * AMF0Number::asNumber() { return this; }
double AMF0Number::doubleValue() const { return m_value; }
void AMF0Number::doubleValue(double v) { m_value = v; }
void AMF0Number::repr(std::string &dst, size_t, size_t, bool asJson) const { dtoa(dst, m_value, asJson); }
bool AMF0Number::isTruthy() const { return (m_value < 0.0) or (m_value > 0.0); }

void AMF0Number::encode(Bytes &dst) const
{
	union {
		uint64_t u64;
		double   d;
	} value_u;

	value_u.d = doubleValue();

	dst.push_back(AMF0_NUMBER_MARKER);
	dst.push_back((value_u.u64 >> 56) & 0xff);
	dst.push_back((value_u.u64 >> 48) & 0xff);
	dst.push_back((value_u.u64 >> 40) & 0xff);
	dst.push_back((value_u.u64 >> 32) & 0xff);
	dst.push_back((value_u.u64 >> 24) & 0xff);
	dst.push_back((value_u.u64 >> 16) & 0xff);
	dst.push_back((value_u.u64 >>  8) & 0xff);
	dst.push_back((value_u.u64      ) & 0xff);
}

bool AMF0Number::setFromEncoding(uint8_t typeMarker, const uint8_t **cursor_ptr, const uint8_t *limit, size_t depth)
{
	const uint8_t *cursor = *cursor_ptr;
	if(limit - cursor < 8)
		return false;

	union {
		uint64_t u64;
		double   d;
	} value_u;

	value_u.u64  = *cursor++; 
	value_u.u64 <<= 8; value_u.u64 += *cursor++;
	value_u.u64 <<= 8; value_u.u64 += *cursor++;
	value_u.u64 <<= 8; value_u.u64 += *cursor++;
	value_u.u64 <<= 8; value_u.u64 += *cursor++;
	value_u.u64 <<= 8; value_u.u64 += *cursor++;
	value_u.u64 <<= 8; value_u.u64 += *cursor++;
	value_u.u64 <<= 8; value_u.u64 += *cursor++;

	doubleValue(value_u.d);

	*cursor_ptr = cursor;
	return true;
}

// --- AMF0Boolean

AMF0Boolean::AMF0Boolean() : m_value(false) { }
AMF0Boolean::AMF0Boolean(bool v) : m_value(v) { }
AMF0::Type AMF0Boolean::getType() const { return AMF0_BOOLEAN; }
bool AMF0Boolean::isBoolean() const { return true; }
AMF0Boolean * AMF0Boolean::asBoolean() { return this; }
bool AMF0Boolean::booleanValue() const { return m_value; }
void AMF0Boolean::booleanValue(bool v) { m_value = v; }
bool AMF0Boolean::isTruthy() const { return m_value; }
void AMF0Boolean::repr(std::string &dst, size_t, size_t, bool) const { dst.append(booleanValue() ? "true" : "false"); }

void AMF0Boolean::encode(Bytes &dst) const
{
	dst.push_back(AMF0_BOOLEAN_MARKER);
	dst.push_back(booleanValue() ? 1 : 0);
}

bool AMF0Boolean::setFromEncoding(uint8_t typeMarker, const uint8_t **cursor_ptr, const uint8_t *limit, size_t depth)
{
	if(limit - *cursor_ptr < 1)
		return false;

	booleanValue(*(*cursor_ptr)++);
	return true;
}

// --- AMF0String

AMF0String::AMF0String(const char *v) : m_value(v) { }
AMF0String::AMF0String(const std::string &v) : m_value(v) { }
AMF0::Type AMF0String::getType() const { return AMF0_STRING; }
bool AMF0String::isString() const { return true; }
AMF0String * AMF0String::asString() { return this; }
const char * AMF0String::stringValue() const { return m_value.c_str(); }
void AMF0String::stringValue(const char *v) { m_value = v; }
size_t AMF0String::size() const { return m_value.size(); }
bool AMF0String::isTruthy() const { return size(); }

void AMF0String::repr(std::string &dst, size_t, size_t, bool) const
{
	jsonString(dst, m_value);
}

bool AMF0String::decodeString(bool isLongString, const uint8_t **cursor_ptr, const uint8_t *limit, std::string &dst)
{
	const uint8_t *cursor = *cursor_ptr;
	size_t stringLength = 0;

	if(isLongString)
	{
		if(limit - cursor < 4)
			return false;
		stringLength = *cursor++;
		stringLength <<= 8; stringLength += *cursor++;
		stringLength <<= 8; stringLength += *cursor++;
		stringLength <<= 8; stringLength += *cursor++;
	}
	else
	{
		if(limit - cursor < 2)
			return false;
		stringLength = *cursor++;
		stringLength <<= 8; stringLength += *cursor++;
	}

	if((size_t)(limit - cursor) < stringLength)
		return false;

	dst = std::string((const char *)cursor, stringLength);
	cursor += stringLength;
	*cursor_ptr = cursor;
	return true;
}

void AMF0String::encode(Bytes &dst) const
{
	size_t sz = size();
	if(sz > 0xffff)
	{
		dst.push_back(AMF0_LONG_STRING_MARKER);
		dst.push_back((sz >> 24) & 0xff);
		dst.push_back((sz >> 16) & 0xff);
		dst.push_back((sz >>  8) & 0xff);
		dst.push_back((sz      ) & 0xff);
	}
	else
	{
		dst.push_back(AMF0_STRING_MARKER);
		dst.push_back((sz >>  8) & 0xff);
		dst.push_back((sz      ) & 0xff);
	}

	dst.insert(dst.end(), m_value.begin(), m_value.end());
}

bool AMF0String::setFromEncoding(uint8_t typeMarker, const uint8_t **cursor_ptr, const uint8_t *limit, size_t depth)
{
	return decodeString(AMF0_LONG_STRING_MARKER == typeMarker, cursor_ptr, limit, m_value);
}

// --- AMF0Object

AMF0::Type AMF0Object::getType() const { return AMF0_OBJECT; }
bool AMF0Object::isObject() const { return true; }
AMF0Object * AMF0Object::asObject() { return this; }
bool AMF0Object::isTruthy() const { return true; }

AMF0Object * AMF0Object::putValueAtKey(AMF0 *value, const char *key)
{
	return putValueAtKey(share_ref(value), key);
}

AMF0Object * AMF0Object::putValueAtKey(const std::shared_ptr<AMF0> &value, const char *key)
{
	return putValueAtKey(value, std::string(key));
}

AMF0Object * AMF0Object::putValueAtKey(const std::shared_ptr<AMF0> &value, const std::string &key)
{
	if(key.size() < 65536)
		m_members[key] = value;

	return this;
}

void AMF0Object::erase(const std::string &key)
{
	m_members.erase(key);
}
void AMF0Object::erase(const char *key) { erase(std::string(key)); }

void AMF0Object::clear()
{
	m_members.clear();
}

size_t AMF0Object::size() const
{
	return m_members.size();
}

bool AMF0Object::has(const std::string &key) const
{
	return m_members.count(key);
}
bool AMF0Object::has(const char *key) const { return has(std::string(key)); }

std::shared_ptr<AMF0> AMF0Object::getValueAtKey(const std::string &key) const
{
	auto it = m_members.find(key);
	if(it != m_members.end())
		return it->second;
	return Undefined();
}

AMF0Object::AMF0Map::iterator AMF0Object::begin() { return m_members.begin(); }
AMF0Object::AMF0Map::const_iterator AMF0Object::begin() const { return m_members.begin(); }
AMF0Object::AMF0Map::iterator AMF0Object::end() { return m_members.end(); }
AMF0Object::AMF0Map::const_iterator AMF0Object::end() const { return m_members.end(); }

void AMF0Object::repr(std::string &dst, size_t depth, size_t indent, bool asJson) const
{
	dst.append("{");
	reprMembers(dst, depth, indent, asJson);
	dst.append("}");
}

void AMF0Object::encode(Bytes &dst) const
{
	dst.push_back(AMF0_OBJECT_MARKER);
	encodeMembers(dst);
}

void AMF0Object::reprMembers(std::string &dst, size_t depth, size_t indent, bool asJson) const
{
	bool isFirst = true;

	for(auto it = begin(); it != end(); it++)
	{
		if((not asJson) or (it->second and not it->second->isUndefined()))
		{
			if(not isFirst)
				dst.push_back(',');
			isFirst = false;
			_indent(dst, indent, depth + 1);
			jsonString(dst, it->first);
			dst.push_back(':');
			if(indent)
				dst.push_back(' ');
			if(it->second)
				it->second->repr(dst, depth + 1, indent, asJson);
			else
				dst.append("undefined");
		}
	}

	if(not isFirst)
		_indent(dst, indent, depth);
}

void AMF0Object::encodeMembers(Bytes &dst) const
{
	for(auto it = begin(); it != end(); it++)
	{
		size_t keyLength = it->first.size(); // safe, no long keys are ever inserted
		dst.push_back((keyLength >> 8) & 0xff);
		dst.push_back((keyLength     ) & 0xff);
		dst.insert(dst.end(), it->first.begin(), it->first.end());

		if(it->second)
			it->second->encode(dst);
		else
			dst.push_back(AMF0_UNDEFINED_MARKER);
	}
	dst.push_back(0);
	dst.push_back(0);
	dst.push_back(AMF0_OBJECT_END_MARKER);
}

bool AMF0Object::setFromEncoding(uint8_t typeMarker, const uint8_t **cursor_ptr, const uint8_t *limit, size_t depth)
{
	const uint8_t *cursor = *cursor_ptr;

	while(limit - cursor >= 3)
	{
		size_t keyLength = *cursor++;
		keyLength <<= 8; keyLength += *cursor++;

		if((size_t)(limit - cursor) < keyLength)
			return false;

		if((0 == keyLength) and (AMF0_OBJECT_END_MARKER == *cursor)) // safe because there's always at least 3 bytes
		{
			cursor++;
			*cursor_ptr = cursor;
			return true;
		}

		std::string key((const char *)cursor, keyLength);
		cursor += keyLength;

		auto value = decode(&cursor, limit, depth + 1);
		if(not value)
			return false;

		putValueAtKey(value, key);
	}

	return false;
}

// --- AMF0TypedObject

AMF0TypedObject::AMF0TypedObject(const char *class_name) :
	m_class_name(class_name, std::min(strlen(class_name), (size_t)65535))
{
}

AMF0::Type AMF0TypedObject::getType() const { return AMF0_TYPED_OBJECT; }
bool AMF0TypedObject::isTypedObject() const { return true; }
AMF0TypedObject * AMF0TypedObject::asTypedObject() { return this; }
const char * AMF0TypedObject::className() const { return m_class_name.c_str(); }

void AMF0TypedObject::repr(std::string &dst, size_t depth, size_t indent, bool asJson) const
{
	if(asJson)
		AMF0Object::repr(dst, depth, indent, asJson);
	else
	{
		dst.append("<");
		jsonString(dst, m_class_name);
		dst.append(":{");
		reprMembers(dst, depth, indent, asJson);
		dst.append("}>");
	}
}

void AMF0TypedObject::encode(Bytes &dst) const
{
	dst.push_back(AMF0_TYPED_OBJECT_MARKER);
	dst.push_back((m_class_name.size() >> 8) & 0xff);
	dst.push_back((m_class_name.size()     ) & 0xff);
	dst.insert(dst.end(), m_class_name.begin(), m_class_name.end());
	encodeMembers(dst);
}

bool AMF0TypedObject::setFromEncoding(uint8_t typeMarker, const uint8_t **cursor_ptr, const uint8_t *limit, size_t depth)
{
	return AMF0String::decodeString(false, cursor_ptr, limit, m_class_name) and AMF0Object::setFromEncoding(typeMarker, cursor_ptr, limit, depth);
}

// --- AMF0ECMAArray

AMF0::Type AMF0ECMAArray::getType() const { return AMF0_ECMAARRAY; }
bool AMF0ECMAArray::isECMAArray() const { return true; }
AMF0ECMAArray *AMF0ECMAArray::asECMAArray() { return this; }

void AMF0ECMAArray::encode(Bytes &dst) const
{
	size_t numElements = std::min(size(), size_t(UINT32_MAX));

	dst.push_back(AMF0_ECMAARRAY_MARKER);
	dst.push_back((numElements >> 24) & 0xff);
	dst.push_back((numElements >> 16) & 0xff);
	dst.push_back((numElements >>  8) & 0xff);
	dst.push_back((numElements      ) & 0xff);

	encodeMembers(dst);
}

bool AMF0ECMAArray::setFromEncoding(uint8_t typeMarker, const uint8_t **cursor_ptr, const uint8_t *limit, size_t depth)
{
	if(limit - *cursor_ptr < 4)
		return false;

	// Adobe's implementations sets associative-count to 0, and all
	// implementations terminate the associative array with a
	// ("" object-end-marker) 00 00 09. So just ignore the length field.
	*cursor_ptr += 4;

	return AMF0Object::setFromEncoding(typeMarker, cursor_ptr, limit, depth);
}

// --- AMF0Null

AMF0::Type AMF0Null::getType() const { return AMF0_NULL; }
bool AMF0Null::isNull() const { return true; }
AMF0Null * AMF0Null::asNull() { return this; }
void AMF0Null::repr(std::string &dst, size_t, size_t, bool) const { dst.append("null"); }

void AMF0Null::encode(Bytes &dst) const
{
	dst.push_back(AMF0_NULL_MARKER);
}

bool AMF0Null::setFromEncoding(uint8_t typeMarker, const uint8_t **cursor_ptr, const uint8_t *limit, size_t depth)
{
	return true;
}

// --- AMF0Undefined

AMF0::Type AMF0Undefined::getType() const { return AMF0_UNDEFINED; }
bool AMF0Undefined::isUndefined() const { return true; }
AMF0Undefined * AMF0Undefined::asUndefined() { return this; }
void AMF0Undefined::repr(std::string &dst, size_t, size_t, bool asJson) const { dst.append(asJson ? "null" : "undefined"); }

void AMF0Undefined::encode(Bytes &dst) const
{
	dst.push_back(AMF0_UNDEFINED_MARKER);
}

bool AMF0Undefined::setFromEncoding(uint8_t typeMarker, const uint8_t **cursor_ptr, const uint8_t *limit, size_t depth)
{
	return true;
}

// --- AMF0Array

AMF0::Type AMF0Array::getType() const { return AMF0_ARRAY; }
bool AMF0Array::isArray() const { return true; }
AMF0Array * AMF0Array::asArray() { return this; }
bool AMF0Array::isTruthy() const { return true; }

AMF0Array * AMF0Array::putValueAtIndex(AMF0 *value, uint32_t index)
{
	return putValueAtIndex(share_ref(value), index);
}

AMF0Array * AMF0Array::putValueAtIndex(const std::shared_ptr<AMF0> &value, uint32_t index)
{
	size_t maybeSize = index;
	maybeSize++;
	if(maybeSize > size())
		resize(maybeSize);
	m_members.at(index) = value;
	return this;
}

AMF0Array * AMF0Array::appendValue(AMF0 *value)
{
	return appendValue(share_ref(value));
}

AMF0Array * AMF0Array::appendValue(const std::shared_ptr<AMF0> &value)
{
	if(size() == UINT32_MAX)
		return nullptr;

	return putValueAtIndex(value, uint32_t(size()));
}

void AMF0Array::resize(size_t newSize)
{
	m_members.resize(newSize);
}

void AMF0Array::reset(uint32_t index)
{
	if(index < size())
		m_members.at(index).reset();
}

void AMF0Array::remove(uint32_t fromIndex, size_t count)
{
	size_t limit = std::min(fromIndex + count, size());
	if((limit < fromIndex) or (fromIndex >= limit))
		return;
	m_members.erase(m_members.begin() + fromIndex, m_members.begin() + limit);
}

void AMF0Array::clear()
{
	m_members.clear();
}

size_t AMF0Array::size() const
{
	return m_members.size();
}

std::shared_ptr<AMF0> AMF0Array::getValueAtIndex(uint32_t index) const
{
	if((index >= size()) or not m_members.at(index))
		return Undefined();
	return m_members.at(index);
}

void AMF0Array::repr(std::string &dst, size_t depth, size_t indent, bool asJson) const
{
	dst.push_back('[');
	bool isFirst = true;
	for(uint32_t i = 0; i < size(); i++)
	{
		if(not isFirst)
			dst.push_back(',');
		isFirst = false;
		_indent(dst, indent, depth + 1);
		getValueAtIndex(i)->repr(dst, depth + 1, indent, asJson);
	}
	if(not isFirst)
		_indent(dst, indent, depth);
	dst.push_back(']');
}

void AMF0Array::encode(Bytes &dst) const
{
	size_t sz = size();
	dst.push_back(AMF0_STRICT_ARRAY_MARKER);
	dst.push_back((sz >> 24) & 0xff);
	dst.push_back((sz >> 16) & 0xff);
	dst.push_back((sz >>  8) & 0xff);
	dst.push_back((sz      ) & 0xff);

	for(uint32_t i = 0; i < size(); i++)
		getValueAtIndex(i)->encode(dst);
}

bool AMF0Array::setFromEncoding(uint8_t typeMarker, const uint8_t **cursor_ptr, const uint8_t *limit, size_t depth)
{
	const uint8_t *cursor = *cursor_ptr;
	if(limit - cursor < 4)
		return false;

	size_t sz = *cursor++;
	sz <<= 8; sz += *cursor++;
	sz <<= 8; sz += *cursor++;
	sz <<= 8; sz += *cursor++;

	for(uint32_t i = 0; i < sz; i++)
	{
		auto value = decode(&cursor, limit, depth + 1);
		if(not value)
			return false;
		putValueAtIndex(value, i);
	}

	*cursor_ptr = cursor;
	return true;
}

// --- AMF0Date TODO

// --- AMF0XMLDocument TODO

} } } // namespace com::zenomt::rtmp
