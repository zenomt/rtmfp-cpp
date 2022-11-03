#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

// Action Message Format 0
// https://www.adobe.com/go/spec_amf0

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "Object.hpp"

namespace com { namespace zenomt { namespace rtmp {

class AMF0Number; class AMF0Boolean; class AMF0String; class AMF0Object;
class AMF0Null; class AMF0Undefined; class AMF0ECMAArray; class AMF0Array;
class AMF0Date; class AMF0XMLDocument; class AMF0TypedObject;

enum {
	AMF0_NUMBER_MARKER = 0x00,
	AMF0_BOOLEAN_MARKER = 0x01,
	AMF0_STRING_MARKER = 0x02,
	AMF0_OBJECT_MARKER = 0x03,
	AMF0_NULL_MARKER = 0x05,
	AMF0_UNDEFINED_MARKER = 0x06,
	AMF0_REFERENCE_MARKER = 0x07,
	AMF0_ECMAARRAY_MARKER = 0x08,
	AMF0_OBJECT_END_MARKER = 0x09,
	AMF0_STRICT_ARRAY_MARKER = 0x0a,
	AMF0_DATE_MARKER = 0x0b,
	AMF0_LONG_STRING_MARKER = 0x0c,
	AMF0_UNSUPPORTED_MARKER = 0x0d,
	AMF0_XML_DOCUMENT_MARKER = 0x0f,
	AMF0_TYPED_OBJECT_MARKER = 0x10,
	AMF0_AVMPLUS_OBJECT_MARKER = 0x11
};

class AMF0 : public Object {
public:
	using Bytes = std::vector<uint8_t>;
	static const size_t MAX_DEPTH = 32;

	enum Type { AMF0_NUMBER, AMF0_BOOLEAN, AMF0_STRING, AMF0_OBJECT,
		AMF0_NULL, AMF0_UNDEFINED, AMF0_ECMAARRAY, AMF0_ARRAY, AMF0_DATE,
		AMF0_XMLDOCUMENT, AMF0_TYPED_OBJECT };

	static std::shared_ptr<AMF0Number> Number(double v = 0);
	static std::shared_ptr<AMF0String> String(const char *v = "");
	static std::shared_ptr<AMF0String> String(const std::string &v);
	static std::shared_ptr<AMF0Boolean> Boolean(bool v = false);
	static std::shared_ptr<AMF0Boolean> True();
	static std::shared_ptr<AMF0Boolean> False();
	static std::shared_ptr<AMF0Null> Null();
	static std::shared_ptr<AMF0Undefined> Undefined();
	static std::shared_ptr<AMF0Object> Object();
	static std::shared_ptr<AMF0TypedObject> TypedObject(const char *class_name);
	static std::shared_ptr<AMF0ECMAArray> ECMAArray();
	static std::shared_ptr<AMF0Array> Array();

	virtual Type getType() const = 0;

	virtual bool isNumber() const;
	virtual AMF0Number *asNumber();
	static  AMF0Number *asNumber(AMF0 *amf);
	virtual double doubleValue() const;

	virtual bool isBoolean() const;
	virtual AMF0Boolean *asBoolean();
	static  AMF0Boolean *asBoolean(AMF0 *amf);
	virtual bool booleanValue() const;
	virtual bool isTruthy() const;

	virtual bool isString() const;
	virtual AMF0String *asString();
	static  AMF0String *asString(AMF0 *amf);
	virtual const char *stringValue() const;

	virtual bool isObject() const;
	virtual AMF0Object *asObject();
	static  AMF0Object *asObject(AMF0 *amf);
	virtual std::shared_ptr<AMF0> getValueAtKey(const char *key) const;
	virtual std::shared_ptr<AMF0> getValueAtKey(const std::string &key) const;

	virtual bool isNull() const;
	virtual AMF0Null *asNull();
	static  AMF0Null *asNull(AMF0 *amf);

	virtual bool isUndefined() const;
	virtual AMF0Undefined *asUndefined();
	static  AMF0Undefined *asUndefined(AMF0 *amf);

	virtual bool isECMAArray() const;
	virtual AMF0ECMAArray *asECMAArray();
	static  AMF0ECMAArray *asECMAArray(AMF0 *amf);

	virtual bool isArray() const;
	virtual AMF0Array *asArray();
	static  AMF0Array *asArray(AMF0 *amf);
	virtual std::shared_ptr<AMF0> getValueAtIndex(uint32_t index) const;

	virtual bool isDate() const;
	virtual AMF0Date *asDate();
	static  AMF0Date *asDate(AMF0 *amf);

	virtual bool isXMLDocument() const;
	virtual AMF0XMLDocument *asXMLDocument();
	static  AMF0XMLDocument *asXMLDocument(AMF0 *amf);

	virtual bool isTypedObject() const;
	virtual AMF0TypedObject *asTypedObject();
	static  AMF0TypedObject *asTypedObject(AMF0 *amf);

	static bool decode(const uint8_t *cursor, const uint8_t *limit, std::vector<std::shared_ptr<AMF0>> &dst);
	static std::shared_ptr<AMF0> decode(const uint8_t **cursor_ptr, const uint8_t *limit);

	static Bytes encode(const AMF0 *v);
	virtual void encode(Bytes &dst) const = 0;

	static Bytes encode(const std::vector<std::shared_ptr<AMF0>> &values);
	static void encode(const std::vector<std::shared_ptr<AMF0>> &values, Bytes &dst);

	std::string repr() const;
	virtual void repr(std::string &dst, size_t depth) const = 0;

	std::shared_ptr<AMF0> duplicate() const;

protected:
	static std::shared_ptr<AMF0> decode(const uint8_t **cursor_ptr, const uint8_t *limit, size_t depth);

	virtual bool setFromEncoding(uint8_t typeMarker, const uint8_t **cursor_ptr, const uint8_t *limit, size_t depth) = 0;
};

class AMF0Number : public AMF0 {
public:
	AMF0Number();
	AMF0Number(double v);

	Type getType() const override;
	bool isNumber() const override;
	AMF0Number *asNumber() override;
	bool isTruthy() const override;

	double doubleValue() const override;
	void doubleValue(double v);

	using AMF0::repr;
	void repr(std::string &dst, size_t depth) const override;

	void encode(Bytes &dst) const override;

protected:
	bool setFromEncoding(uint8_t typeMarker, const uint8_t **cursor_ptr, const uint8_t *limit, size_t depth) override;

	double m_value;
};

class AMF0Boolean : public AMF0 {
public:
	AMF0Boolean();
	AMF0Boolean(bool v);

	Type getType() const override;
	bool isBoolean() const override;
	AMF0Boolean *asBoolean() override;
	bool isTruthy() const override;

	bool booleanValue() const override;
	void booleanValue(bool v);

	using AMF0::repr;
	void repr(std::string &dst, size_t depth) const override;

	void encode(Bytes &dst) const override;

protected:
	bool setFromEncoding(uint8_t typeMarker, const uint8_t **cursor_ptr, const uint8_t *limit, size_t depth) override;

	bool m_value;
};

class AMF0String : public AMF0 {
public:
	AMF0String() = default;
	AMF0String(const char *v);
	AMF0String(const std::string &v);

	Type getType() const override;
	bool isString() const override;
	AMF0String *asString() override;
	bool isTruthy() const override;

	const char *stringValue() const override;
	void stringValue(const char *v);
	size_t size() const;

	using AMF0::repr;
	void repr(std::string &dst, size_t depth) const override;

	void encode(Bytes &dst) const override;

	static bool decodeString(bool isLongString, const uint8_t **cursor_ptr, const uint8_t *limit, std::string &dst);

protected:
	bool setFromEncoding(uint8_t typeMarker, const uint8_t **cursor_ptr, const uint8_t *limit, size_t depth) override;

	std::string m_value;
};

class AMF0Object : public AMF0 {
public:
	using AMF0Map = std::map<std::string, std::shared_ptr<AMF0>>;

	AMF0Object() = default;

	Type getType() const override;
	bool isObject() const override;
	AMF0Object *asObject() override;
	bool isTruthy() const override;

	AMF0Object *putValueAtKey(AMF0 *value, const char *key);
	AMF0Object *putValueAtKey(const std::shared_ptr<AMF0> &value, const char *key);
	AMF0Object *putValueAtKey(const std::shared_ptr<AMF0> &value, const std::string &key);
	void erase(const char *key);
	void erase(const std::string &key);
	void clear();

	size_t size() const;
	bool has(const char *key) const;
	bool has(const std::string &key) const;

	using AMF0::getValueAtKey;
	std::shared_ptr<AMF0> getValueAtKey(const std::string &key) const override;

	AMF0Map::iterator begin();
	AMF0Map::const_iterator begin() const;

	AMF0Map::iterator end();
	AMF0Map::const_iterator end() const;

	using AMF0::repr;
	void repr(std::string &dst, size_t depth) const override;

	void encode(Bytes &dst) const override;

protected:
	void reprMembers(std::string &dst, size_t depth) const;
	void encodeMembers(Bytes &dst) const;
	bool setFromEncoding(uint8_t typeMarker, const uint8_t **cursor_ptr, const uint8_t *limit, size_t depth) override;

	AMF0Map m_members;
};

class AMF0TypedObject : public AMF0Object {
public:
	AMF0TypedObject(const char *class_name);

	Type getType() const override;
	bool isTypedObject() const override;
	AMF0TypedObject *asTypedObject() override;

	const char *className() const;

	using AMF0::repr;
	void repr(std::string &dst, size_t depth) const override;

	void encode(Bytes &dst) const override;

protected:
	friend class AMF0;
	AMF0TypedObject() = default;

	bool setFromEncoding(uint8_t typeMarker, const uint8_t **cursor_ptr, const uint8_t *limit, size_t depth) override;

	std::string m_class_name;
};

class AMF0ECMAArray : public AMF0Object {
public:
	AMF0ECMAArray() = default;

	Type getType() const override;
	bool isECMAArray() const override;
	AMF0ECMAArray *asECMAArray() override;

	void encode(Bytes &dst) const override;

protected:
	bool setFromEncoding(uint8_t typeMarker, const uint8_t **cursor_ptr, const uint8_t *limit, size_t depth) override;
};

class AMF0Null : public AMF0 {
public:
	AMF0Null() = default;

	Type getType() const override;
	bool isNull() const override;
	AMF0Null *asNull() override;

	using AMF0::repr;
	void repr(std::string &dst, size_t depth) const override;

	void encode(Bytes &dst) const override;

protected:
	bool setFromEncoding(uint8_t typeMarker, const uint8_t **cursor_ptr, const uint8_t *limit, size_t depth) override;
};

class AMF0Undefined : public AMF0 {
public:
	AMF0Undefined() = default;

	Type getType() const override;
	bool isUndefined() const override;
	AMF0Undefined *asUndefined() override;

	using AMF0::repr;
	void repr(std::string &dst, size_t depth) const override;

	void encode(Bytes &dst) const override;

protected:
	bool setFromEncoding(uint8_t typeMarker, const uint8_t **cursor_ptr, const uint8_t *limit, size_t depth) override;
};

class AMF0Array : public AMF0 {
public:
	AMF0Array() = default;

	Type getType() const override;
	bool isArray() const override;
	AMF0Array *asArray() override;
	bool isTruthy() const override;

	AMF0Array *putValueAtIndex(AMF0 *value, uint32_t index);
	AMF0Array *putValueAtIndex(const std::shared_ptr<AMF0> &value, uint32_t index);
	AMF0Array *appendValue(AMF0 *value);
	AMF0Array *appendValue(const std::shared_ptr<AMF0> &value);
	void resize(size_t newSize);
	void reset(uint32_t index);
	void remove(uint32_t fromIndex, size_t count);
	void clear();

	size_t size() const;
	std::shared_ptr<AMF0> getValueAtIndex(uint32_t index) const override;

	using AMF0::repr;
	void repr(std::string &dst, size_t depth) const override;

	void encode(Bytes &dst) const override;

protected:
	bool setFromEncoding(uint8_t typeMarker, const uint8_t **cursor_ptr, const uint8_t *limit, size_t depth) override;

	std::vector<std::shared_ptr<AMF0>> m_members;
};


} } } // namespace com::zenomt::rtmp
