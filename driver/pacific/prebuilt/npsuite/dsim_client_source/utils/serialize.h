// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
//
// This file and all technical concepts, proprietary knowledge, algorithms and
// intellectual property rights it contains (collectively the "Confidential Information"),
// are the sole propriety information of Cisco and shall remain at Cisco's ownership.
// You shall not disclose the Confidential Information to any third party and you
// shall use it solely in connection with operating and/or maintaining of Cisco's
// products and pursuant to the terms and conditions of the license agreement you
// entered into with Cisco.
//
// THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
// IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
// AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// END_LEGAL

#ifndef _SERIALIZE_H_
#define _SERIALIZE_H_

#undef DEBUG_SERIALIZER_ENABLED

#ifdef DEBUG_SERIALIZER_ENABLED
#define DEBUG_SERIALIZE(what) std::cerr << __FUNCTION__ << ": SERIALIZE:   " << what << std::endl;
#define DEBUG_DESERIALIZE(what) std::cerr << __FUNCTION__ << ": DESERIALIZE: " << what << std::endl;
#else
#define DEBUG_SERIALIZE(what)
#define DEBUG_DESERIALIZE(what)
#endif

#include <array>
#include <vector>
#include <list>
#include <map>
#include <string>
#include <sstream>
#include <iostream>

using namespace std;

//
// Create a wrapper template class that we can use generically to serialize
// anything that implements this template.
//
template <typename BaseType>
struct TypeWrapper {
    BaseType value;
};

template <typename BaseType>
static inline TypeWrapper<const BaseType&>
encapsulate_value(const BaseType& value)
{
    return TypeWrapper<const BaseType&>{value};
}

template <typename BaseType>
static inline TypeWrapper<BaseType&>
encapsulate_value(BaseType& value)
{
    return TypeWrapper<BaseType&>{value};
}

//
// Provide to_string extensions so we can use to_string with template types that
// may not have them.
//
static inline const std::string
to_string(const std::string& s)
{
    return s;
}

//
// Convert a container of to_string things to a string
//
template <class BaseType, template <typename Elem, typename Allocator = std::allocator<Elem>> class Container>
static inline const std::string
to_string(const Container<BaseType>& elems)
{
    std::string out = "[";
    for (const auto& elem : elems) {
        if (out.size() > 1) {
            out += ", ";
        }
        out += to_string(elem);
    }
    out += "]";
    return out;
}

//
// This is how long any individual serialized item can be
//
using serialize_length_t = uint32_t;

//
// Read the plain old data type given its size in bytes
//
template <typename BaseType>
static inline std::istream&
operator>>(std::istream& in, TypeWrapper<BaseType&> wrapped)
{
    in.read(reinterpret_cast<char*>(&wrapped.value), sizeof(BaseType));
    DEBUG_DESERIALIZE("pod " << sizeof(BaseType) << " bytes = " << to_string(wrapped.value))
    return in;
}

//
// Write the plain old data type given its size in bytes
//
template <typename BaseType>
static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<BaseType&> const wrapped)
{
    DEBUG_SERIALIZE("const pod " << sizeof(BaseType) << " bytes = " << to_string(wrapped.value))
    return out.write(reinterpret_cast<const char*>(&(wrapped.value)), sizeof(BaseType));
}

//
// Write the const std::string length and then the data
//
static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<const std::string&> const wrapped)
{
    DEBUG_SERIALIZE("const std::string '" << wrapped.value << "'")
    serialize_length_t len = static_cast<serialize_length_t>(wrapped.value.size());
    return out << encapsulate_value(len) << wrapped.value;
}

//
// Write the std::string length and then the data
//
static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<std::string&> const wrapped)
{
    DEBUG_SERIALIZE("std::string '" << wrapped.value << "'")
    serialize_length_t len = static_cast<serialize_length_t>(wrapped.value.size());
    return out << encapsulate_value(len) << wrapped.value;
}

//
// Read the std::string length and then the data
//
static inline std::istream&
operator>>(std::istream& in, TypeWrapper<std::string&> wrapped)
{
    serialize_length_t len{};
    in >> encapsulate_value(len);
    if (len) {
        std::vector<char> string_buf(len);
        in.read(string_buf.data(), len);
        wrapped.value.assign(string_buf.data(), len);
        DEBUG_DESERIALIZE("std::string '" << wrapped.value << "'")
    }

    return in;
}

/////////////////////////////////////////////////////////////////////////////////////////////
// std::array support
/////////////////////////////////////////////////////////////////////////////////////////////

//
// Read the std::array length and then each elem.
//
template <class BaseType, std::size_t ArraySize, template <typename ArrayElem, std::size_t> class ArrayContainer>
static inline std::istream&
operator>>(std::istream& in, TypeWrapper<ArrayContainer<BaseType, ArraySize>&> wrapped)
{
    serialize_length_t num_elems{};
    in >> encapsulate_value(num_elems);
    DEBUG_DESERIALIZE("std::array <> [" << num_elems << " elems]")
    if (num_elems) {
        for (auto idx = 0U; idx < num_elems; idx++) {
            BaseType elem;
            in >> encapsulate_value(elem);
            DEBUG_DESERIALIZE("std::array <> [" << idx << "] = " << to_string(elem))
            wrapped.value[idx] = elem;
        }
    }

    return in;
}

//
// Write the const std::array length and then each elem.
//
template <class BaseType, std::size_t ArraySize, template <typename ArrayElem, std::size_t> class ArrayContainer>
static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<const ArrayContainer<BaseType, ArraySize>&> const wrapped)
{
    serialize_length_t num_elems = static_cast<serialize_length_t>(wrapped.value.size());
    DEBUG_SERIALIZE("std::array <> [" << num_elems << " elems]")
    out << encapsulate_value(num_elems);
    auto idx = 0U;
    for (const auto& elem : wrapped.value) {
        DEBUG_SERIALIZE("std::array <> [" << idx << "] = " << to_string(elem))
        out << encapsulate_value(elem);
        idx++;
    }
    return (out);
}

//
// Write the std::array length and then each elem.
//
template <class BaseType, std::size_t ArraySize, template <typename ArrayElem, std::size_t> class ArrayContainer>
static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<ArrayContainer<BaseType, ArraySize>&> const wrapped)
{
    serialize_length_t num_elems = static_cast<serialize_length_t>(wrapped.value.size());
    DEBUG_SERIALIZE("std::array <> [" << num_elems << " elems]")
    out << encapsulate_value(num_elems);
    auto idx = 0U;
    for (const auto elem : wrapped.value) {
        DEBUG_SERIALIZE("std::array <> [" << idx << "] = " << to_string(elem));
        out << encapsulate_value(elem);
        idx++;
    }
    return (out);
}

/////////////////////////////////////////////////////////////////////////////////////////////
// std::vector / std:list support
/////////////////////////////////////////////////////////////////////////////////////////////

template <class BaseType, template <typename Elem, typename Allocator = std::allocator<Elem>> class Container>
static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<Container<BaseType>&> const wrapped)
{
    serialize_length_t num_elems = static_cast<serialize_length_t>(wrapped.value.size());
    DEBUG_SERIALIZE("std::container <> [" << num_elems << " elems]")
    out << encapsulate_value(num_elems);
    auto idx = 0U;
    for (const auto& elem : wrapped.value) {
        DEBUG_SERIALIZE("std::container <> [" << idx << "] = " << to_string(elem));
        out << encapsulate_value(elem);
        idx++;
    }
    return (out);
}

template <class BaseType, template <typename Elem, typename Allocator = std::allocator<Elem>> class Container>
static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<const Container<BaseType>&> const wrapped)
{
    serialize_length_t num_elems = static_cast<serialize_length_t>(wrapped.value.size());
    DEBUG_SERIALIZE("std::container <> [" << num_elems << " elems]")
    out << encapsulate_value(num_elems);
    auto idx = 0U;
    for (const auto& elem : wrapped.value) {
        DEBUG_SERIALIZE("std::container <> [" << idx << "] = " << to_string(elem));
        out << encapsulate_value(elem);
        idx++;
    }
    return (out);
}

template <class BaseType, template <typename Elem, typename Allocator = std::allocator<Elem>> class Container>
static inline std::istream&
operator>>(std::istream& in, TypeWrapper<Container<BaseType>&> wrapped)
{
    serialize_length_t num_elems = 0U;
    in >> encapsulate_value(num_elems);
    DEBUG_DESERIALIZE("std::container <> [" << num_elems << " elems]")
    if (in && num_elems) {
        auto idx = 0U;
        while (num_elems--) {
            BaseType elem;
            in >> encapsulate_value(elem);
            DEBUG_DESERIALIZE("std::container <> [" << idx << "] = " << to_string(elem));
            wrapped.value.push_back(elem);
            idx++;
        }
    }

    return in;
}

/////////////////////////////////////////////////////////////////////////////////////////////
// std::pair support
/////////////////////////////////////////////////////////////////////////////////////////////

template <typename K, typename V>
static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<std::pair<K, V>&> const wrapped)
{
    DEBUG_SERIALIZE("std::pair <K, V>")
    out << encapsulate_value(wrapped.value.first);
    out << encapsulate_value(wrapped.value.second);
    return (out);
}

template <typename K, typename V>
static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<const std::pair<K, V>&> const wrapped)
{
    DEBUG_SERIALIZE("const std::pair <K, V>")
    out << encapsulate_value(wrapped.value.first);
    out << encapsulate_value(wrapped.value.second);
    return (out);
}

template <typename K, typename V>
static inline std::istream&
operator>>(std::istream& in, TypeWrapper<std::pair<K, V>&> wrapped)
{
    DEBUG_DESERIALIZE("std::pair <K, V>")
    in >> encapsulate_value(wrapped.value.first);
    in >> encapsulate_value(wrapped.value.second);
    return in;
}

/////////////////////////////////////////////////////////////////////////////////////////////
// std::map support
/////////////////////////////////////////////////////////////////////////////////////////////

template <template <class K, class V, class Compare = std::less<K>, class Alloc = std::allocator<std::pair<const K, V>>> class M,
          class K,
          class V>

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<M<K, V>&> const wrapped)
{
    serialize_length_t num_elems = static_cast<serialize_length_t>(wrapped.value.size());
    DEBUG_SERIALIZE("std::map<K,V> " << num_elems << " elems")
    out << encapsulate_value(num_elems);
    for (auto i : wrapped.value) {
        out << encapsulate_value(i.first) << encapsulate_value(i.second);
    }
    return (out);
}

template <template <class K, class V, class Compare = std::less<K>, class Alloc = std::allocator<std::pair<const K, V>>> class M,
          class K,
          class V>

static inline std::istream&
operator>>(std::istream& in, TypeWrapper<M<K, V>&> wrapped)
{
    K k;
    V v;
    serialize_length_t num_elems = 0;
    in >> encapsulate_value(num_elems);
    DEBUG_DESERIALIZE("std::map<K,V> " << num_elems << " elems")
    if (in && num_elems) {
        while (num_elems--) {
            in >> encapsulate_value(k) >> encapsulate_value(v);
            wrapped.value.insert(std::make_pair(k, v));
        }
    }

    return in;
}

#endif
