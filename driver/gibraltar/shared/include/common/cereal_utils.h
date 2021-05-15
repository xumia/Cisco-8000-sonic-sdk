// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __CEREAL_UTILS_H__
#define __CEREAL_UTILS_H__
#include "api/types/la_common_types.h"
namespace cereal
{

// template class that is added as friend in order to allow access to private members of the class
// this class is later specialized in the auto-generated code, and all access to class members
// are done from inside that class
template <class Type>
class serializer_class
{
};

// forward-declaration of cereal class used for accessing private constructors
class access;

// forward declaration of all archives so we can choose them as serializers
class JSONOutputArchive;
class JSONInputArchive;
class BinaryOutputArchive;
class BinaryInputArchive;
class XMLOutputArchive;
class XMLInputArchive;

// this is a non-existing forward declaration to overcome the error:
// error: no function named '...' with type '...' was found in the specified scope
// when using the macro CEREAL_SUPPORT_PRIVATE_CLASS for private classes support
class cereal_dummy_archive;
template <class Type>
void save(cereal_dummy_archive&, Type&);
template <class Type>
void load(cereal_dummy_archive&, Type&);
template <class Archive>
static void force_serialization(Archive&);

// Disallow 'long double' serialization due to security vulnerabilities.
// By defining an empty serialize function for 'long double' Cereal will fail at
// compile time due to the existance of multiple serialization functions.
// For more details about the security vulnerability see issue: CSCvv40905
template <class Archive>
void
serialize(Archive&, long double&)
{
}

// la_uint128_t is not supported by Cereal
template <class Archive>
void
serialize(Archive& ar, la_uint128_t& m)
{
    la_uint64_t* mp = (la_uint64_t*)&m;
    ar(mp[0], mp[1]);
}

// C timespec is not supported by Cereal
template <class Archive>
void
save(Archive& ar, const struct timespec& ts)
{
    ar(ts.tv_sec);
    ar(ts.tv_nsec);
}

template <class Archive>
void
load(Archive& ar, struct timespec& ts)
{
    ar(ts.tv_sec);
    ar(ts.tv_nsec);
}

} // namespace cereal

// the following are for allowing easy switching between different archives
#define CEREAL_MODE_BINARY 0
#define CEREAL_MODE_JSON 1
#define CEREAL_MODE_XML 2

#ifndef CEREAL_MODE
#define CEREAL_MODE CEREAL_MODE_BINARY
#endif

#if CEREAL_MODE == CEREAL_MODE_BINARY

using cereal_output_archive_class = ::cereal::BinaryOutputArchive;
#define CEREAL_OUTPUT_STREAM_MODE_FLAGS std::ios::out | std::ios::binary
#define CEREAL_UTILS_CREATE_OUTPUT_ARCHIVE(var_name, output_stream) cereal_output_archive_class var_name(output_stream)
using cereal_input_archive_class = ::cereal::BinaryInputArchive;
#define CEREAL_INPUT_STREAM_MODE_FLAGS std::ios::in | std::ios::binary

#elif CEREAL_MODE == CEREAL_MODE_JSON

using cereal_output_archive_class = ::cereal::JSONOutputArchive;
#define CEREAL_OUTPUT_STREAM_MODE_FLAGS std::ios::out
#define CEREAL_UTILS_CREATE_OUTPUT_ARCHIVE(var_name, output_stream)                                                                \
    cereal_output_archive_class var_name(output_stream, cereal::JSONOutputArchive::Options::NoIndent())
using cereal_input_archive_class = ::cereal::JSONInputArchive;
#define CEREAL_INPUT_STREAM_MODE_FLAGS std::ios::in

#elif CEREAL_MODE == CEREAL_MODE_XML

using cereal_output_archive_class = ::cereal::XMLOutputArchive;
#define CEREAL_OUTPUT_STREAM_MODE_FLAGS std::ios::out
#define CEREAL_UTILS_CREATE_OUTPUT_ARCHIVE(var_name, output_stream)                                                                \
    cereal_output_archive_class(output_stream, cereal::XMLOutputArchive::Options::Default().indent(false).outputType(false))
using cereal_input_archive_class = ::cereal::XMLInputArchive;
#define CEREAL_INPUT_STREAM_MODE_FLAGS std::ios::in

#else

#error "unknown cereal mode!!!"

#endif

#if defined(__GNUC__) && !defined(__clang__)
// on gcc there seems to be a problem when declaring template friend function inside the class
// when it's done, cereal is not able to find the proper serialization function.
#define CEREAL_SUPPORT_PRIVATE_CLASS(INNER_CLASS)
#else
#define CEREAL_SUPPORT_PRIVATE_CLASS(INNER_CLASS)                                                                                  \
    template <class Archive>                                                                                                       \
    friend void ::cereal::save(Archive&, const INNER_CLASS&);                                                                      \
    template <class Archive>                                                                                                       \
    friend void ::cereal::load(Archive&, INNER_CLASS&);
#endif

#define CEREAL_SUPPORT_PRIVATE_MEMBERS                                                                                             \
    template <class Type>                                                                                                          \
    friend class cereal::serializer_class;                                                                                         \
    friend class cereal::access;                                                                                                   \
    template <class Archive>                                                                                                       \
    friend void ::cereal::force_serialization(Archive&);

#endif // __CEREAL_UTILS_H__
