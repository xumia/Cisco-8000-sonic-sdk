// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __NSIM_BV_SERIALIZERS_H__
#define __NSIM_BV_SERIALIZERS_H__

#include <list>
#include <string>

#include "utils/nsim_bv.h"
#include "utils/serialize.h"

namespace nsim
{

//
// Serializer
//
static inline std::ostream&
serialize_bit_vector(std::ostream& out, const class bit_vector& s)
{
    std::vector<uint64_t> bits;
    uint32_t width;
    s.get(bits, width);
    out << encapsulate_value(width);
    out << encapsulate_value(bits);
    return out;
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<const class bit_vector&> wrapped)
{
    DEBUG_SERIALIZE("const bit_vector")
    return serialize_bit_vector(out, wrapped.value);
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<class bit_vector&> wrapped)
{
    DEBUG_SERIALIZE("bit_vector")
    return serialize_bit_vector(out, wrapped.value);
}

//
// Deserializer
//
static inline std::istream&
operator>>(std::istream& in, TypeWrapper<class bit_vector&> wrapped)
{
    DEBUG_DESERIALIZE("bit_vector")
    std::vector<uint64_t> bits;
    uint32_t width;
    in >> encapsulate_value(width);
    in >> encapsulate_value(bits);
    wrapped.value.set(bits, width);
    return in;
}

static inline std::string
to_string(const class bit_vector& s)
{
    return s.to_string();
}

} // namespace nsim

#endif
