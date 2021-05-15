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

#ifndef __NSIM_CONTROL_INTERFACE_SERIALIZERS_H__
#define __NSIM_CONTROL_INTERFACE_SERIALIZERS_H__

#include <string>
#include "nsim/nsim_control_interface.h"
#include "utils/serialize.h"

namespace nsim
{

//
// Serializer
//
static inline std::ostream&
serialize_nsim_source_location_info_t(std::ostream& out, const struct nsim_source_location_info_t& s)
{
    out << encapsulate_value(s.m_scope);
    out << encapsulate_value(s.m_file_name);
    out << encapsulate_value(static_cast<uint32_t>(s.m_line_number));
    return out;
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<const struct nsim_source_location_info_t&> wrapped)
{
    DEBUG_SERIALIZE("const nsim_source_location_info_t")
    return serialize_nsim_source_location_info_t(out, wrapped.value);
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<struct nsim_source_location_info_t&> wrapped)
{
    DEBUG_SERIALIZE("nsim_source_location_info_t")
    return serialize_nsim_source_location_info_t(out, wrapped.value);
}

//
// Deserializer
//
static inline std::istream&
operator>>(std::istream& in, TypeWrapper<struct nsim_source_location_info_t&> wrapped)
{
    uint32_t tmp_uint32; // Use fixed size for serialization instead of size_t
    DEBUG_DESERIALIZE("nsim_source_location_info_t")
    in >> encapsulate_value(wrapped.value.m_scope);
    in >> encapsulate_value(wrapped.value.m_file_name);
    in >> encapsulate_value(tmp_uint32);
    wrapped.value.m_line_number = tmp_uint32;
    return in;
}

} // namespace nsim

#endif
