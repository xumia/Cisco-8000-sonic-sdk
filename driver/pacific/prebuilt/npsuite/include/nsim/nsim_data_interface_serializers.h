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

#ifndef __NSIM_DATA_INTERFACE_SERIALIZERS_H__
#define __NSIM_DATA_INTERFACE_SERIALIZERS_H__

#include <list>
#include <map>
#include <string>
#include <iostream>

#include "utils/nsim_bv.h"
#include "nsim/nsim_data_interface.h" // for nsim_packet_info_t, nsim_db_trigger_info_t
#include "utils/serialize.h"

namespace nsim
{

//
// packet_statistics_database_access_t Serializer
//
static inline std::ostream&
serialize_packet_statistics_database_access_t(std::ostream& out, const class packet_statistics_database_access_t& s)
{
    out << encapsulate_value(s.m_table_name);
    out << encapsulate_value(s.m_database_name);
    out << encapsulate_value(s.m_incoming_interface);
    out << encapsulate_value(s.m_outgoing_interface);
    return out;
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<const class packet_statistics_database_access_t&> const wrapped)
{
    DEBUG_SERIALIZE("const packet_statistics_database_access_t")
    return serialize_packet_statistics_database_access_t(out, wrapped.value);
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<class packet_statistics_database_access_t&> const wrapped)
{
    DEBUG_SERIALIZE("packet_statistics_database_access_t")
    return serialize_packet_statistics_database_access_t(out, wrapped.value);
}

//
// packet_statistics_database_access_t Deserializer
//
static inline std::istream&
operator>>(std::istream& in, TypeWrapper<class packet_statistics_database_access_t&> wrapped)
{
    DEBUG_DESERIALIZE("packet_statistics_database_access_t")
    in >> encapsulate_value(wrapped.value.m_table_name);
    in >> encapsulate_value(wrapped.value.m_database_name);
    in >> encapsulate_value(wrapped.value.m_incoming_interface);
    in >> encapsulate_value(wrapped.value.m_outgoing_interface);
    return in;
}

//
// packet_statistics_macro_t Serializer
//
static inline std::ostream&
serialize_packet_statistics_macro_t(std::ostream& out, const class packet_statistics_macro_t& s)
{
    out << encapsulate_value(s.m_macro_name);
    out << encapsulate_value(s.m_database_accesses);
    return out;
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<const class packet_statistics_macro_t&> const wrapped)
{
    DEBUG_SERIALIZE("const packet_statistics_macro_t")
    return serialize_packet_statistics_macro_t(out, wrapped.value);
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<class packet_statistics_macro_t&> const wrapped)
{
    DEBUG_SERIALIZE("packet_statistics_macro_t")
    return serialize_packet_statistics_macro_t(out, wrapped.value);
}

//
// packet_statistics_macro_t Deserializer
//
static inline std::istream&
operator>>(std::istream& in, TypeWrapper<class packet_statistics_macro_t&> wrapped)
{
    DEBUG_DESERIALIZE("packet_statistics_macro_t")
    in >> encapsulate_value(wrapped.value.m_macro_name);
    in >> encapsulate_value(wrapped.value.m_database_accesses);
    return in;
}

//
// packet_statistics_engine_t Serializer
//
static inline std::ostream&
serialize_packet_statistics_engine_t(std::ostream& out, const class packet_statistics_engine_t& s)
{
    out << encapsulate_value(s.m_engine_name);
    out << encapsulate_value(s.m_is_hardware_npl);
    out << encapsulate_value(s.m_executed_macros);
    return out;
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<const class packet_statistics_engine_t&> const wrapped)
{
    DEBUG_SERIALIZE("const packet_statistics_engine_t")
    return serialize_packet_statistics_engine_t(out, wrapped.value);
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<class packet_statistics_engine_t&> const wrapped)
{
    DEBUG_SERIALIZE("packet_statistics_engine_t")
    return serialize_packet_statistics_engine_t(out, wrapped.value);
}

//
// packet_statistics_engine_t Deserializer
//
static inline std::istream&
operator>>(std::istream& in, TypeWrapper<class packet_statistics_engine_t&> wrapped)
{
    DEBUG_DESERIALIZE("packet_statistics_engine_t")
    in >> encapsulate_value(wrapped.value.m_engine_name);
    in >> encapsulate_value(wrapped.value.m_is_hardware_npl);
    in >> encapsulate_value(wrapped.value.m_executed_macros);
    return in;
}

//
// packet_statistics_pass_t Serializer
//
static inline std::ostream&
serialize_packet_statistics_pass_t(std::ostream& out, const class packet_statistics_pass_t& s)
{
    out << encapsulate_value(s.m_engines);
    return out;
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<const class packet_statistics_pass_t&> const wrapped)
{
    DEBUG_SERIALIZE("const packet_statistics_pass_t")
    return serialize_packet_statistics_pass_t(out, wrapped.value);
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<class packet_statistics_pass_t&> const wrapped)
{
    DEBUG_SERIALIZE("packet_statistics_pass_t")
    return serialize_packet_statistics_pass_t(out, wrapped.value);
}

//
// packet_statistics_pass_t Deserializer
//
static inline std::istream&
operator>>(std::istream& in, TypeWrapper<class packet_statistics_pass_t&> wrapped)
{
    DEBUG_DESERIALIZE("packet_statistics_pass_t")
    in >> encapsulate_value(wrapped.value.m_engines);
    return in;
}

//
// packet_statistics_t Serializer
//
static inline std::ostream&
serialize_packet_statistics_t(std::ostream& out, const class packet_statistics_t& s)
{
    out << encapsulate_value(s.m_thread_id);
    out << encapsulate_value(s.m_packet_id);
    out << encapsulate_value(s.m_passes);
    return out;
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<const class packet_statistics_t&> const wrapped)
{
    DEBUG_SERIALIZE("const packet_statistics_t")
    return serialize_packet_statistics_t(out, wrapped.value);
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<class packet_statistics_t&> const wrapped)
{
    DEBUG_SERIALIZE("packet_statistics_t")
    return serialize_packet_statistics_t(out, wrapped.value);
}

//
// packet_statistics_t Deserializer
//
static inline std::istream&
operator>>(std::istream& in, TypeWrapper<class packet_statistics_t&> wrapped)
{
    DEBUG_DESERIALIZE("packet_statistics_t")
    in >> encapsulate_value(wrapped.value.m_thread_id);
    in >> encapsulate_value(wrapped.value.m_packet_id);
    in >> encapsulate_value(wrapped.value.m_passes);
    return in;
}

//
// Serializer
//
static inline std::ostream&
serialize_nsim_packet_info_t(std::ostream& out, const struct nsim_packet_info_t& s)
{
    out << encapsulate_value(s.m_packet_data.to_string_without_leading_0x());
    out << encapsulate_value(static_cast<uint32_t>(s.m_slice_id)); // Use fixed size for serialization instead of size_t
    out << encapsulate_value(static_cast<uint32_t>(s.m_ifg));
    out << encapsulate_value(static_cast<uint32_t>(s.m_pif));
    out << encapsulate_value(s.m_should_dump_state);
    out << encapsulate_value(s.m_packet_statistics);
    return out;
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<const struct nsim_packet_info_t&> wrapped)
{
    DEBUG_SERIALIZE("const nsim_packet_info_t")
    return serialize_nsim_packet_info_t(out, wrapped.value);
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<struct nsim_packet_info_t&> wrapped)
{
    DEBUG_SERIALIZE("nsim_packet_info_t")
    return serialize_nsim_packet_info_t(out, wrapped.value);
}

//
// Deserializer
//
static inline std::istream&
operator>>(std::istream& in, TypeWrapper<struct nsim_packet_info_t&> wrapped)
{
    uint32_t tmp32; // Use fixed size for serialization instead of size_t
    std::string tmp;
    DEBUG_DESERIALIZE("nsim_packet_info_t")
    in >> encapsulate_value(tmp);
    wrapped.value.m_packet_data = bit_vector(
        tmp, tmp.size() * 4 /* bits */); // Need to preserve any leading zeros of the packet, hence providing a size to the vector
    in >> encapsulate_value(tmp32);
    wrapped.value.m_slice_id = tmp32;
    in >> encapsulate_value(tmp32);
    wrapped.value.m_ifg = tmp32;
    in >> encapsulate_value(tmp32);
    wrapped.value.m_pif = tmp32;
    in >> encapsulate_value(wrapped.value.m_should_dump_state);
    in >> encapsulate_value(wrapped.value.m_packet_statistics);
    return in;
}

//
// Serializer
//
static inline std::ostream&
serialize_nsim_db_trigger_info_t(std::ostream& out, const struct nsim_db_trigger_info_t& s)
{
    out << encapsulate_value(static_cast<uint32_t>(s.m_line_id)); // Use fixed size for serialization instead of size_t
    out << encapsulate_value(static_cast<uint32_t>(s.m_trigger_type));
    out << encapsulate_value(static_cast<uint32_t>(s.m_mp_type));
    return out;
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<const struct nsim_db_trigger_info_t&> const wrapped)
{
    DEBUG_SERIALIZE("const nsim_db_trigger_info_t")
    return serialize_nsim_db_trigger_info_t(out, wrapped.value);
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<struct nsim_db_trigger_info_t&> const wrapped)
{
    DEBUG_SERIALIZE("nsim_db_trigger_info_t")
    return serialize_nsim_db_trigger_info_t(out, wrapped.value);
}

//
// Deserializer
//
static inline std::istream&
operator>>(std::istream& in, TypeWrapper<struct nsim_db_trigger_info_t&> wrapped)
{
    uint32_t tmp_uint32; // Use fixed size for serialization instead of size_t
    DEBUG_DESERIALIZE("nsim_db_trigger_info_t")
    in >> encapsulate_value(tmp_uint32);
    wrapped.value.m_line_id = tmp_uint32;
    in >> encapsulate_value(tmp_uint32);
    wrapped.value.m_trigger_type = tmp_uint32;
    in >> encapsulate_value(tmp_uint32);
    wrapped.value.m_mp_type = tmp_uint32;
    return in;
}

} // namespace nsim

#endif
