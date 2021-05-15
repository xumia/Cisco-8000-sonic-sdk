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

#ifndef __NSIM_PORT_CONFIG_SERIALIZERS_H__
#define __NSIM_PORT_CONFIG_SERIALIZERS_H__

#include <vector>
#include <string>

#include "nsim_port_config.h"
#include "utils/serialize.h"

//
// Serializer for nsim_port_info_lane_t
//
static inline std::ostream&
serialize_bit_vector(std::ostream& out, const nsim_port_info_lane_t& s)
{
    uint32_t tmp;
    tmp = static_cast<uint32_t>(s.lane_base);
    out << encapsulate_value(tmp);
    tmp = static_cast<uint32_t>(s.lane_size);
    out << encapsulate_value(tmp);
    return out;
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<const nsim_port_info_lane_t&> wrapped)
{
    DEBUG_SERIALIZE("const nsim_port_info_lane_t")
    return serialize_bit_vector(out, wrapped.value);
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<nsim_port_info_lane_t&> wrapped)
{
    DEBUG_SERIALIZE("nsim_port_info_lane_t")
    return serialize_bit_vector(out, wrapped.value);
}

//
// Deserializer for nsim_port_info_lane_t
//
static inline std::istream&
operator>>(std::istream& in, TypeWrapper<nsim_port_info_lane_t&> wrapped)
{
    DEBUG_DESERIALIZE("nsim_port_info_lane_t")
    uint32_t tmp;
    in >> encapsulate_value(tmp);
    wrapped.value.lane_base = static_cast<size_t>(tmp);
    in >> encapsulate_value(tmp);
    wrapped.value.lane_size = static_cast<size_t>(tmp);
    return in;
}

static inline std::string
to_string(const nsim_port_info_lane_t& s)
{
    return "(lane base:" + std::to_string(s.lane_base) + ", lane size:" + std::to_string(s.lane_size) + ")";
}

//
// Serializer for nsim_port_pif_config_t
//
static inline std::ostream&
serialize_bit_vector(std::ostream& out, const nsim_port_pif_config_t& s)
{
    out << encapsulate_value(s.valid);
    uint32_t tmp;
    tmp = static_cast<uint32_t>(s.pif);
    out << encapsulate_value(tmp);
    out << encapsulate_value(s.tx);
    out << encapsulate_value(s.rx);
    return out;
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<const nsim_port_pif_config_t&> wrapped)
{
    DEBUG_SERIALIZE("const nsim_port_pif_config_t")
    return serialize_bit_vector(out, wrapped.value);
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<nsim_port_pif_config_t&> wrapped)
{
    DEBUG_SERIALIZE("nsim_port_pif_config_t")
    return serialize_bit_vector(out, wrapped.value);
}

//
// Deserializer for nsim_port_pif_config_t
//
static inline std::istream&
operator>>(std::istream& in, TypeWrapper<nsim_port_pif_config_t&> wrapped)
{
    DEBUG_DESERIALIZE("nsim_port_pif_config_t")
    in >> encapsulate_value(wrapped.value.valid);
    uint32_t tmp;
    in >> encapsulate_value(tmp);
    wrapped.value.pif = static_cast<size_t>(tmp);
    in >> encapsulate_value(wrapped.value.tx);
    in >> encapsulate_value(wrapped.value.rx);
    return in;
}

static inline std::string
to_string(const nsim_port_pif_config_t& s)
{
    return "(valid:" + std::to_string(s.valid) + ", pif:" + std::to_string(s.pif) + ", tx:" + to_string(s.tx)
           + ", rx:" + to_string(s.rx) + ")";
}

//
// Serializer for nsim_port_config_t
//
static inline std::ostream&
serialize_bit_vector(std::ostream& out, const nsim_port_config_t& s)
{
    uint32_t tmp;
    tmp = static_cast<uint32_t>(s.slice);
    out << encapsulate_value(tmp);
    tmp = static_cast<uint32_t>(s.ifg);
    out << encapsulate_value(tmp);
    out << encapsulate_value(s.pif_config);
    return out;
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<const nsim_port_config_t&> wrapped)
{
    DEBUG_SERIALIZE("const nsim_port_config_t")
    return serialize_bit_vector(out, wrapped.value);
}

static inline std::ostream&
operator<<(std::ostream& out, TypeWrapper<nsim_port_config_t&> wrapped)
{
    DEBUG_SERIALIZE("nsim_port_config_t")
    return serialize_bit_vector(out, wrapped.value);
}

//
// Deserializer for nsim_port_config_t
//
static inline std::istream&
operator>>(std::istream& in, TypeWrapper<nsim_port_config_t&> wrapped)
{
    DEBUG_DESERIALIZE("nsim_port_config_t")
    uint32_t tmp;
    in >> encapsulate_value(tmp);
    wrapped.value.slice = static_cast<size_t>(tmp);
    in >> encapsulate_value(tmp);
    wrapped.value.ifg = static_cast<size_t>(tmp);
    in >> encapsulate_value(wrapped.value.pif_config);
    return in;
}

static inline std::string
to_string(const nsim_port_config_t& s)
{
    return "(slice:" + std::to_string(s.slice) + ", ifg:" + std::to_string(s.ifg) + ", config:" + to_string(s.pif_config) + ")";
}

#endif
