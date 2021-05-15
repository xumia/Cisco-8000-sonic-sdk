// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "common/common_strings.h"
#include "common/gen_utils.h"

#include <sstream>

namespace silicon_one
{

std::string
to_string(bool value)
{
    return (value ? "true" : "false");
}

std::string
to_hex_string(int value)
{
    std::stringstream stream;
    stream << std::hex << value;

    return stream.str();
}

std::string
to_string(la_serdes_direction_e direction)
{

    static const char* strs[] = {
            [(int)la_serdes_direction_e::RX] = "RX", [(int)la_serdes_direction_e::TX] = "TX",
    };

    if ((size_t)direction < array_size(strs)) {
        return std::string(strs[(size_t)direction]);
    }

    return "Unknown SerDes direction";
}

std::string
to_string(la_mac_port::port_debug_info_e info_type)
{
    switch (info_type) {
    case la_mac_port::port_debug_info_e::MAC_STATUS:
        return "MAC_STATUS";
    case la_mac_port::port_debug_info_e::SERDES_STATUS:
        return "SERDES_STATUS";
    case la_mac_port::port_debug_info_e::SERDES_CONFIG:
        return "SERDES_CONFIG";
    case la_mac_port::port_debug_info_e::SERDES_EYE_CAPTURE:
        return "SERDES_EYE_CAPTURE";
    case la_mac_port::port_debug_info_e::SERDES_REG_DUMP:
        return "SERDES_REG_DUMP";
    case la_mac_port::port_debug_info_e::ALL:
        return "ALL";
    case la_mac_port::port_debug_info_e::SERDES_EXTENDED_DEBUG:
        return "SERDES_EXTENDED_DEBUG";
    default:
        return "Unknown port debug type";
    }

    return "Unknown port debug type";
}

std::string
to_string(la_slice_id_t slice_id, la_ifg_id_t ifg_id, la_uint_t serdes_idx)
{
    std::stringstream stream;

    stream << std::to_string(slice_id) << "/" << std::to_string(ifg_id) << "/" << std::to_string(serdes_idx);

    return stream.str();
}

std::string
to_string(la_mem_protect_error_e mem_protect_error)
{
    static const char* strs[] = {
            [(int)la_mem_protect_error_e::ECC_1B] = "ECC_1B",
            [(int)la_mem_protect_error_e::ECC_2B] = "ECC_2B",
            [(int)la_mem_protect_error_e::PARITY] = "PARITY",
    };

    if ((size_t)mem_protect_error < array_size(strs)) {
        return strs[(size_t)mem_protect_error];
    }

    return "Unknown mem_protect error";
}

std::string
to_string(dram_corrupted_buffer val)
{
    std::stringstream ss;

    ss << "{bank_base=" << val.bank_base << ", channel_base=" << val.channel_base << ", row=" << val.row
       << ", column=" << val.column << ", bad_cells=" << std::hex << val.bad_cells << "}";

    return ss.str();
}

std::string
to_string(la_device_family_e family)
{
    static const char* strs[] = {
            [(size_t)la_device_family_e::NONE] = "NONE",
            [(size_t)la_device_family_e::PACIFIC] = "PACIFIC",
            [(size_t)la_device_family_e::GIBRALTAR] = "GIBRALTAR",
            [(size_t)la_device_family_e::ASIC4] = "ASIC4",
            [(size_t)la_device_family_e::ASIC3] = "ASIC3",
            [(size_t)la_device_family_e::ASIC7] = "ASIC7",
            [(size_t)la_device_family_e::ASIC5] = "ASIC5",
    };

    static_assert(array_size(strs) == (size_t)la_device_family_e::LAST + 1, "");

    if ((size_t)family < array_size(strs)) {
        return strs[(size_t)family];
    }

    return "Unknown device family";
}

std::string
to_string(la_device_revision_e revision)
{
    static const char* strs[] = {
            [(size_t)la_device_revision_e::NONE] = "NONE",
            [(size_t)la_device_revision_e::PACIFIC_A0] = "PACIFIC_A0",
            [(size_t)la_device_revision_e::PACIFIC_B0] = "PACIFIC_B0",
            [(size_t)la_device_revision_e::PACIFIC_B1] = "PACIFIC_B1",
            [(size_t)la_device_revision_e::GIBRALTAR_A0] = "GIBRALTAR_A0",
            [(size_t)la_device_revision_e::GIBRALTAR_A1] = "GIBRALTAR_A1",
            [(size_t)la_device_revision_e::GIBRALTAR_A2] = "GIBRALTAR_A2",
            [(size_t)la_device_revision_e::ASIC4_A0] = "ASIC4_A0",
            [(size_t)la_device_revision_e::ASIC3_A0] = "ASIC3_A0",
            [(size_t)la_device_revision_e::ASIC7_A0] = "ASIC7_A0",
            [(size_t)la_device_revision_e::ASIC5_A0] = "ASIC5_A0",
    };

    static_assert(array_size(strs) == (size_t)la_device_revision_e::LAST + 1, "");

    if ((size_t)revision < array_size(strs)) {
        return strs[(size_t)revision];
    }

    return "Unknown device revision";
}

std::string
to_string(la_resource_descriptor::type_e resource_type)
{

    static const char* strs[]
        = {[(size_t)la_resource_descriptor::type_e::AC_PROFILE] = "AC_PROFILE",
           [(size_t)la_resource_descriptor::type_e::ACL_GROUP] = "ACL_GROUP",
           [(size_t)la_resource_descriptor::type_e::CENTRAL_EM] = "CENTRAL_EM",
           [(size_t)la_resource_descriptor::type_e::COUNTER_BANK] = "COUNTER_BANK",
           [(size_t)la_resource_descriptor::type_e::EGRESS_ENC_EM0] = "EGRESS_ENC_EM0",
           [(size_t)la_resource_descriptor::type_e::EGRESS_ENC_EM1] = "EGRESS_ENC_EM1",
           [(size_t)la_resource_descriptor::type_e::EGRESS_ENC_EM2] = "EGRESS_ENC_EM2",
           [(size_t)la_resource_descriptor::type_e::EGRESS_ENC_EM3] = "EGRESS_ENC_EM3",
           [(size_t)la_resource_descriptor::type_e::EGRESS_ENC_EM4] = "EGRESS_ENC_EM4",
           [(size_t)la_resource_descriptor::type_e::EGRESS_ENC_EM5] = "EGRESS_ENC_EM5",
           [(size_t)la_resource_descriptor::type_e::EGRESS_IPV4_ACL] = "EGRESS_IPV4_ACL",
           [(size_t)la_resource_descriptor::type_e::EGRESS_IPV6_ACL] = "EGRESS_IPV6_ACL",
           [(size_t)la_resource_descriptor::type_e::EGRESS_LARGE_ENCAP_EM] = "EGRESS_LARGE_ENCAP_EM",
           [(size_t)la_resource_descriptor::type_e::EGRESS_L3_DLP0_EM] = "EGRESS_L3_DLP0_EM",
           [(size_t)la_resource_descriptor::type_e::EGRESS_SMALL_ENCAP_EM] = "EGRESS_SMALL_ENCAP_EM",
           [(size_t)la_resource_descriptor::type_e::EGRESS_QOS_PROFILES] = "EGRESS_QOS_PROFILES",
           [(size_t)la_resource_descriptor::type_e::INGRESS_ETH_NARROW_DB1_INTERFACE0_ACL]
           = "INGRESS_ETH_NARROW_DB1_INTERFACE0_ACL",
           [(size_t)la_resource_descriptor::type_e::INGRESS_ETH_NARROW_DB2_INTERFACE0_ACL]
           = "INGRESS_ETH_NARROW_DB2_INTERFACE0_ACL",
           [(size_t)la_resource_descriptor::type_e::INGRESS_IPV4_NARROW_DB1_INTERFACE0_ACL]
           = "INGRESS_IPV4_NARROW_DB1_INTERFACE0_ACL",
           [(size_t)la_resource_descriptor::type_e::INGRESS_IPV4_NARROW_DB2_INTERFACE0_ACL]
           = "INGRESS_IPV4_NARROW_DB2_INTERFACE0_ACL",
           [(size_t)la_resource_descriptor::type_e::INGRESS_IPV4_NARROW_DB3_INTERFACE0_ACL]
           = "INGRESS_IPV4_NARROW_DB3_INTERFACE0_ACL",
           [(size_t)la_resource_descriptor::type_e::INGRESS_IPV4_NARROW_DB4_INTERFACE0_ACL]
           = "INGRESS_IPV4_NARROW_DB4_INTERFACE0_ACL",
           [(size_t)la_resource_descriptor::type_e::INGRESS_IPV4_WIDE_DB1_INTERFACE0_ACL] = "INGRESS_IPV4_WIDE_DB1_INTERFACE0_ACL",
           [(size_t)la_resource_descriptor::type_e::INGRESS_IPV4_WIDE_DB2_INTERFACE0_ACL] = "INGRESS_IPV4_WIDE_DB2_INTERFACE0_ACL",
           [(size_t)la_resource_descriptor::type_e::INGRESS_IPV4_WIDE_DB3_INTERFACE0_ACL] = "INGRESS_IPV4_WIDE_DB3_INTERFACE0_ACL",
           [(size_t)la_resource_descriptor::type_e::INGRESS_IPV4_WIDE_DB4_INTERFACE0_ACL] = "INGRESS_IPV4_WIDE_DB4_INTERFACE0_ACL",
           [(size_t)la_resource_descriptor::type_e::INGRESS_IPV6_NARROW_DB1_INTERFACE0_ACL]
           = "INGRESS_IPV6_NARROW_DB1_INTERFACE0_ACL",
           [(size_t)la_resource_descriptor::type_e::INGRESS_IPV6_NARROW_DB2_INTERFACE0_ACL]
           = "INGRESS_IPV6_NARROW_DB2_INTERFACE0_ACL",
           [(size_t)la_resource_descriptor::type_e::INGRESS_IPV6_NARROW_DB3_INTERFACE0_ACL]
           = "INGRESS_IPV6_NARROW_DB3_INTERFACE0_ACL",
           [(size_t)la_resource_descriptor::type_e::INGRESS_IPV6_NARROW_DB4_INTERFACE0_ACL]
           = "INGRESS_IPV6_NARROW_DB4_INTERFACE0_ACL",
           [(size_t)la_resource_descriptor::type_e::INGRESS_IPV6_WIDE_DB1_INTERFACE0_ACL] = "INGRESS_IPV6_WIDE_DB1_INTERFACE0_ACL",
           [(size_t)la_resource_descriptor::type_e::INGRESS_IPV6_WIDE_DB2_INTERFACE0_ACL] = "INGRESS_IPV6_WIDE_DB2_INTERFACE0_ACL",
           [(size_t)la_resource_descriptor::type_e::INGRESS_IPV6_WIDE_DB3_INTERFACE0_ACL] = "INGRESS_IPV6_WIDE_DB3_INTERFACE0_ACL",
           [(size_t)la_resource_descriptor::type_e::INGRESS_IPV6_WIDE_DB4_INTERFACE0_ACL] = "INGRESS_IPV6_WIDE_DB4_INTERFACE0_ACL",
           [(size_t)la_resource_descriptor::type_e::INGRESS_QOS_PROFILES] = "INGRESS_QOS_PROFILES",
           [(size_t)la_resource_descriptor::type_e::IPV4_LPTS] = "IPV4_LPTS",
           [(size_t)la_resource_descriptor::type_e::IPV4_VRF_DIP_EM_TABLE] = "IPV4_VRF_DIP_EM_TABLE",
           [(size_t)la_resource_descriptor::type_e::IPV6_COMPRESSED_SIPS] = "IPV6_COMPRESSED_SIPS",
           [(size_t)la_resource_descriptor::type_e::IPV6_LPTS] = "IPV6_LPTS",
           [(size_t)la_resource_descriptor::type_e::IPV6_VRF_DIP_EM_TABLE] = "IPV6_VRF_DIP_EM_TABLE",
           [(size_t)la_resource_descriptor::type_e::L2_SERVICE_PORT] = "L2_SERVICE_PORT",
           [(size_t)la_resource_descriptor::type_e::L3_AC_PORT] = "L3_AC_PORT",
           [(size_t)la_resource_descriptor::type_e::LPM] = "LPM",
           [(size_t)la_resource_descriptor::type_e::LPM_IPV4_ROUTES] = "LPM_IPV4_ROUTES",
           [(size_t)la_resource_descriptor::type_e::LPM_IPV6_ROUTES] = "LPM_IPV6_ROUTES",
           [(size_t)la_resource_descriptor::type_e::MAC_FORWARDING_TABLE] = "MAC_FORWARDING_TABLE",
           [(size_t)la_resource_descriptor::type_e::MC_EMDB] = "MC_EMDB",
           [(size_t)la_resource_descriptor::type_e::METER_ACTION] = "METER_ACTION",
           [(size_t)la_resource_descriptor::type_e::METER_PROFILE] = "METER_PROFILE",
           [(size_t)la_resource_descriptor::type_e::MY_IPV4_TABLE] = "MY_IPV4_TABLE",
           [(size_t)la_resource_descriptor::type_e::NATIVE_CE_PTR_TABLE] = "NATIVE_CE_PTR_TABLE",
           [(size_t)la_resource_descriptor::type_e::NATIVE_FEC_ENTRY] = "NATIVE_FEC_ENTRY",
           [(size_t)la_resource_descriptor::type_e::NEXT_HOP] = "NEXT_HOP",
           [(size_t)la_resource_descriptor::type_e::PROTECTION_GROUP] = "PROTECTION_GROUP",
           [(size_t)la_resource_descriptor::type_e::RTF_CONF_SET] = "RTF_CONF_SET",
           [(size_t)la_resource_descriptor::type_e::SIP_INDEX_TABLE] = "SIP_INDEX_TABLE",
           [(size_t)la_resource_descriptor::type_e::STAGE1_LB_GROUP] = "STAGE1_LB_GROUP",
           [(size_t)la_resource_descriptor::type_e::STAGE1_LB_MEMBER] = "STAGE1_LB_MEMBER",
           [(size_t)la_resource_descriptor::type_e::STAGE1_PROTECTION_MONITOR] = "STAGE1_PROTECTION_MONITOR",
           [(size_t)la_resource_descriptor::type_e::STAGE2_LB_GROUP] = "STAGE2_LB_GROUP",
           [(size_t)la_resource_descriptor::type_e::STAGE2_LB_MEMBER] = "STAGE2_LB_MEMBER",
           [(size_t)la_resource_descriptor::type_e::STAGE2_PROTECTION_MONITOR] = "STAGE2_PROTECTION_MONITOR",
           [(size_t)la_resource_descriptor::type_e::STAGE3_LB_GROUP] = "STAGE3_LB_GROUP",
           [(size_t)la_resource_descriptor::type_e::STAGE3_LB_MEMBER] = "STAGE3_LB_MEMBER",
           [(size_t)la_resource_descriptor::type_e::TC_PROFILE] = "TC_PROFILE",
           [(size_t)la_resource_descriptor::type_e::TCAM_EGRESS_NARROW_POOL_0] = "TCAM_EGRESS_NARROW_POOL_0",
           [(size_t)la_resource_descriptor::type_e::TCAM_EGRESS_WIDE] = "TCAM_EGRESS_WIDE",
           [(size_t)la_resource_descriptor::type_e::TCAM_INGRESS_NARROW_POOL_0] = "TCAM_INGRESS_NARROW_POOL_0",
           [(size_t)la_resource_descriptor::type_e::TCAM_INGRESS_NARROW_POOL_1] = "TCAM_INGRESS_NARROW_POOL_1",
           [(size_t)la_resource_descriptor::type_e::TCAM_INGRESS_WIDE] = "TCAM_INGRESS_WIDE",
           [(size_t)la_resource_descriptor::type_e::TUNNEL_0_EM] = "TUNNEL_0_EM",
           [(size_t)la_resource_descriptor::type_e::TUNNEL_1_EM] = "TUNNEL_1_EM",
           [(size_t)la_resource_descriptor::type_e::VOQ_CGM_EVICTED_PROFILE] = "VOQ_CGM_EVICTED_PROFILE",
           [(size_t)la_resource_descriptor::type_e::VOQ_CGM_PROFILE] = "VOQ_CGM_PROFILE",
           [(size_t)la_resource_descriptor::type_e::UNSPECIFIED] = "UNSPECIFIED"};

    static_assert(array_size(strs) == (size_t)la_resource_descriptor::type_e::UNSPECIFIED + 1,
                  "resource requires to_string implementation");

    if ((size_t)resource_type < array_size(strs)) {
        return std::string(strs[(size_t)resource_type]);
    }

    return "Unknown resource type";
}

} // namespace silicon_one
