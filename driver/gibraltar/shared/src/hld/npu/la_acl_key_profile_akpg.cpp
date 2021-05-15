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

#include "la_acl_key_profile_akpg.h"
#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "lld/gibraltar_tree.h"
#include "lld/pacific_tree.h"
#include "runtime_flexibility_resources.h"
#include "system/la_device_impl.h"

namespace silicon_one
{
constexpr int8_t VLAN_OUTER_OFFSET = -2;
constexpr int8_t VLAN_INNER_OFFSET = -2;

la_acl_key_profile_akpg::la_acl_key_profile_akpg(const la_device_impl_wptr& device) : la_acl_key_profile_base(device)
{
}

la_acl_key_profile_akpg::~la_acl_key_profile_akpg()
{
}

int8_t
la_acl_key_profile_akpg::get_vlan_outer_offset() const
{
    return VLAN_OUTER_OFFSET;
}

int8_t
la_acl_key_profile_akpg::get_vlan_inner_offset() const
{
    return VLAN_INNER_OFFSET;
}

la_status
la_acl_key_profile_akpg::fill_ethernet_udk_components(std::vector<udk_component>& udk_components,
                                                      const la_acl_key_def_vec_t& key_def)
{
    udk_components.resize(key_def.size() + 1, udk_component());
    uint64_t key_size = 0;
    size_t field_idx = 0;
    constexpr bool IS_ABSOLUTE = false;

    // Library accounts for calculated-field size internally.
    udk_component udk_comp(UDK_COMPONENT_TYPE_CALCULATED_FIELD, NPL_NETWORK_RX_ETH_RTF_MACRO_CALCULATED_FIELD_ACL_ID);
    udk_components[field_idx] = udk_comp;
    field_idx++;

    for (auto acl_field_def : key_def) {
        switch (acl_field_def.type) {
        case la_acl_field_type_e::UDF: {
            udk_component udk_comp(acl_field_def.udf_desc.protocol_layer,
                                   acl_field_def.udf_desc.header,
                                   acl_field_def.udf_desc.width,
                                   acl_field_def.udf_desc.offset,
                                   acl_field_def.udf_desc.is_relative);
            udk_components[field_idx] = udk_comp;
            key_size += acl_field_def.udf_desc.width;
            break;
        }
        case la_acl_field_type_e::DA: {
            udk_component udk_comp(SOP, CURRENT_HEADER, DA_WIDTH, DA_OFFSET, IS_ABSOLUTE);
            udk_components[field_idx] = udk_comp;
            key_size += DA_WIDTH;
            break;
        }
        case la_acl_field_type_e::SA: {
            udk_component udk_comp(SOP, CURRENT_HEADER, SA_WIDTH, SA_OFFSET, IS_ABSOLUTE);
            udk_components[field_idx] = udk_comp;
            key_size += SA_WIDTH;
            break;
        }
        case la_acl_field_type_e::VLAN_OUTER: {
            udk_component udk_comp(SOP, NEXT_HEADER, VLAN_OUTER_WIDTH, get_vlan_outer_offset(), IS_ABSOLUTE);
            udk_components[field_idx] = udk_comp;
            key_size += VLAN_OUTER_WIDTH;
            break;
        }
        case la_acl_field_type_e::VLAN_INNER: {
            udk_component udk_comp(SOP, NEXT_NEXT_HEADER, VLAN_INNER_WIDTH, get_vlan_inner_offset(), IS_ABSOLUTE);
            udk_components[field_idx] = udk_comp;
            key_size += VLAN_INNER_WIDTH;
            break;
        }
        case la_acl_field_type_e::ETHER_TYPE: {
            udk_component udk_comp(SOP, CURRENT_HEADER, ETHER_TYPE_WIDTH, ETHER_TYPE_OFFSET, IS_ABSOLUTE);
            udk_components[field_idx] = udk_comp;
            key_size += ETHER_TYPE_WIDTH;
            break;
        }
        case la_acl_field_type_e::CLASS_ID: {
            // Library accounts for calculated-field size internally.
            udk_component udk_comp(UDK_COMPONENT_TYPE_CALCULATED_FIELD,
                                   NPL_NETWORK_RX_ETH_RTF_MACRO_CALCULATED_FIELD_DEST_CLASS_ID);
            udk_components[field_idx] = udk_comp;
            break;
        }
        case la_acl_field_type_e::QOS_GROUP: {
            // Library accounts for calculated-field size internally.
            udk_component udk_comp(UDK_COMPONENT_TYPE_CALCULATED_FIELD, NPL_NETWORK_RX_ETH_RTF_MACRO_CALCULATED_FIELD_QOS_GROUP);
            udk_components[field_idx] = udk_comp;
            break;
        }
        default:
            return LA_STATUS_EINVAL;
        }
        field_idx++;
    }

    // Convert key-size calculated above in bytes to bits.
    key_size *= 8;
    if (key_size > 160) {
        log_err(HLD, "la_acl_key_profile_base::%s Aggregated ethernet acl key size %d > 160", __func__, static_cast<int>(key_size));
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_key_profile_akpg::fill_v4_udk_components(std::vector<udk_component>& udk_components, const la_acl_key_def_vec_t& key_def)
{
    uint64_t udk_comp_size = key_def.size() + 1; // +1 for acl_id field
    udk_components.resize(udk_comp_size, udk_component());
    uint64_t key_size = 0;
    size_t field_idx = 0;
    bool src_bincode = false;
    bool dst_bincode = false;
    bool sport = false;
    bool msg_code = false;
    bool msg_type = false;
    bool protocol = false;
    constexpr bool IS_RELATIVE = true;
    constexpr bool IS_ABSOLUTE = false;
    bool is_og = false;

    // Library accounts for calculated-field size internally.
    udk_component udk_comp(UDK_COMPONENT_TYPE_CALCULATED_FIELD, NPL_NETWORK_RX_IPV4_RTF_MACRO_CALCULATED_FIELD_ACL_ID);
    udk_components[field_idx] = udk_comp;
    field_idx++;

    for (auto acl_field_def : key_def) {
        switch (acl_field_def.type) {
        case la_acl_field_type_e::UDF: {
            udk_component udk_comp(acl_field_def.udf_desc.protocol_layer,
                                   acl_field_def.udf_desc.header,
                                   acl_field_def.udf_desc.width,
                                   acl_field_def.udf_desc.offset,
                                   acl_field_def.udf_desc.is_relative);
            udk_components[field_idx] = udk_comp;
            key_size += acl_field_def.udf_desc.width;
            break;
        }
        case la_acl_field_type_e::DA: {
            udk_component udk_comp(SOP, CURRENT_HEADER, DA_WIDTH, DA_OFFSET, IS_ABSOLUTE);
            udk_components[field_idx] = udk_comp;
            key_size += DA_WIDTH;
            break;
        }
        case la_acl_field_type_e::SA: {
            udk_component udk_comp(SOP, CURRENT_HEADER, SA_WIDTH, SA_OFFSET, IS_ABSOLUTE);
            udk_components[field_idx] = udk_comp;
            key_size += SA_WIDTH;
            break;
        }
        case la_acl_field_type_e::VLAN_OUTER: {
            udk_component udk_comp(SOP, NEXT_HEADER, VLAN_OUTER_WIDTH, get_vlan_outer_offset(), IS_ABSOLUTE);
            udk_components[field_idx] = udk_comp;
            key_size += VLAN_OUTER_WIDTH;
            break;
        }
        case la_acl_field_type_e::VLAN_INNER: {
            udk_component udk_comp(SOP, NEXT_NEXT_HEADER, VLAN_INNER_WIDTH, get_vlan_inner_offset(), IS_ABSOLUTE);
            udk_components[field_idx] = udk_comp;
            key_size += VLAN_INNER_WIDTH;
            break;
        }
        case la_acl_field_type_e::ETHER_TYPE: {
            udk_component udk_comp(SOP, CURRENT_HEADER, ETHER_TYPE_WIDTH, ETHER_TYPE_OFFSET, IS_ABSOLUTE);
            udk_components[field_idx] = udk_comp;
            key_size += ETHER_TYPE_WIDTH;
            break;
        }
        case la_acl_field_type_e::TOS: {
            udk_component udk_comp(CURRENT_PROTOCOL_LAYER, CURRENT_HEADER, TOS_WIDTH, TOS_OFFSET, IS_RELATIVE);
            udk_components[field_idx] = udk_comp;
            key_size += TOS_WIDTH;
            break;
        }
        case la_acl_field_type_e::IPV4_LENGTH: {
            udk_component udk_comp(CURRENT_PROTOCOL_LAYER, CURRENT_HEADER, IPV4_LENGTH_WIDTH, IPV4_LENGTH_OFFSET, IS_RELATIVE);
            udk_components[field_idx] = udk_comp;
            key_size += IPV4_LENGTH_WIDTH;
            break;
        }
        case la_acl_field_type_e::IPV4_FLAGS: {
            // Library accounts for calculated-field size internally.
            udk_component udk_comp(UDK_COMPONENT_TYPE_CALCULATED_FIELD,
                                   NPL_NETWORK_RX_IPV4_RTF_MACRO_CALCULATED_FIELD_IP_FIRST_FRAGMENT);
            udk_components[field_idx] = udk_comp;
            break;
        }
        case la_acl_field_type_e::IPV4_FRAG_OFFSET: {
            udk_component udk_comp(
                CURRENT_PROTOCOL_LAYER, CURRENT_HEADER, IPV4_FRAG_OFFSET_WIDTH, IPV4_FRAG_OFFSET_OFFSET, IS_RELATIVE);
            udk_components[field_idx] = udk_comp;
            key_size += IPV4_FRAG_OFFSET_WIDTH;
            break;
        }
        case la_acl_field_type_e::TTL: {
            udk_component udk_comp(CURRENT_PROTOCOL_LAYER, CURRENT_HEADER, TTL_WIDTH, TTL_OFFSET, IS_RELATIVE);
            udk_components[field_idx] = udk_comp;
            key_size += TTL_WIDTH;
            break;
        }
        case la_acl_field_type_e::PROTOCOL: {
            protocol = true;
            field_idx--;
            udk_comp_size--;
            break;
        }
        case la_acl_field_type_e::IPV4_SIP: {
            udk_component udk_comp(CURRENT_PROTOCOL_LAYER, CURRENT_HEADER, IPV4_SIP_WIDTH, IPV4_SIP_OFFSET, IS_RELATIVE);
            udk_components[field_idx] = udk_comp;
            key_size += IPV4_SIP_WIDTH;
            break;
        }
        case la_acl_field_type_e::IPV4_DIP: {
            udk_component udk_comp(CURRENT_PROTOCOL_LAYER, CURRENT_HEADER, IPV4_DIP_WIDTH, IPV4_DIP_OFFSET, IS_RELATIVE);
            udk_components[field_idx] = udk_comp;
            key_size += IPV4_DIP_WIDTH;
            break;
        }
        case la_acl_field_type_e::SPORT: {
            sport = true;
            field_idx--;
            udk_comp_size--;
            break;
        }
        case la_acl_field_type_e::DPORT: {
            udk_component udk_comp(CURRENT_PROTOCOL_LAYER, NEXT_HEADER, DPORT_WIDTH, DPORT_OFFSET, IS_RELATIVE);
            udk_components[field_idx] = udk_comp;
            key_size += DPORT_WIDTH;
            break;
        }
        case la_acl_field_type_e::MSG_TYPE: {
            msg_type = true;
            field_idx--;
            udk_comp_size--;
            break;
        }
        case la_acl_field_type_e::MSG_CODE: {
            msg_code = true;
            field_idx--;
            udk_comp_size--;
            break;
        }
        case la_acl_field_type_e::TCP_FLAGS: {
            udk_component udk_comp(CURRENT_PROTOCOL_LAYER, NEXT_HEADER, TCP_FLAGS_WIDTH, TCP_FLAGS_OFFSET, IS_RELATIVE);
            udk_components[field_idx] = udk_comp;
            key_size += TCP_FLAGS_WIDTH;
            break;
        }
        case la_acl_field_type_e::VRF_GID: {
            // Library accounts for calculated-field size internally.
            udk_component udk_comp(UDK_COMPONENT_TYPE_CALCULATED_FIELD, NPL_NETWORK_RX_IPV4_RTF_MACRO_CALCULATED_FIELD_L3_RELAY_ID);
            udk_components[field_idx] = udk_comp;
            break;
        }
        case la_acl_field_type_e::CLASS_ID: {
            // Library accounts for calculated-field size internally.
            udk_component udk_comp(UDK_COMPONENT_TYPE_CALCULATED_FIELD,
                                   NPL_NETWORK_RX_IPV4_RTF_MACRO_CALCULATED_FIELD_DEST_CLASS_ID);
            udk_components[field_idx] = udk_comp;
            break;
        }
        case la_acl_field_type_e::SRC_PCL_BINCODE: {
            // Library accounts for calculated-field size internally.
            if (!dst_bincode) {
                udk_component udk_comp(UDK_COMPONENT_TYPE_CALCULATED_FIELD,
                                       NPL_NETWORK_RX_IPV4_RTF_MACRO_CALCULATED_FIELD_OBJECT_GROUPS);
                udk_components[field_idx] = udk_comp;
            } else {
                udk_comp_size--;
                udk_components.resize(udk_comp_size, udk_component());
                field_idx--;
            }
            src_bincode = true;
            break;
        }
        case la_acl_field_type_e::DST_PCL_BINCODE: {
            // Library accounts for calculated-field size internally.
            if (!src_bincode) {
                udk_component udk_comp(UDK_COMPONENT_TYPE_CALCULATED_FIELD,
                                       NPL_NETWORK_RX_IPV4_RTF_MACRO_CALCULATED_FIELD_OBJECT_GROUPS);
                udk_components[field_idx] = udk_comp;
            } else {
                udk_comp_size--;
                udk_components.resize(udk_comp_size, udk_component());
                field_idx--;
            }
            dst_bincode = true;
            break;
        }
        case la_acl_field_type_e::QOS_GROUP: {
            // Library accounts for calculated-field size internally.
            udk_component udk_comp(UDK_COMPONENT_TYPE_CALCULATED_FIELD, NPL_NETWORK_RX_IPV4_RTF_MACRO_CALCULATED_FIELD_QOS_GROUP);
            udk_components[field_idx] = udk_comp;
            break;
        }

        default:
            return LA_STATUS_EINVAL;
        }
        field_idx++;
    }

    if (protocol || sport || msg_code || msg_type) {
        udk_components.resize(udk_comp_size + 2, udk_component());
        udk_component udk_comp1(UDK_COMPONENT_TYPE_CALCULATED_FIELD,
                                NPL_NETWORK_RX_IPV4_RTF_MACRO_CALCULATED_FIELD_ACL_L4_PROTOCOL);
        udk_components[field_idx] = udk_comp1;
        field_idx++;
        udk_component udk_comp2(UDK_COMPONENT_TYPE_CALCULATED_FIELD, NPL_NETWORK_RX_IPV4_RTF_MACRO_CALCULATED_FIELD_SRC_PORT);
        udk_components[field_idx] = udk_comp2;
        field_idx++;
    }

    if ((dst_bincode) && (src_bincode)) {
        is_og = true;
    } else if ((dst_bincode) || (src_bincode)) {
        log_err(HLD, "la_acl_key_profile_akpg: og acl, must configure both src&dst bincodes");
        return LA_STATUS_EINVAL;
    }

    // Convert key-size calculated above in bytes to bits.
    key_size *= 8;
    if (is_og) {
        key_size += NPL_OBJECT_GROUP_COMPRESSION_CODE_LEN * 2;
    }

    if (key_size > 320) {
        log_err(HLD, "la_acl_key_profile_akpg::%s Aggregated ipv4 acl key size %d > 320", __func__, static_cast<int>(key_size));
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_key_profile_akpg::fill_v6_udk_components(std::vector<udk_component>& udk_components, const la_acl_key_def_vec_t& key_def)
{
    uint64_t udk_comp_size = key_def.size() + 1; // +1 for acl_id field
    udk_components.resize(udk_comp_size, udk_component());
    uint64_t key_size = 0;
    size_t field_idx = 0;
    bool src_bincode = false;
    bool dst_bincode = false;
    bool sport = false;
    bool msg_code = false;
    bool msg_type = false;
    bool last_next_header = false;
    constexpr bool IS_RELATIVE = true;
    constexpr bool IS_ABSOLUTE = false;
    bool is_og = false;

    // Library accounts for calculated-field size internally.
    udk_component udk_comp(UDK_COMPONENT_TYPE_CALCULATED_FIELD, NPL_NETWORK_RX_IPV6_RTF_MACRO_CALCULATED_FIELD_ACL_ID);
    udk_components[field_idx] = udk_comp;
    field_idx++;

    for (auto acl_field_def : key_def) {
        switch (acl_field_def.type) {
        case la_acl_field_type_e::UDF: {
            udk_component udk_comp(acl_field_def.udf_desc.protocol_layer,
                                   acl_field_def.udf_desc.header,
                                   acl_field_def.udf_desc.width,
                                   acl_field_def.udf_desc.offset,
                                   acl_field_def.udf_desc.is_relative);
            udk_components[field_idx] = udk_comp;
            key_size += acl_field_def.udf_desc.width;
            break;
        }
        case la_acl_field_type_e::DA: {
            udk_component udk_comp(SOP, CURRENT_HEADER, DA_WIDTH, DA_OFFSET, IS_ABSOLUTE);
            udk_components[field_idx] = udk_comp;
            key_size += DA_WIDTH;
            break;
        }
        case la_acl_field_type_e::SA: {
            udk_component udk_comp(SOP, CURRENT_HEADER, SA_WIDTH, SA_OFFSET, IS_ABSOLUTE);
            udk_components[field_idx] = udk_comp;
            key_size += SA_WIDTH;
            break;
        }
        case la_acl_field_type_e::VLAN_OUTER: {
            udk_component udk_comp(SOP, NEXT_HEADER, VLAN_OUTER_WIDTH, get_vlan_outer_offset(), IS_ABSOLUTE);
            udk_components[field_idx] = udk_comp;
            key_size += VLAN_OUTER_WIDTH;
            break;
        }
        case la_acl_field_type_e::VLAN_INNER: {
            udk_component udk_comp(SOP, NEXT_NEXT_HEADER, VLAN_INNER_WIDTH, get_vlan_inner_offset(), IS_ABSOLUTE);
            udk_components[field_idx] = udk_comp;
            key_size += VLAN_INNER_WIDTH;
            break;
        }
        case la_acl_field_type_e::ETHER_TYPE: {
            udk_component udk_comp(SOP, CURRENT_HEADER, ETHER_TYPE_WIDTH, ETHER_TYPE_OFFSET, IS_ABSOLUTE);
            udk_components[field_idx] = udk_comp;
            key_size += ETHER_TYPE_WIDTH;
            break;
        }
        case la_acl_field_type_e::TOS: {
            udk_component udk_comp(UDK_COMPONENT_TYPE_CALCULATED_FIELD,
                                   NPL_NETWORK_RX_IPV6_RTF_MACRO_CALCULATED_FIELD_TRAFFIC_CLASS);
            udk_components[field_idx] = udk_comp;
            break;
        }
        case la_acl_field_type_e::IPV6_LENGTH: {
            udk_component udk_comp(CURRENT_PROTOCOL_LAYER, CURRENT_HEADER, IPV6_LENGTH_WIDTH, IPV6_LENGTH_OFFSET, IS_RELATIVE);
            udk_components[field_idx] = udk_comp;
            key_size += IPV6_LENGTH_WIDTH;
            break;
        }
        case la_acl_field_type_e::HOP_LIMIT: {
            udk_component udk_comp(CURRENT_PROTOCOL_LAYER, CURRENT_HEADER, HOP_LIMIT_WIDTH, HOP_LIMIT_OFFSET, IS_RELATIVE);
            udk_components[field_idx] = udk_comp;
            key_size += HOP_LIMIT_WIDTH;
            break;
        }
        case la_acl_field_type_e::LAST_NEXT_HEADER: {
            last_next_header = true;
            field_idx--;
            udk_comp_size--;
            break;
        }
        case la_acl_field_type_e::IPV6_SIP: {
            udk_component udk_comp(CURRENT_PROTOCOL_LAYER, CURRENT_HEADER, IPV6_SIP_WIDTH, IPV6_SIP_OFFSET, IS_RELATIVE);
            udk_components[field_idx] = udk_comp;
            key_size += IPV6_SIP_WIDTH;
            break;
        }
        case la_acl_field_type_e::IPV6_DIP: {
            udk_component udk_comp(CURRENT_PROTOCOL_LAYER, CURRENT_HEADER, IPV6_DIP_WIDTH, IPV6_DIP_OFFSET, IS_RELATIVE);
            udk_components[field_idx] = udk_comp;
            key_size += IPV6_DIP_WIDTH;
            break;
        }
        case la_acl_field_type_e::SPORT: {
            sport = true;
            field_idx--;
            udk_comp_size--;
            break;
        }
        case la_acl_field_type_e::DPORT: {
            udk_component udk_comp(CURRENT_PROTOCOL_LAYER, NEXT_HEADER, DPORT_WIDTH, DPORT_OFFSET, IS_RELATIVE);
            udk_components[field_idx] = udk_comp;
            key_size += DPORT_WIDTH;
            break;
        }
        case la_acl_field_type_e::MSG_TYPE: {
            msg_type = true;
            field_idx--;
            udk_comp_size--;
            break;
        }
        case la_acl_field_type_e::MSG_CODE: {
            msg_code = true;
            field_idx--;
            udk_comp_size--;
            break;
        }
        case la_acl_field_type_e::TCP_FLAGS: {
            udk_component udk_comp(CURRENT_PROTOCOL_LAYER, NEXT_HEADER, TCP_FLAGS_WIDTH, TCP_FLAGS_OFFSET, IS_RELATIVE);
            udk_components[field_idx] = udk_comp;
            key_size += TCP_FLAGS_WIDTH;
            break;
        }
        case la_acl_field_type_e::IPV6_FRAGMENT: {
            udk_component udk_comp(UDK_COMPONENT_TYPE_CALCULATED_FIELD,
                                   NPL_NETWORK_RX_IPV6_RTF_MACRO_CALCULATED_FIELD_IP_FIRST_FRAGMENT);
            udk_components[field_idx] = udk_comp;
            break;
        }
        case la_acl_field_type_e::VRF_GID: {
            // Library accounts for calculated-field size internally.
            udk_component udk_comp(UDK_COMPONENT_TYPE_CALCULATED_FIELD, NPL_NETWORK_RX_IPV6_RTF_MACRO_CALCULATED_FIELD_L3_RELAY_ID);
            udk_components[field_idx] = udk_comp;
            break;
        }
        case la_acl_field_type_e::CLASS_ID: {
            // Library accounts for calculated-field size internally.
            udk_component udk_comp(UDK_COMPONENT_TYPE_CALCULATED_FIELD,
                                   NPL_NETWORK_RX_IPV6_RTF_MACRO_CALCULATED_FIELD_DEST_CLASS_ID);
            udk_components[field_idx] = udk_comp;
            break;
        }
        case la_acl_field_type_e::SRC_PCL_BINCODE: {
            // Library accounts for calculated-field size internally.
            if (!dst_bincode) {
                udk_component udk_comp(UDK_COMPONENT_TYPE_CALCULATED_FIELD,
                                       NPL_NETWORK_RX_IPV6_RTF_MACRO_CALCULATED_FIELD_OBJECT_GROUPS);
                udk_components[field_idx] = udk_comp;
            } else {
                udk_comp_size--;
                udk_components.resize(udk_comp_size, udk_component());
                field_idx--;
            }
            src_bincode = true;
            break;
        }
        case la_acl_field_type_e::DST_PCL_BINCODE: {
            // Library accounts for calculated-field size internally.
            if (!src_bincode) {
                udk_component udk_comp(UDK_COMPONENT_TYPE_CALCULATED_FIELD,
                                       NPL_NETWORK_RX_IPV6_RTF_MACRO_CALCULATED_FIELD_OBJECT_GROUPS);
                udk_components[field_idx] = udk_comp;
            } else {
                udk_comp_size--;
                udk_components.resize(udk_comp_size, udk_component());
                field_idx--;
            }
            dst_bincode = true;
            break;
        }
        case la_acl_field_type_e::QOS_GROUP: {
            // Library accounts for calculated-field size internally.
            udk_component udk_comp(UDK_COMPONENT_TYPE_CALCULATED_FIELD, NPL_NETWORK_RX_IPV6_RTF_MACRO_CALCULATED_FIELD_QOS_GROUP);
            udk_components[field_idx] = udk_comp;
            break;
        }

        default:
            return LA_STATUS_EINVAL;
        }
        field_idx++;
    }

    if (last_next_header || sport || msg_code || msg_type) {
        udk_components.resize(udk_comp_size + 2, udk_component());
        udk_component udk_comp1(UDK_COMPONENT_TYPE_CALCULATED_FIELD,
                                NPL_NETWORK_RX_IPV6_RTF_MACRO_CALCULATED_FIELD_ACL_L4_PROTOCOL);
        udk_components[field_idx] = udk_comp1;
        field_idx++;
        udk_component udk_comp2(UDK_COMPONENT_TYPE_CALCULATED_FIELD, NPL_NETWORK_RX_IPV6_RTF_MACRO_CALCULATED_FIELD_SRC_PORT);
        udk_components[field_idx] = udk_comp2;
        field_idx++;
    }

    if ((dst_bincode) && (src_bincode)) {
        is_og = true;
    } else if ((dst_bincode) || (src_bincode)) {
        log_err(HLD, "la_acl_key_profile_akpg: og acl, must configure both src&dst bincodes");
        return LA_STATUS_EINVAL;
    }

    // Convert key-size calculated above in bytes to bits.
    key_size *= 8;
    if (is_og) {
        key_size += NPL_OBJECT_GROUP_COMPRESSION_CODE_LEN * 2;
    }

    if (key_size > 320) {
        log_err(HLD, "la_acl_key_profile_akpg::%s Aggregated ipv6 acl key size %d > 320", __func__, static_cast<int>(key_size));
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
