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

#ifndef __LA_ACL_KEY_UTILS_H__
#define __LA_ACL_KEY_UTILS_H__

#include "hld_types.h"
#include "nplapi/npl_types.h"

namespace silicon_one
{

constexpr la_uint16_t VLAN_TPID_OFFSET = 16;
constexpr la_uint16_t VLAN_PCP_OFFSET = 13;
constexpr la_uint16_t VLAN_DEI_OFFSET = 12;

template <class T>
using is_udk = std::enable_if<std::is_same<T, npl_ingress_rtf_eth_db1_160_f0_table_key_t>::value
                              || std::is_same<T, npl_ingress_rtf_eth_db2_160_f0_table_key_t>::value
                              || std::is_same<T, npl_ingress_rtf_ipv4_db1_160_f0_table_key_t>::value
                              || std::is_same<T, npl_ingress_rtf_ipv4_db2_160_f0_table_key_t>::value
                              || std::is_same<T, npl_ingress_rtf_ipv4_db3_160_f0_table_key_t>::value
                              || std::is_same<T, npl_ingress_rtf_ipv4_db4_160_f0_table_key_t>::value
                              || std::is_same<T, npl_ingress_rtf_ipv4_db1_320_f0_table_key_t>::value
                              || std::is_same<T, npl_ingress_rtf_ipv4_db2_320_f0_table_key_t>::value
                              || std::is_same<T, npl_ingress_rtf_ipv4_db3_320_f0_table_key_t>::value
                              || std::is_same<T, npl_ingress_rtf_ipv4_db4_320_f0_table_key_t>::value
                              || std::is_same<T, npl_ingress_rtf_ipv6_db1_160_f0_table_key_t>::value
                              || std::is_same<T, npl_ingress_rtf_ipv6_db2_160_f0_table_key_t>::value
                              || std::is_same<T, npl_ingress_rtf_ipv6_db3_160_f0_table_key_t>::value
                              || std::is_same<T, npl_ingress_rtf_ipv6_db4_160_f0_table_key_t>::value
                              || std::is_same<T, npl_ingress_rtf_ipv6_db1_320_f0_table_key_t>::value
                              || std::is_same<T, npl_ingress_rtf_ipv6_db2_320_f0_table_key_t>::value
                              || std::is_same<T, npl_ingress_rtf_ipv6_db3_320_f0_table_key_t>::value
                              || std::is_same<T, npl_ingress_rtf_ipv6_db4_320_f0_table_key_t>::value>;

template <class T>
using is_eth_rtf = std::enable_if<std::is_same<T, npl_ingress_rtf_eth_db1_160_f0_table_key_t>::value
                                  || std::is_same<T, npl_ingress_rtf_eth_db2_160_f0_table_key_t>::value>;

template <class T>
using is_ipv4_rtf = std::enable_if<std::is_same<T, npl_ingress_rtf_ipv4_db1_160_f0_table_key_t>::value
                                   || std::is_same<T, npl_ingress_rtf_ipv4_db2_160_f0_table_key_t>::value
                                   || std::is_same<T, npl_ingress_rtf_ipv4_db3_160_f0_table_key_t>::value
                                   || std::is_same<T, npl_ingress_rtf_ipv4_db4_160_f0_table_key_t>::value
                                   || std::is_same<T, npl_ingress_rtf_ipv4_db1_320_f0_table_key_t>::value
                                   || std::is_same<T, npl_ingress_rtf_ipv4_db2_320_f0_table_key_t>::value
                                   || std::is_same<T, npl_ingress_rtf_ipv4_db3_320_f0_table_key_t>::value
                                   || std::is_same<T, npl_ingress_rtf_ipv4_db4_320_f0_table_key_t>::value>;

template <class T>
using is_ipv6_rtf = std::enable_if<std::is_same<T, npl_ingress_rtf_ipv6_db1_160_f0_table_key_t>::value
                                   || std::is_same<T, npl_ingress_rtf_ipv6_db2_160_f0_table_key_t>::value
                                   || std::is_same<T, npl_ingress_rtf_ipv6_db3_160_f0_table_key_t>::value
                                   || std::is_same<T, npl_ingress_rtf_ipv6_db4_160_f0_table_key_t>::value
                                   || std::is_same<T, npl_ingress_rtf_ipv6_db1_320_f0_table_key_t>::value
                                   || std::is_same<T, npl_ingress_rtf_ipv6_db2_320_f0_table_key_t>::value
                                   || std::is_same<T, npl_ingress_rtf_ipv6_db3_320_f0_table_key_t>::value
                                   || std::is_same<T, npl_ingress_rtf_ipv6_db4_320_f0_table_key_t>::value>;

// field_to_npl for ethernet rtf fields (160 key size)
template <typename npl_table_key_t, typename is_eth_rtf<npl_table_key_t>::type* = nullptr>
la_status
field_to_npl(const la_acl_field_def acl_field_def,
             const la_acl_key& key_mask,
             npl_table_key_t& npl_key,
             npl_table_key_t& npl_mask,
             la_uint8_t& idx)
{
    npl_object_groups_t bincode_keys;
    npl_object_groups_t bincode_masks;
    memset(&bincode_keys, 0, sizeof(bincode_keys));
    memset(&bincode_masks, 0, sizeof(bincode_masks));
    la_uint32_t vlan_key = 0;
    la_uint32_t vlan_mask = 0;

    for (const auto acl_field : key_mask) {
        /*
         * The following for loop only processes a particular field
         * when the field definition and the field type match, with the
         * following exception: if the field type is DST_PCL_BINCODE
         * and the field definition is SRC_PCL_BINCODE, it is processed
         * as a single field in the key.
         */
        if (((acl_field.type == la_acl_field_type_e::DST_PCL_BINCODE)
             && (acl_field_def.type == la_acl_field_type_e::SRC_PCL_BINCODE))
            || (acl_field_def.type == acl_field.type)) {

            if (acl_field_def.type == la_acl_field_type_e::UDF) {
                if (acl_field_def.udf_desc.index == acl_field.udf_index) {
                    npl_key.ud_key.udfs[idx].value[0] = acl_field.val.udf.q_data[0];
                    npl_key.ud_key.udfs[idx].value[1] = acl_field.val.udf.q_data[1];
                    npl_mask.ud_key.udfs[idx].value[0] = acl_field.mask.udf.q_data[0];
                    npl_mask.ud_key.udfs[idx].value[1] = acl_field.mask.udf.q_data[1];
                    break;
                }
            } else if (acl_field.type == la_acl_field_type_e::VLAN_OUTER) {
                // constuct key in the following way tpid(16 bits), pcp(3 bits), dei(1bit), vid(12 bits)
                vlan_key = acl_field.val.vlan1.tpid << VLAN_TPID_OFFSET;
                vlan_key += acl_field.val.vlan1.tci.fields.pcp << VLAN_PCP_OFFSET;
                vlan_key += acl_field.val.vlan1.tci.fields.dei << VLAN_DEI_OFFSET;
                vlan_key += acl_field.val.vlan1.tci.fields.vid;
                vlan_mask = acl_field.mask.vlan1.tpid << VLAN_TPID_OFFSET;
                vlan_mask += acl_field.mask.vlan1.tci.fields.pcp << VLAN_PCP_OFFSET;
                vlan_mask += acl_field.mask.vlan1.tci.fields.dei << VLAN_DEI_OFFSET;
                vlan_mask += acl_field.mask.vlan1.tci.fields.vid;
                npl_key.ud_key.udfs[idx].value[0] = vlan_key;
                npl_mask.ud_key.udfs[idx].value[0] = vlan_mask;
                break;
            } else if (acl_field.type == la_acl_field_type_e::VLAN_INNER) {
                vlan_key = acl_field.val.vlan2.tpid << VLAN_TPID_OFFSET;
                vlan_key += acl_field.val.vlan2.tci.fields.pcp << VLAN_PCP_OFFSET;
                vlan_key += acl_field.val.vlan2.tci.fields.dei << VLAN_DEI_OFFSET;
                vlan_key += acl_field.val.vlan2.tci.fields.vid;
                vlan_mask = acl_field.mask.vlan2.tpid << VLAN_TPID_OFFSET;
                vlan_mask += acl_field.mask.vlan2.tci.fields.pcp << VLAN_PCP_OFFSET;
                vlan_mask += acl_field.mask.vlan2.tci.fields.dei << VLAN_DEI_OFFSET;
                vlan_mask += acl_field.mask.vlan2.tci.fields.vid;
                npl_key.ud_key.udfs[idx].value[0] = vlan_key;
                npl_mask.ud_key.udfs[idx].value[0] = vlan_mask;
                break;
            } else {
                npl_key.ud_key.udfs[idx].value[0] = acl_field.val.udf.q_data[0];
                npl_key.ud_key.udfs[idx].value[1] = acl_field.val.udf.q_data[1];
                npl_mask.ud_key.udfs[idx].value[0] = acl_field.mask.udf.q_data[0];
                npl_mask.ud_key.udfs[idx].value[1] = acl_field.mask.udf.q_data[1];
                break;
            }
        }
    }
    return LA_STATUS_SUCCESS;
}

// field_to_npl for ipv4 rtf fields (160 and 320 key sizes)
template <typename npl_table_key_t, typename is_ipv4_rtf<npl_table_key_t>::type* = nullptr>
la_status
field_to_npl(const la_acl_field_def acl_field_def,
             const la_acl_key& key_mask,
             npl_table_key_t& npl_key,
             npl_table_key_t& npl_mask,
             la_uint8_t& idx)
{
    npl_object_groups_t bincode_keys;
    npl_object_groups_t bincode_masks;
    memset(&bincode_keys, 0, sizeof(bincode_keys));
    memset(&bincode_masks, 0, sizeof(bincode_masks));
    la_uint32_t vlan_key = 0;
    la_uint32_t vlan_mask = 0;

    if ((acl_field_def.type == la_acl_field_type_e::PROTOCOL) || (acl_field_def.type == la_acl_field_type_e::SPORT)
        || (acl_field_def.type == la_acl_field_type_e::MSG_CODE)
        || (acl_field_def.type == la_acl_field_type_e::MSG_TYPE)) {
        idx--;
        return LA_STATUS_SUCCESS;
    }

    for (const auto acl_field : key_mask) {
        /*
         * The following for loop only processes a particular field
         * when the field definition and the field type match, with the
         * following exception: if the field type is DST_PCL_BINCODE
         * and the field definition is SRC_PCL_BINCODE, it is processed
         * as a single field in the key.
         */
        if (((acl_field.type == la_acl_field_type_e::DST_PCL_BINCODE)
             && (acl_field_def.type == la_acl_field_type_e::SRC_PCL_BINCODE))
            || (acl_field_def.type == acl_field.type)) {

            if (acl_field_def.type == la_acl_field_type_e::UDF) {
                if (acl_field_def.udf_desc.index == acl_field.udf_index) {
                    npl_key.ud_key.udfs[idx].value[0] = acl_field.val.udf.q_data[0];
                    npl_key.ud_key.udfs[idx].value[1] = acl_field.val.udf.q_data[1];
                    npl_mask.ud_key.udfs[idx].value[0] = acl_field.mask.udf.q_data[0];
                    npl_mask.ud_key.udfs[idx].value[1] = acl_field.mask.udf.q_data[1];
                    break;
                }
            } else if (acl_field_def.type == la_acl_field_type_e::IPV4_FLAGS) {
                // Today there is support only for not-first-fragment match in NPL, so can ignore df & mf
                npl_key.ud_key.udfs[idx].value[0] = static_cast<npl_bool_e>(~acl_field.val.ipv4_flags.fragment);
                npl_mask.ud_key.udfs[idx].value[0] = static_cast<npl_bool_e>(acl_field.mask.ipv4_flags.fragment);
                break;
            } else if (acl_field.type == la_acl_field_type_e::DST_PCL_BINCODE) {
                bincode_keys.dest_code.bits_17_0 = acl_field.val.udf.q_data[0];
                bincode_keys.dest_code.bits_n_18 = acl_field.val.udf.q_data[0] >> 18;
                bincode_masks.dest_code.bits_17_0 = acl_field.mask.udf.q_data[0];
                bincode_masks.dest_code.bits_n_18 = acl_field.mask.udf.q_data[0] >> 18;
                npl_key.ud_key.udfs[idx].value[0] = bincode_keys.pack().get_value();
                npl_mask.ud_key.udfs[idx].value[0] = bincode_masks.pack().get_value();
                break;
            } else if (acl_field.type == la_acl_field_type_e::SRC_PCL_BINCODE) {
                bincode_keys.src_code.bits_17_0 = acl_field.val.udf.q_data[0];
                bincode_keys.src_code.bits_n_18 = acl_field.val.udf.q_data[0] >> 18;
                bincode_masks.src_code.bits_17_0 = acl_field.mask.udf.q_data[0];
                bincode_masks.src_code.bits_n_18 = acl_field.mask.udf.q_data[0] >> 18;
                npl_key.ud_key.udfs[idx].value[0] = bincode_keys.pack().get_value();
                npl_mask.ud_key.udfs[idx].value[0] = bincode_masks.pack().get_value();
            } else if (acl_field.type == la_acl_field_type_e::VRF_GID) {
                npl_key.ud_key.udfs[idx].value[0] = acl_field.val.udf.q_data[0];
                npl_key.ud_key.udfs[idx].value[1] = acl_field.val.udf.q_data[1];
                npl_mask.ud_key.udfs[idx].value[0] = acl_field.mask.udf.q_data[0];
                npl_mask.ud_key.udfs[idx].value[1] = acl_field.mask.udf.q_data[1];
                break;
            } else if (acl_field.type == la_acl_field_type_e::VLAN_OUTER) {
                // constuct key in the following way tpid(16 bits), pcp(3 bits), dei(1bit), vid(12 bits)
                vlan_key = acl_field.val.vlan1.tpid << VLAN_TPID_OFFSET;
                vlan_key += acl_field.val.vlan1.tci.fields.pcp << VLAN_PCP_OFFSET;
                vlan_key += acl_field.val.vlan1.tci.fields.dei << VLAN_DEI_OFFSET;
                vlan_key += acl_field.val.vlan1.tci.fields.vid;
                vlan_mask = acl_field.mask.vlan1.tpid << VLAN_TPID_OFFSET;
                vlan_mask += acl_field.mask.vlan1.tci.fields.pcp << VLAN_PCP_OFFSET;
                vlan_mask += acl_field.mask.vlan1.tci.fields.dei << VLAN_DEI_OFFSET;
                vlan_mask += acl_field.mask.vlan1.tci.fields.vid;
                npl_key.ud_key.udfs[idx].value[0] = vlan_key;
                npl_mask.ud_key.udfs[idx].value[0] = vlan_mask;
                break;
            } else if (acl_field.type == la_acl_field_type_e::VLAN_INNER) {
                vlan_key = acl_field.val.vlan2.tpid << VLAN_TPID_OFFSET;
                vlan_key += acl_field.val.vlan2.tci.fields.pcp << VLAN_PCP_OFFSET;
                vlan_key += acl_field.val.vlan2.tci.fields.dei << VLAN_DEI_OFFSET;
                vlan_key += acl_field.val.vlan2.tci.fields.vid;
                vlan_mask = acl_field.mask.vlan2.tpid << VLAN_TPID_OFFSET;
                vlan_mask += acl_field.mask.vlan2.tci.fields.pcp << VLAN_PCP_OFFSET;
                vlan_mask += acl_field.mask.vlan2.tci.fields.dei << VLAN_DEI_OFFSET;
                vlan_mask += acl_field.mask.vlan2.tci.fields.vid;
                npl_key.ud_key.udfs[idx].value[0] = vlan_key;
                npl_mask.ud_key.udfs[idx].value[0] = vlan_mask;
                break;
            } else {
                npl_key.ud_key.udfs[idx].value[0] = acl_field.val.udf.q_data[0];
                npl_key.ud_key.udfs[idx].value[1] = acl_field.val.udf.q_data[1];
                npl_mask.ud_key.udfs[idx].value[0] = acl_field.mask.udf.q_data[0];
                npl_mask.ud_key.udfs[idx].value[1] = acl_field.mask.udf.q_data[1];
                break;
            }
        }
    }
    return LA_STATUS_SUCCESS;
}

template <typename npl_table_key_t, typename is_udk<npl_table_key_t>::type* = nullptr>
la_status
ipv4_protocol_field_to_npl(const la_acl_key& key_mask, npl_table_key_t& npl_key, npl_table_key_t& npl_mask, la_uint8_t& idx)
{
    bool protocol = false;
    bool sport = false;
    bool msg_code = false;
    bool msg_type = false;
    la_uint8_t protocol_val = 0;
    la_uint8_t protocol_mask = 0;
    la_uint16_t sport_val = 0;
    la_uint16_t sport_mask = 0;
    la_uint8_t msg_code_val = 0;
    la_uint8_t msg_code_mask = 0;
    la_uint8_t msg_type_val = 0;
    la_uint8_t msg_type_mask = 0;

    for (auto acl_field_def : key_mask) {
        if (acl_field_def.type == la_acl_field_type_e::PROTOCOL) {
            protocol = true;
            protocol_val = acl_field_def.val.protocol;
            protocol_mask = acl_field_def.mask.protocol;
        }
        if (acl_field_def.type == la_acl_field_type_e::SPORT) {
            sport = true;
            sport_val = acl_field_def.val.sport;
            sport_mask = acl_field_def.mask.sport;
        }
        if (acl_field_def.type == la_acl_field_type_e::MSG_CODE) {
            msg_code = true;
            msg_code_val = acl_field_def.val.mcode;
            msg_code_mask = acl_field_def.mask.mcode;
        }
        if (acl_field_def.type == la_acl_field_type_e::MSG_TYPE) {
            msg_type = true;
            msg_type_val = acl_field_def.val.mtype;
            msg_type_mask = acl_field_def.mask.mtype;
        }
    }

    if (protocol || sport || msg_code || msg_type) {
        if (sport && (msg_code || msg_type)) {
            return LA_STATUS_EINVAL;
        }
        // step 1, configure the protocol
        if (protocol) {
            if (protocol_val == static_cast<la_uint8_t>(la_l4_protocol_e::TCP)) {
                npl_key.ud_key.udfs[idx].value[0] = NPL_ACL_TCP;
                npl_mask.ud_key.udfs[idx].value[0] = protocol_mask ? 0x3 : 0x0;
            } else if (protocol_val == static_cast<la_uint8_t>(la_l4_protocol_e::UDP)) {
                npl_key.ud_key.udfs[idx].value[0] = NPL_ACL_UDP;
                npl_mask.ud_key.udfs[idx].value[0] = protocol_mask ? 0x3 : 0x0;
            } else if (protocol_val == static_cast<la_uint8_t>(la_l4_protocol_e::ICMP)) {
                npl_key.ud_key.udfs[idx].value[0] = NPL_ACL_ICMP;
                npl_mask.ud_key.udfs[idx].value[0] = protocol_mask ? 0x3 : 0x0;
            } else {
                npl_key.ud_key.udfs[idx].value[0] = NPL_ACL_OTHER;
                npl_mask.ud_key.udfs[idx].value[0] = protocol_mask ? 0x3 : 0x0;
            }
        } else {
            if (sport) {
                npl_key.ud_key.udfs[idx].value[0] = NPL_ACL_TCP;
                npl_mask.ud_key.udfs[idx].value[0] = sport_mask ? NPL_ACL_UDP_TCP_MASK : 0x0;
            } else if (msg_code || msg_type) {
                npl_key.ud_key.udfs[idx].value[0] = NPL_ACL_ICMP;
                npl_mask.ud_key.udfs[idx].value[0] = (msg_code_mask || msg_type_mask) ? 0x3 : 0x0;
            }
        }
        idx++;

        // step 2, configure the sport_or_msg_type_or_l4_protocol
        if (npl_key.ud_key.udfs[idx - 1].value[0] == NPL_ACL_OTHER) {
            npl_key.ud_key.udfs[idx].value[0] = protocol_val;
            npl_mask.ud_key.udfs[idx].value[0] = protocol_mask;
        } else if (sport) {
            npl_key.ud_key.udfs[idx].value[0] = sport_val;
            npl_mask.ud_key.udfs[idx].value[0] = sport_mask;
        } else {
            if (msg_code) {
                npl_key.ud_key.udfs[idx].value[0] = bit_utils::set_bits(npl_key.ud_key.udfs[idx].value[0], 7, 0, msg_code_val);
                npl_mask.ud_key.udfs[idx].value[0] = bit_utils::set_bits(npl_mask.ud_key.udfs[idx].value[0], 7, 0, msg_code_mask);
            }
            if (msg_type) {
                npl_key.ud_key.udfs[idx].value[0] = bit_utils::set_bits(npl_key.ud_key.udfs[idx].value[0], 15, 8, msg_type_val);
                npl_mask.ud_key.udfs[idx].value[0] = bit_utils::set_bits(npl_mask.ud_key.udfs[idx].value[0], 15, 8, msg_type_mask);
            }
        }
        idx++;
    }

    return LA_STATUS_SUCCESS;
}

template <typename npl_table_key_t, typename is_udk<npl_table_key_t>::type* = nullptr>
la_status
ipv6_next_header_field_to_npl(const la_acl_key& key_mask, npl_table_key_t& npl_key, npl_table_key_t& npl_mask, la_uint8_t& idx)
{
    bool last_next_header = false;
    bool sport = false;
    bool msg_code = false;
    bool msg_type = false;
    la_uint8_t last_next_header_val = 0;
    la_uint8_t last_next_header_mask = 0;
    la_uint16_t sport_val = 0;
    la_uint16_t sport_mask = 0;
    la_uint8_t msg_code_val = 0;
    la_uint8_t msg_code_mask = 0;
    la_uint8_t msg_type_val = 0;
    la_uint8_t msg_type_mask = 0;

    for (auto acl_field_def : key_mask) {
        if (acl_field_def.type == la_acl_field_type_e::LAST_NEXT_HEADER) {
            last_next_header = true;
            last_next_header_val = acl_field_def.val.last_next_header;
            last_next_header_mask = acl_field_def.mask.last_next_header;
        }
        if (acl_field_def.type == la_acl_field_type_e::SPORT) {
            sport = true;
            sport_val = acl_field_def.val.sport;
            sport_mask = acl_field_def.mask.sport;
        }
        if (acl_field_def.type == la_acl_field_type_e::MSG_CODE) {
            msg_code = true;
            msg_code_val = acl_field_def.val.mcode;
            msg_code_mask = acl_field_def.mask.mcode;
        }
        if (acl_field_def.type == la_acl_field_type_e::MSG_TYPE) {
            msg_type = true;
            msg_type_val = acl_field_def.val.mtype;
            msg_type_mask = acl_field_def.mask.mtype;
        }
    }

    if (last_next_header || sport || msg_code || msg_type) {
        if (sport && (msg_code || msg_type)) {
            return LA_STATUS_EINVAL;
        }
        // step 1, configure the next_header type
        if (last_next_header) {
            if (last_next_header_val == static_cast<la_uint8_t>(la_l4_protocol_e::TCP)) {
                npl_key.ud_key.udfs[idx].value[0] = NPL_ACL_TCP;
                npl_mask.ud_key.udfs[idx].value[0] = last_next_header_mask ? 0x3 : 0x0;
            } else if (last_next_header_val == static_cast<la_uint8_t>(la_l4_protocol_e::UDP)) {
                npl_key.ud_key.udfs[idx].value[0] = NPL_ACL_UDP;
                npl_mask.ud_key.udfs[idx].value[0] = last_next_header_mask ? 0x3 : 0x0;
            } else if (last_next_header_val == static_cast<la_uint8_t>(la_l4_protocol_e::IPV6_ICMP)) {
                npl_key.ud_key.udfs[idx].value[0] = NPL_ACL_ICMP;
                npl_mask.ud_key.udfs[idx].value[0] = last_next_header_mask ? 0x3 : 0x0;
            } else {
                npl_key.ud_key.udfs[idx].value[0] = NPL_ACL_OTHER;
                npl_mask.ud_key.udfs[idx].value[0] = last_next_header_mask ? 0x3 : 0x0;
            }
        } else {
            if (sport) {
                npl_key.ud_key.udfs[idx].value[0] = NPL_ACL_TCP;
                npl_mask.ud_key.udfs[idx].value[0] = sport_mask ? NPL_ACL_UDP_TCP_MASK : 0x0;
            } else if (msg_code || msg_type) {
                npl_key.ud_key.udfs[idx].value[0] = NPL_ACL_ICMP;
                npl_mask.ud_key.udfs[idx].value[0] = (msg_code_mask || msg_type_mask) ? 0x3 : 0x0;
            }
        }
        idx++;

        // step 2, configure the sport_or_msg_type_or_l4_protocol
        if (npl_key.ud_key.udfs[idx - 1].value[0] == NPL_ACL_OTHER) {
            npl_key.ud_key.udfs[idx].value[0] = last_next_header_val << 8;
            npl_mask.ud_key.udfs[idx].value[0] = last_next_header_mask << 8;
        } else if (sport) {
            npl_key.ud_key.udfs[idx].value[0] = sport_val;
            npl_mask.ud_key.udfs[idx].value[0] = sport_mask;
        } else {
            if (msg_code) {
                npl_key.ud_key.udfs[idx].value[0] = bit_utils::set_bits(npl_key.ud_key.udfs[idx].value[0], 7, 0, msg_code_val);
                npl_mask.ud_key.udfs[idx].value[0] = bit_utils::set_bits(npl_mask.ud_key.udfs[idx].value[0], 7, 0, msg_code_mask);
            }
            if (msg_type) {
                npl_key.ud_key.udfs[idx].value[0] = bit_utils::set_bits(npl_key.ud_key.udfs[idx].value[0], 15, 8, msg_type_val);
                npl_mask.ud_key.udfs[idx].value[0] = bit_utils::set_bits(npl_mask.ud_key.udfs[idx].value[0], 15, 8, msg_type_mask);
            }
        }
        idx++;
    }

    return LA_STATUS_SUCCESS;
}

// field_to_npl for ipv6 rtf fields (160 and 320 key sizes)
template <typename npl_table_key_t, typename is_ipv6_rtf<npl_table_key_t>::type* = nullptr>
la_status
field_to_npl(const la_acl_field_def acl_field_def,
             const la_acl_key& key_mask,
             npl_table_key_t& npl_key,
             npl_table_key_t& npl_mask,
             la_uint8_t& idx)
{
    npl_object_groups_t bincode_keys;
    npl_object_groups_t bincode_masks;
    npl_sport_or_l4_protocol_t l4_data_key;
    npl_sport_or_l4_protocol_t l4_data_mask;

    memset(&bincode_keys, 0, sizeof(bincode_keys));
    memset(&bincode_masks, 0, sizeof(bincode_masks));
    la_uint32_t vlan_key = 0;
    la_uint32_t vlan_mask = 0;

    if ((acl_field_def.type == la_acl_field_type_e::LAST_NEXT_HEADER) || (acl_field_def.type == la_acl_field_type_e::SPORT)
        || (acl_field_def.type == la_acl_field_type_e::MSG_CODE)
        || (acl_field_def.type == la_acl_field_type_e::MSG_TYPE)) {
        idx--;
        return LA_STATUS_SUCCESS;
    }

    for (const auto acl_field : key_mask) {
        /*
         * The following for loop only processes a particular field
         * when the field definition and the field type match, with the
         * following exception: if the field type is DST_PCL_BINCODE
         * and the field definition is SRC_PCL_BINCODE, it is processed
         * as a single field in the key.
         */
        if (((acl_field.type == la_acl_field_type_e::DST_PCL_BINCODE)
             && (acl_field_def.type == la_acl_field_type_e::SRC_PCL_BINCODE))
            || (acl_field_def.type == acl_field.type)) {

            if (acl_field_def.type == la_acl_field_type_e::UDF) {
                if (acl_field_def.udf_desc.index == acl_field.udf_index) {
                    npl_key.ud_key.udfs[idx].value[0] = acl_field.val.udf.q_data[0];
                    npl_key.ud_key.udfs[idx].value[1] = acl_field.val.udf.q_data[1];
                    npl_mask.ud_key.udfs[idx].value[0] = acl_field.mask.udf.q_data[0];
                    npl_mask.ud_key.udfs[idx].value[1] = acl_field.mask.udf.q_data[1];
                    break;
                }
            } else if (acl_field_def.type == la_acl_field_type_e::IPV6_FRAGMENT) {
                // Today there is support only for not-first-fragment match in NPL, so can ignore df & mf
                npl_key.ud_key.udfs[idx].value[0] = static_cast<npl_bool_e>(~acl_field.val.ipv6_fragment.fragment);
                npl_mask.ud_key.udfs[idx].value[0] = static_cast<npl_bool_e>(acl_field.mask.ipv6_fragment.fragment);
                break;
            } else if (acl_field.type == la_acl_field_type_e::DST_PCL_BINCODE) {
                bincode_keys.dest_code.bits_17_0 = acl_field.val.udf.q_data[0];
                bincode_keys.dest_code.bits_n_18 = acl_field.val.udf.q_data[0] >> 18;
                bincode_masks.dest_code.bits_17_0 = acl_field.mask.udf.q_data[0];
                bincode_masks.dest_code.bits_n_18 = acl_field.mask.udf.q_data[0] >> 18;
                npl_key.ud_key.udfs[idx].value[0] = bincode_keys.pack().get_value();
                npl_mask.ud_key.udfs[idx].value[0] = bincode_masks.pack().get_value();
                break;
            } else if (acl_field.type == la_acl_field_type_e::SRC_PCL_BINCODE) {
                bincode_keys.src_code.bits_17_0 = acl_field.val.udf.q_data[0];
                bincode_keys.src_code.bits_n_18 = acl_field.val.udf.q_data[0] >> 18;
                bincode_masks.src_code.bits_17_0 = acl_field.mask.udf.q_data[0];
                bincode_masks.src_code.bits_n_18 = acl_field.mask.udf.q_data[0] >> 18;
                npl_key.ud_key.udfs[idx].value[0] = bincode_keys.pack().get_value();
                npl_mask.ud_key.udfs[idx].value[0] = bincode_masks.pack().get_value();
            } else if (acl_field.type == la_acl_field_type_e::VRF_GID) {
                npl_key.ud_key.udfs[idx].value[0] = acl_field.val.udf.q_data[0];
                npl_key.ud_key.udfs[idx].value[1] = acl_field.val.udf.q_data[1];
                npl_mask.ud_key.udfs[idx].value[0] = acl_field.mask.udf.q_data[0];
                npl_mask.ud_key.udfs[idx].value[1] = acl_field.mask.udf.q_data[1];
                break;
            } else if (acl_field.type == la_acl_field_type_e::VLAN_OUTER) {
                // constuct key in the following way tpid(16 bits), pcp(3 bits), dei(1bit), vid(12 bits)
                vlan_key = acl_field.val.vlan1.tpid << VLAN_TPID_OFFSET;
                vlan_key += acl_field.val.vlan1.tci.fields.pcp << VLAN_PCP_OFFSET;
                vlan_key += acl_field.val.vlan1.tci.fields.dei << VLAN_DEI_OFFSET;
                vlan_key += acl_field.val.vlan1.tci.fields.vid;
                vlan_mask = acl_field.mask.vlan1.tpid << VLAN_TPID_OFFSET;
                vlan_mask += acl_field.mask.vlan1.tci.fields.pcp << VLAN_PCP_OFFSET;
                vlan_mask += acl_field.mask.vlan1.tci.fields.dei << VLAN_DEI_OFFSET;
                vlan_mask += acl_field.mask.vlan1.tci.fields.vid;
                npl_key.ud_key.udfs[idx].value[0] = vlan_key;
                npl_mask.ud_key.udfs[idx].value[0] = vlan_mask;
                break;
            } else if (acl_field.type == la_acl_field_type_e::VLAN_INNER) {
                vlan_key = acl_field.val.vlan2.tpid << VLAN_TPID_OFFSET;
                vlan_key += acl_field.val.vlan2.tci.fields.pcp << VLAN_PCP_OFFSET;
                vlan_key += acl_field.val.vlan2.tci.fields.dei << VLAN_DEI_OFFSET;
                vlan_key += acl_field.val.vlan2.tci.fields.vid;
                vlan_mask = acl_field.mask.vlan2.tpid << VLAN_TPID_OFFSET;
                vlan_mask += acl_field.mask.vlan2.tci.fields.pcp << VLAN_PCP_OFFSET;
                vlan_mask += acl_field.mask.vlan2.tci.fields.dei << VLAN_DEI_OFFSET;
                vlan_mask += acl_field.mask.vlan2.tci.fields.vid;
                npl_key.ud_key.udfs[idx].value[0] = vlan_key;
                npl_mask.ud_key.udfs[idx].value[0] = vlan_mask;
                break;
            } else if (acl_field.type == la_acl_field_type_e::LAST_NEXT_HEADER) {
                if (acl_field.val.last_next_header == static_cast<la_uint8_t>(la_l4_protocol_e::TCP)) {
                    npl_key.ud_key.udfs[idx].value[0] = NPL_ACL_TCP;
                    npl_mask.ud_key.udfs[idx].value[0] = 0x3;
                } else if (acl_field.val.last_next_header == static_cast<la_uint8_t>(la_l4_protocol_e::UDP)) {
                    npl_key.ud_key.udfs[idx].value[0] = NPL_ACL_UDP;
                    npl_mask.ud_key.udfs[idx].value[0] = 0x3;
                } else if (acl_field.val.last_next_header == static_cast<la_uint8_t>(la_l4_protocol_e::IPV6_ICMP)) {
                    npl_key.ud_key.udfs[idx].value[0] = NPL_ACL_ICMP;
                    npl_mask.ud_key.udfs[idx].value[0] = 0x3;
                } else {

                    npl_key.ud_key.udfs[idx].value[0] = NPL_ACL_OTHER;
                    npl_mask.ud_key.udfs[idx].value[0] = 0xff;
                }
                break;
            } else if (acl_field.type == la_acl_field_type_e::SPORT) {
                l4_data_key.sport_or_l4_protocol_type.src_port = acl_field.val.sport;
                l4_data_mask.sport_or_l4_protocol_type.src_port = acl_field.mask.sport;
                npl_key.ud_key.udfs[idx].value[0] = l4_data_key.pack().get_value();
                npl_mask.ud_key.udfs[idx].value[0] = l4_data_mask.pack().get_value();
                break;
            } else if (acl_field.type == la_acl_field_type_e::MSG_CODE) {
                l4_data_key.sport_or_l4_protocol_type.icmp_type_code.code = acl_field.val.mcode;
                l4_data_mask.sport_or_l4_protocol_type.icmp_type_code.code = acl_field.mask.mcode;
                npl_key.ud_key.udfs[idx].value[0] = l4_data_key.pack().get_value();
                npl_mask.ud_key.udfs[idx].value[0] = l4_data_mask.pack().get_value();
                break;
            } else if (acl_field.type == la_acl_field_type_e::MSG_TYPE) {
                l4_data_key.sport_or_l4_protocol_type.icmp_type_code.type = acl_field.val.mtype;
                l4_data_mask.sport_or_l4_protocol_type.icmp_type_code.type = acl_field.mask.mtype;
                npl_key.ud_key.udfs[idx].value[0] = l4_data_key.pack().get_value();
                npl_mask.ud_key.udfs[idx].value[0] = l4_data_mask.pack().get_value();
                break;
            } else {
                npl_key.ud_key.udfs[idx].value[0] = acl_field.val.udf.q_data[0];
                npl_key.ud_key.udfs[idx].value[1] = acl_field.val.udf.q_data[1];
                npl_mask.ud_key.udfs[idx].value[0] = acl_field.mask.udf.q_data[0];
                npl_mask.ud_key.udfs[idx].value[1] = acl_field.mask.udf.q_data[1];
                break;
            }
        }
    }
    return LA_STATUS_SUCCESS;
}

// copy_key_mask_to_npl for UDK fields (160 and 320 key sizes)
template <typename npl_table_key_t, typename is_udk<npl_table_key_t>::type* = nullptr>
la_status
copy_key_mask_to_npl(la_slice_id_t slice,
                     la_acl_id_t acl_id,
                     la_acl_id_t acl_id_mask,
                     const la_acl_key_def_vec_t& key_def,
                     const la_acl_key& key_mask,
                     npl_table_key_t& npl_key,
                     npl_table_key_t& npl_mask)
{
    la_uint8_t idx = 0;

    // ACL ID
    npl_key.ud_key.udfs[idx].value[0] = acl_id;
    npl_mask.ud_key.udfs[idx].value[0] = acl_id_mask;
    idx++;

    for (auto acl_field_def : key_def) {
        if (acl_field_def.type == la_acl_field_type_e::DST_PCL_BINCODE) {
            continue;
        }
        la_status status = field_to_npl(acl_field_def, key_mask, npl_key, npl_mask, idx);
        return_on_error(status);
        idx++;
    }

    constexpr bool is_ipv4 = std::is_same<npl_table_key_t, npl_ingress_rtf_ipv4_db1_160_f0_table_key_t>::value
                             || std::is_same<npl_table_key_t, npl_ingress_rtf_ipv4_db2_160_f0_table_key_t>::value
                             || std::is_same<npl_table_key_t, npl_ingress_rtf_ipv4_db3_160_f0_table_key_t>::value
                             || std::is_same<npl_table_key_t, npl_ingress_rtf_ipv4_db4_160_f0_table_key_t>::value
                             || std::is_same<npl_table_key_t, npl_ingress_rtf_ipv4_db1_320_f0_table_key_t>::value
                             || std::is_same<npl_table_key_t, npl_ingress_rtf_ipv4_db2_320_f0_table_key_t>::value
                             || std::is_same<npl_table_key_t, npl_ingress_rtf_ipv4_db3_320_f0_table_key_t>::value
                             || std::is_same<npl_table_key_t, npl_ingress_rtf_ipv4_db4_320_f0_table_key_t>::value;

    constexpr bool is_ipv6 = std::is_same<npl_table_key_t, npl_ingress_rtf_ipv6_db1_160_f0_table_key_t>::value
                             || std::is_same<npl_table_key_t, npl_ingress_rtf_ipv6_db2_160_f0_table_key_t>::value
                             || std::is_same<npl_table_key_t, npl_ingress_rtf_ipv6_db3_160_f0_table_key_t>::value
                             || std::is_same<npl_table_key_t, npl_ingress_rtf_ipv6_db4_160_f0_table_key_t>::value
                             || std::is_same<npl_table_key_t, npl_ingress_rtf_ipv6_db1_320_f0_table_key_t>::value
                             || std::is_same<npl_table_key_t, npl_ingress_rtf_ipv6_db2_320_f0_table_key_t>::value
                             || std::is_same<npl_table_key_t, npl_ingress_rtf_ipv6_db3_320_f0_table_key_t>::value
                             || std::is_same<npl_table_key_t, npl_ingress_rtf_ipv6_db4_320_f0_table_key_t>::value;

    if (is_ipv4) {
        la_status status = ipv4_protocol_field_to_npl(key_mask, npl_key, npl_mask, idx);
        return_on_error(status);
    } else if (is_ipv6) {
        la_status status = ipv6_next_header_field_to_npl(key_mask, npl_key, npl_mask, idx);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

// copy_npl_to_key_mask for UDK fields (160 and 320 key sizes)
template <typename npl_table_key_t, typename is_udk<npl_table_key_t>::type* = nullptr>
la_status
copy_npl_to_key_mask(const la_acl_key_def_vec_t& key_def,
                     const npl_table_key_t& npl_key,
                     const npl_table_key_t& npl_mask,
                     la_acl_key& out_key_mask)
{
    la_acl_field acl_field;
    la_uint8_t idx = 0;

    // ACL ID, need to define a well-known field id for it yet.
    acl_field.val.udf.s_data = npl_key.ud_key.udfs[idx].pack().get_value();
    acl_field.mask.udf.s_data = npl_mask.ud_key.udfs[idx].pack().get_value();
    idx++;
    constexpr bool is_ipv6 = std::is_same<npl_table_key_t, npl_ingress_rtf_ipv6_db1_320_f0_table_key_t>::value;

    for (auto acl_field_def : key_def) {
        memset(&acl_field, 0, sizeof(acl_field));
        acl_field.type = acl_field_def.type;
        acl_field.val.udf.s_data = npl_key.ud_key.udfs[idx].pack().get_value();
        acl_field.mask.udf.s_data = npl_mask.ud_key.udfs[idx].pack().get_value();
        if (is_ipv6) {
            if (acl_field_def.type == la_acl_field_type_e::IPV6_FRAGMENT) {
                acl_field.val.ipv6_fragment.fragment = ~acl_field.val.ipv6_fragment.fragment;
            }
        } else {
            if (acl_field_def.type == la_acl_field_type_e::IPV4_FLAGS) {
                acl_field.val.ipv4_flags.fragment = ~acl_field.val.ipv4_flags.fragment;
            }
        }

        out_key_mask.push_back(acl_field);
        idx++;
    }

    out_key_mask.push_back(acl_field);

    return LA_STATUS_SUCCESS;
}

// get_acl_id for UDK
template <typename npl_table_key_t, typename is_udk<npl_table_key_t>::type* = nullptr>
la_acl_id_t
get_npl_acl_id(const la_acl_key_def_vec_t& key_def, const npl_table_key_t& npl_key)
{
    return npl_key.ud_key.udfs[0].pack().get_value();
}
}
#endif // __LA_ACL_KEY_UTILS_H__
