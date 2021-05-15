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

#ifndef __LA_ACL_KEY_PROFILE_BASE_H__
#define __LA_ACL_KEY_PROFILE_BASE_H__

#include <vector>

#include "api/npu/la_acl_key_profile.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "nplapi/npl_enums.h"
#include "nplapi/npl_tables_enum.h"
#include "nplapi/nplapi_fwd.h"
#include "runtime_flexibility_library.h"

namespace silicon_one
{

class la_device_impl;

class la_acl_key_profile_base : public la_acl_key_profile
{
    ////////// Serialization ///////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    ////////////////////////////////////

public:
    /// @brief ACL key size.
    enum class key_size_e {
        SIZE_160, ///< Key size is 160b.
        SIZE_320, ///< Key size is 320b.
    };

    explicit la_acl_key_profile_base(const la_device_impl_wptr& device);
    ~la_acl_key_profile_base() override;
    la_status initialize(la_object_id_t oid,
                         la_acl_key_type_e key_type,
                         la_acl_direction_e dir,
                         const la_acl_key_def_vec_t& key_def,
                         la_acl_tcam_pool_id_t tcam_pool_id);
    la_status destroy();

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // la_acl_key_profile API-s
    la_status get_key_type(la_acl_key_type_e& out_key_type) const override;
    la_status get_key_definition(la_acl_key_def_vec_t& out_key_def_vec) const override;
    la_acl_tcam_pool_id_t get_key_tcam_pool_id() const override;
    la_acl_direction_e get_direction() const override;

    // Implementation
    key_size_e get_key_size() const;
    uint64_t get_udk_table_id() const;

    const udk_translation_info_sptr& get_translation_info();
    la_status update_all_acl_key_profiles();
    la_status microcode_update();

    la_status get_fwd0_table_index(npl_fwd0_table_index_e& out_table_index) const;
    la_status get_fwd1_table_index(npl_fwd1_table_index_e& out_table_index) const;
    la_status get_eth_rtf_macro_table_id(npl_network_rx_eth_rtf_macro_table_id_e& out_table_id) const;
    la_status get_ipv4_rtf_macro_table_id(npl_network_rx_ipv4_rtf_macro_table_id_e& out_table_id) const;
    la_status get_ipv6_rtf_macro_table_id(npl_network_rx_ipv6_rtf_macro_table_id_e& out_table_id) const;
    la_status get_npl_table_id(npl_tables_e& out_table) const;
    la_status get_allocated_table_id(uint64_t& out_table_id) const;

protected:
    static constexpr int8_t SOP = 0;
    static constexpr int8_t CURRENT_PROTOCOL_LAYER = 0;
    static constexpr int8_t CURRENT_HEADER = 0;
    static constexpr int8_t NEXT_HEADER = 1;
    static constexpr int8_t NEXT_NEXT_HEADER = 2;
    static constexpr la_uint16_t DA_WIDTH = 6;
    static constexpr la_uint16_t DA_OFFSET = 0;
    static constexpr la_uint16_t SA_WIDTH = 6;
    static constexpr la_uint16_t SA_OFFSET = 6;
    static constexpr la_uint16_t ETHER_TYPE_WIDTH = 2;
    static constexpr la_uint16_t ETHER_TYPE_OFFSET = 12;
    static constexpr la_uint16_t VLAN_OUTER_WIDTH = 4;
    static constexpr la_uint16_t VLAN_INNER_WIDTH = 4;
    static constexpr la_uint16_t TOS_WIDTH = 1;
    static constexpr la_uint16_t TOS_OFFSET = 1;
    static constexpr la_uint16_t IPV4_LENGTH_WIDTH = 2;
    static constexpr la_uint16_t IPV4_LENGTH_OFFSET = 2;
    static constexpr la_uint16_t IPV6_LENGTH_WIDTH = 2;
    static constexpr la_uint16_t IPV6_LENGTH_OFFSET = 4;
    static constexpr la_uint16_t IPV4_FRAG_OFFSET_WIDTH = 2;
    static constexpr la_uint16_t IPV4_FRAG_OFFSET_OFFSET = 6;
    static constexpr la_uint16_t TTL_WIDTH = 1;
    static constexpr la_uint16_t TTL_OFFSET = 8;
    static constexpr la_uint16_t PROTOCOL_WIDTH = 1;
    static constexpr la_uint16_t PROTOCOL_OFFSET = 9;
    static constexpr la_uint16_t IPV4_SIP_WIDTH = 4;
    static constexpr la_uint16_t IPV4_SIP_OFFSET = 12;
    static constexpr la_uint16_t IPV4_DIP_WIDTH = 4;
    static constexpr la_uint16_t IPV4_DIP_OFFSET = 16;
    static constexpr la_uint16_t SPORT_WIDTH = 2;
    static constexpr la_uint16_t SPORT_OFFSET = 0;
    static constexpr la_uint16_t DPORT_WIDTH = 2;
    static constexpr la_uint16_t DPORT_OFFSET = 2;
    static constexpr la_uint16_t MSG_TYPE_WIDTH = 1;
    static constexpr la_uint16_t MSG_TYPE_OFFSET = 0;
    static constexpr la_uint16_t MSG_CODE_WIDTH = 1;
    static constexpr la_uint16_t MSG_CODE_OFFSET = 1;
    static constexpr la_uint16_t TCP_FLAGS_WIDTH = 1;
    static constexpr la_uint16_t TCP_FLAGS_OFFSET = 13;
    static constexpr la_uint16_t TRAFFIC_CLASS_WIDTH = 2;  // Actually 1B only
    static constexpr la_uint16_t TRAFFIC_CLASS_OFFSET = 0; // Starts at 4b of first byte, how to specify that??
    static constexpr la_uint16_t HOP_LIMIT_WIDTH = 1;
    static constexpr la_uint16_t HOP_LIMIT_OFFSET = 7;
    static constexpr la_uint16_t IPV6_SIP_WIDTH = 16;
    static constexpr la_uint16_t IPV6_SIP_OFFSET = 8;
    static constexpr la_uint16_t IPV6_DIP_WIDTH = 16;
    static constexpr la_uint16_t IPV6_DIP_OFFSET = 24;

    static constexpr uint64_t INVALID_UDK_TABLE_ID = 0xFFFFFFFF;

    // Containing device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    // ACL key
    la_acl_key_def_vec_t m_acl_key;

    // Key type of the ACL.
    la_acl_key_type_e m_key_type;

    // Direction of the ACL.
    la_acl_direction_e m_dir;

    // Key size
    key_size_e m_key_size;

    // Tcam pool id
    la_acl_tcam_pool_id_t m_tcam_pool_id;

    // UDF NPL
    std::vector<microcode_write> m_microcode_writes;

    // Translation info
    std::vector<udk_translation_info_sptr> m_trans_info;

    // Assigned UDK table id
    uint64_t m_udk_table_id;

    npl_fwd0_table_index_e m_fwd0_table_index;
    npl_fwd1_table_index_e m_fwd1_table_index;
    npl_network_rx_eth_rtf_macro_table_id_e m_eth_rtf_macro_table_id;
    npl_network_rx_ipv4_rtf_macro_table_id_e m_ipv4_rtf_macro_table_id;
    npl_network_rx_ipv6_rtf_macro_table_id_e m_ipv6_rtf_macro_table_id;
    npl_tables_e m_npl_table_e;
    uint64_t m_allocated_table_id;

    // For serialization
    la_acl_key_profile_base(){};

    // Helper functions
    la_status prepare_place_udk_data(la_acl_key_type_e key_type,
                                     std::vector<udk_table_id_and_components>& udk_table_id_and_components,
                                     std::vector<udk_translation_info>& trans_info);
    la_status place_udk_for_key_type(la_acl_key_type_e key_type);
    la_status trans_info_update();
    la_status validate_key_profile(la_acl_key_type_e key_type,
                                   la_acl_direction_e dir,
                                   const la_acl_key_def_vec_t& key_def,
                                   la_acl_tcam_pool_id_t tcam_pool_id) const;

    virtual la_status fill_ethernet_udk_components(std::vector<udk_component>& udk_components, const la_acl_key_def_vec_t& key_def)
        = 0;
    virtual la_status fill_v4_udk_components(std::vector<udk_component>& udk_components, const la_acl_key_def_vec_t& key_def) = 0;
    virtual la_status fill_v6_udk_components(std::vector<udk_component>& udk_components, const la_acl_key_def_vec_t& key_def) = 0;
    la_status allocate_table_id(la_acl_key_type_e key_type,
                                key_size_e key_size,
                                la_acl_tcam_pool_id_t _tcam_pool_id,
                                uint64_t& out_table_id);
    la_status release_table_id(la_acl_key_type_e key_type,
                               key_size_e key_size,
                               la_acl_tcam_pool_id_t _tcam_pool_id,
                               uint64_t table_id);
    la_status update_all_table_ids(la_acl_key_type_e key_type,
                                   key_size_e key_size,
                                   la_acl_tcam_pool_id_t tcam_pool_id,
                                   uint64_t udk_table_id);

    virtual int8_t get_vlan_outer_offset() const = 0;
    virtual int8_t get_vlan_inner_offset() const = 0;
};

} // namespace silicon_one

#endif //  __LA_ACL_KEY_PROFILE_BASE_H__
