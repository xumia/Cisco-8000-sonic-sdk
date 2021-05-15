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

#ifndef __LA_COPC_BASE_H__
#define __LA_COPC_BASE_H__

#include "api/npu/la_copc.h"
#include "hld_types_fwd.h"
#include "hld_utils.h"
#include "nplapi/nplapi_tables.h"

#include <deque>

namespace silicon_one
{

class la_copc_base : public la_control_plane_classifier
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief COPC L4 port key struct.
    struct copc_key_l4_ports_t {
        la_uint16_t src_port; ///< Source port
        la_uint16_t dst_port; ///< Destination port
    };

    /// @brief COPC IPv4 key structure.
    struct copc_key_ipv4_t {
        silicon_one::la_ipv4_addr_t dip;       ///< Destination IP address
        la_uint8_t protocol;                   ///< L4 protocol
        copc_key_l4_ports_t l4_ports;          ///< L4 ports
        la_uint8_t npp_attributes;             ///< NPP attributes
        la_uint8_t bd_attributes;              ///< BD attributes
        la_uint8_t l2_service_port_attributes; ///< L2 service port attributes
        la_uint8_t mac_lp_type;                ///< MAC logical port type
        la_uint8_t ttl;                        ///< TTL
        bool my_mac;                           ///< Mac terminated
        bool is_svi;                           ///< Is SVI
        bool has_vlan_tag;                     ///< Has vlan tag
        bool ip_not_first_fragment;            ///< Boolean flag for fragmented packet
    };

    /// @brief COPC IPv6 key structure.
    struct copc_key_ipv6_t {
        silicon_one::la_ipv6_addr_t dip;       ///< Destination IP address
        la_uint8_t next_header;                ///< L4 protocol
        copc_key_l4_ports_t l4_ports;          ///< L4 ports
        la_uint8_t npp_attributes;             ///< NPP attributes
        la_uint8_t bd_attributes;              ///< BD attributes
        la_uint8_t l2_service_port_attributes; ///< L2 service port attributes
        la_uint8_t mac_lp_type;                ///< MAC logical port type
        la_uint8_t hop_limit;                  ///< TTL
        bool my_mac;                           ///< Mac terminated
        bool is_svi;                           ///< Is SVI
        bool has_vlan_tag;                     ///< Has vlan tag
        bool ip_not_first_fragment;            ///< Boolean flag for non first fragment
    };

    /// @brief COPC MAC key structure.
    struct copc_key_mac_t {
        la_mac_addr_t mac_da;                  ///< MAC DA Type
        la_uint16_t ether_type;                ///< Ether Type
        la_uint8_t npp_attributes;             ///< NPP attributes
        la_uint8_t bd_attributes;              ///< BD attributes
        la_uint8_t l2_service_port_attributes; ///< L2 service port attributes
        la_uint8_t mac_lp_type;                ///< MAC logical port type
        bool my_mac;                           ///< Mac terminated
        bool is_svi;                           ///< Is SVI
        bool has_vlan_tag;                     ///< Has vlan tag
    };

    /// union of all ctcam table structures
    union copc_key_fields_t {
        copc_key_ipv4_t ipv4;
        copc_key_ipv6_t ipv6;
        copc_key_mac_t mac;
    };

    /// @brief COPC key - value and mask
    struct copc_key_t {
        la_control_plane_classifier::type_e type; ///< key type
        copc_key_fields_t val;                    ///< Key value
        copc_key_fields_t mask;                   ///< Key mask - which fields of the value are valid
    };

    /// @brief COPC result.
    struct copc_result_t {
        la_event_e event; ///< COPC result trap for COPC entry.
    };

    /// @brief COPC entry information.
    struct copc_entry_desc_t {
        copc_key_t key_val;   ///< Entry key.
        copc_result_t result; ///< Entry value.
    };
    explicit la_copc_base(la_device_impl_wptr device);
    ~la_copc_base() override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid, la_control_plane_classifier::type_e type);
    la_status destroy();

    // la_object API-s
    object_type_e type() const override;
    std::string to_string() const override;
    la_object_id_t oid() const override;
    const la_device* get_device() const override;
    la_status get_copc_type(la_control_plane_classifier::type_e& out_type) const override;
    la_status get_count(size_t& out_count) const override;
    la_status append(const la_control_plane_classifier::key& key, const la_control_plane_classifier::result& result) override;
    la_status push(size_t position,
                   const la_control_plane_classifier::key& key,
                   const la_control_plane_classifier::result& result) override;
    la_status set(size_t position,
                  const la_control_plane_classifier::key& key,
                  const la_control_plane_classifier::result& result) override;
    la_status pop(size_t position) override;
    la_status get(size_t position, la_control_plane_classifier::entry_desc& out_copc_entry_desc) const override;
    la_status clear() override;
    slice_ifg_vec_t get_ifgs() const;

protected:
    /// Device this ethernet port belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    // COPC Type
    la_control_plane_classifier::type_e m_type;

    // Shadow of configured COPC entries
    std::deque<la_control_plane_classifier::entry_desc> m_entries;

    la_copc_base() = default; // For serialization only.

private:
    // Helper functions
    la_status get_tcam_size(la_slice_id_t slice, size_t& size) const;
    la_status get_tcam_fullness(la_slice_id_t slice, size_t& size) const;
    la_status get_tcam_line_index(la_slice_id_t slice, size_t position, size_t& tcam_line_index) const;
    la_status is_tcam_line_contains_entry(la_slice_id_t slice, size_t tcam_line, bool& contains) const;
    la_status pop_tcam_table_entry(la_slice_id_t slice, size_t tcam_line);
    la_status is_tcam_available();
    la_status set_tcam_line(size_t position, const copc_key_t& key_val, const copc_result_t& result);

    // Copy to NPL functions
    la_status convert_trap_to_npl_result(const la_event_e& event, npl_l2_lpts_payload_t& result_event);
    la_status copy_key_mask_to_npl(const copc_key_ipv4_t& key_mask,
                                   npl_l2_lpts_ipv4_table_t::key_type& npl_key_mask,
                                   bool is_mask) const;
    la_status copy_result_to_npl(const copc_result_t& result, npl_l2_lpts_ipv4_table_l2_lpts_result_payload_t& l2_lpts_result);
    la_status copy_key_mask_to_npl(const copc_key_ipv6_t& key_mask,
                                   npl_l2_lpts_ipv6_table_t::key_type& npl_key_mask,
                                   bool is_mask) const;
    la_status copy_result_to_npl(const copc_result_t& result, npl_l2_lpts_ipv6_table_l2_lpts_result_payload_t& l2_lpts_result);
    la_status copy_key_mask_to_npl(const copc_key_mac_t& key_mask,
                                   npl_l2_lpts_mac_table_t::key_type& npl_key_mask,
                                   bool is_mask) const;
    la_status copy_result_to_npl(const copc_result_t& result, npl_l2_lpts_mac_table_l2_lpts_result_payload_t& l2_lpts_result);
    la_status populate_tcam_key_value_result(npl_l2_lpts_ipv4_table_t::key_type& out_key,
                                             npl_l2_lpts_ipv4_table_t::key_type& out_mask,
                                             npl_l2_lpts_ipv4_table_t::value_type& out_value,
                                             const copc_key_t& key_val,
                                             const copc_result_t& result);
    la_status populate_tcam_key_value_result(npl_l2_lpts_ipv6_table_t::key_type& out_key,
                                             npl_l2_lpts_ipv6_table_t::key_type& out_mask,
                                             npl_l2_lpts_ipv6_table_t::value_type& out_value,
                                             const copc_key_t& key_val,
                                             const copc_result_t& result);
    la_status populate_tcam_key_value_result(npl_l2_lpts_mac_table_t::key_type& out_key,
                                             npl_l2_lpts_mac_table_t::key_type& out_mask,
                                             npl_l2_lpts_mac_table_t::value_type& out_value,
                                             const copc_key_t& key_val,
                                             const copc_result_t& result);
    la_status convert_la_key_to_sdk_key(const la_control_plane_classifier::key& la_key_val, copc_key_t& sdk_key_val);
    la_status convert_la_ipv4_key_to_sdk_ipv4_key(const la_control_plane_classifier::key& la_key_val, copc_key_t& sdk_key_val);
    la_status convert_la_ipv6_key_to_sdk_ipv6_key(const la_control_plane_classifier::key& la_key_val, copc_key_t& sdk_key_val);
    la_status convert_la_mac_key_to_sdk_mac_key(const la_control_plane_classifier::key& la_key_val, copc_key_t& sdk_key_val);

    // Template helper functions
    template <class _TableType>
    la_status push_entry(const std::shared_ptr<_TableType>& table,
                         size_t position,
                         bool is_push,
                         const copc_key_t& key_val,
                         const copc_result_t& result);
};
}
/// @}

#endif /* __LA_COPC_BASE_H__ */
