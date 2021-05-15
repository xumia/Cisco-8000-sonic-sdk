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

// la_ac_port_common models the shared part betweeen la_l2_service_port_base and
// la_l3_ac_port_impl

#ifndef __LA_AC_PORT_COMMON_H__
#define __LA_AC_PORT_COMMON_H__

#include "api/types/la_common_types.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_object.h"
#include "common/la_status.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "ifg_use_count.h"
#include "nplapi/nplapi_tables.h"

namespace silicon_one
{

class la_ac_port_common
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_ac_port_common(const la_device_impl_wptr& device);

    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    la_ac_port_common() = default;

    ~la_ac_port_common();

    /// Initialization - sets the common AC properties
    la_status initialize(la_object_wcptr parent,
                         la_uint64_t gid,
                         la_ethernet_port_base_wptr ethernet_port_impl,
                         la_vlan_id_t vid1,
                         la_vlan_id_t vid2);
    void destroy();

    /// IFG management
    la_status add_ifg(la_slice_ifg ifg);
    la_status remove_ifg(la_slice_ifg ifg);

    /// Changing the attached-switch in the containing object results with an update to the service-mapping
    /// tables that are managed in this object
    la_status set_switch(const la_switch_wcptr& sw);

    // For L3, there is no switch associated with the port. However, the
    // 'relay_id' (which is otherwise the switch's gid) is used to carry the
    // 'lp_additional_attributes' such as ipv6_acl.
    //
    // This is the API for l3_ac_port to set the ID value directly.
    la_status set_relay_id(la_slice_id_t slice_idx, uint32_t relay_id);

    const la_device_impl* get_device() const;

    uint64_t get_local_slp_id(la_slice_id_t slice_dx) const;
    static constexpr uint64_t LOCAL_SLP_ID_INVALID = (uint64_t)-1;

    la_status set_service_mapping_vids(la_vlan_id_t vid1, la_vlan_id_t vid2);
    la_status get_service_mapping_vids(la_vlan_id_t& out_vid1, la_vlan_id_t& out_vid2) const;

    la_status add_service_mapping_vid(la_vlan_id_t vid);
    la_status remove_service_mapping_vid(la_vlan_id_t vid);
    la_status get_service_mapping_vid_list(la_vid_vec_t& out_mapped_vids) const;

    la_status allocate_local_slp_id(la_slice_id_t slice_idx);
    la_status deallocate_local_slp_id(la_slice_id_t slice_idx);
    la_status configure_slice_ac_tcam_attributes(la_slice_id_t slice_idx,
                                                 const npl_mac_lp_attributes_payload_t& payload,
                                                 const uint32_t relay_id);
    la_status set_destination_p2p_pwe(la_pwe_gid_t pwe_gid, bool is_attached);

    la_status disable();

private:
    /// Helper functions to manage the service-mapping various tables
    la_status configure_slice_ac_attributes(la_slice_id_t slice_idx);
    la_status erase_slice_ac_attributes(la_slice_id_t slice_idx);

    la_status configure_slice_ac_port_table(la_slice_id_t slice_idx);
    la_status configure_slice_ac_port_tag_table(la_slice_id_t slice_idx);
    la_status configure_slice_ac_port_tag_fallback_table(la_slice_id_t slice_idx, la_vlan_id_t vid, bool update_entry);
    la_status configure_slice_ac_port_tag_tag_table(la_slice_pair_id_t slice_idx,
                                                    la_vlan_id_t vid1,
                                                    la_vlan_id_t vid2,
                                                    bool update_entry);

    la_status configure_slice_ac_port_tcam_table(la_slice_id_t slice_idx,
                                                 const npl_mac_lp_attributes_payload_t& payload,
                                                 const uint32_t relay_id);
    la_status configure_slice_ac_port_tcam_tag_table(la_slice_id_t slice_idx,
                                                     const npl_mac_lp_attributes_payload_t& payload,
                                                     const uint32_t relay_id);
    la_status configure_slice_ac_port_tcam_tag_tag_table(la_slice_id_t slice_idx,
                                                         const npl_mac_lp_attributes_payload_t& payload,
                                                         const uint32_t relay_id);

    /// Helper functions to update the switch attribute in the service-mapping table paylaod
    la_status set_switch_per_slice(la_switch_gid_t sw_gid, la_slice_id_t slice_idx);
    la_status set_switch_per_slice_ac_port(la_switch_gid_t sw_gid, la_slice_id_t slice_idx);
    la_status set_switch_per_slice_ac_port_tag(la_switch_gid_t sw_gid, la_slice_id_t slice_idx);
    la_status set_switch_per_slice_ac_port_tag_tag(la_switch_gid_t sw_gid, la_slice_id_t slice_idx);
    la_status add_service_mapping_vid_per_slice(la_slice_id_t slice, la_vlan_id_t vid);
    la_status remove_service_mapping_vid_per_slice(la_slice_id_t slice, la_vlan_id_t vid);
    la_status erase_slice_service_mapping_vid(la_slice_id_t slice);
    la_status configure_slice_service_mapping_vid(la_slice_id_t slice);

    la_uint_t get_slice_relay_id(la_slice_id_t slice_idx);
    la_status set_destination_p2p_pwe_per_slice(la_pwe_gid_t pwe_gid, la_slice_id_t slice_idx);
    la_status set_destination_p2p_pwe_per_slice_ac_port(la_pwe_gid_t pwe_gid, la_slice_id_t slice_idx);
    la_status set_destination_p2p_pwe_per_slice_ac_port_tag(la_pwe_gid_t pwe_gid, la_slice_id_t slice_idx);
    la_status set_destination_p2p_pwe_per_slice_ac_port_tag_tag(la_pwe_gid_t pwe_gid, la_slice_id_t slice_idx);

private:
    struct slice_data {
        /// AC port: (Port) -> (Relay ID, LP ID)
        npl_service_mapping_em0_ac_port_table_entry_wptr_t em0_ac_entry;

        /// AC port: (Port, VID) -> (Relay ID, LP ID)
        npl_service_mapping_em0_ac_port_tag_table_entry_wptr_t em0_ac_tag_entry;

        /// AC port: (Port, VID, VID) -> (Relay ID, LP ID)
        npl_service_mapping_em0_ac_port_tag_tag_table_entry_wptr_t em0_ac_tag_tag_entry;

        /// AC port: (Port, VID) -> (Relay ID, LP ID)
        npl_service_mapping_em1_ac_port_tag_table_entry_wptr_t em1_ac_tag_entry;

        /// TCAM AC port: (Port) -> (Relay ID, LP ID)
        npl_service_mapping_tcam_ac_port_table_entry_wptr_t tcam_ac_entry;

        /// TCAM AC port: (Port, VID) -> (Relay ID, LP ID)
        npl_service_mapping_tcam_ac_port_tag_table_entry_wptr_t tcam_ac_tag_entry;

        /// TCAM AC port: (Port, VID, VID) -> (Relay ID, LP ID)
        npl_service_mapping_tcam_ac_port_tag_tag_table_entry_wptr_t tcam_ac_tag_tag_entry;

        // Special relay_id for L3
        uint32_t relay_id = 0;

        uint64_t local_slp_id = LOCAL_SLP_ID_INVALID;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(slice_data);

    /// The global ID of the containing object
    la_uint64_t m_gid;

    /// Creating device
    la_device_impl_wptr m_device;

    /// IFG management
    ifg_use_count_uptr m_ifg_use_count;

    /// Underlying Ethernet port object
    la_ethernet_port_base_wptr m_eth_port;

    /// The VLAN tags associated with this AC port
    la_vlan_id_t m_vid1;
    la_vlan_id_t m_vid2;

    /// Attached switch in case there is one
    la_switch_wcptr m_attached_switch;

    // Attached pwe id for p2p case
    bool m_attached_p2p_pwe;
    la_pwe_gid_t m_attached_p2p_pwe_gid;

    /// Per-slice-pair data
    std::vector<slice_data> m_slice_data;

    // Parent object
    la_object_wcptr m_parent;

    // Mapped vid's
    la_vid_vec_t m_mapped_vids;

    // port state to indicate if port is active or disabled
    enum class object_state_e { ACTIVE, DISABLED };

    object_state_e m_port_state;
};

} // namespace silicon_one

#endif // __LA_AC_PORT_COMMON_H__
