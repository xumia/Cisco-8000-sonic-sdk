// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

//
// Implementation of common parts of multicast-group configurations. Mainly managing the EM MC DB.
//

#ifndef __LA_MULTICAST_GROUP_COMMON_BASE_H__
#define __LA_MULTICAST_GROUP_COMMON_BASE_H__

#include <map>
#include <vector>

#include "api/npu/la_l2_destination.h"
#include "api/npu/la_l2_port.h"
#include "api/npu/la_l3_port.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_object.h"
#include "api/types/la_tm_types.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "nplapi/npl_constants.h"
#include "nplapi/npl_types.h"
#include "nplapi/nplapi_tables.h"
#include "npu/mc_copy_id_manager.h"

namespace silicon_one
{

class la_multicast_group_common_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    enum class vxlan_type_e { INVALID, L2_VXLAN, L3_VXLAN };

    explicit la_multicast_group_common_base(const la_device_impl_wptr& device);
    la_multicast_group_common_base() = default; // needed for cereal
    virtual ~la_multicast_group_common_base();
    virtual la_status initialize(la_multicast_group_gid_t multicast_gid,
                                 la_multicast_group_gid_t local_mcid,
                                 la_replication_paradigm_e rep_paradigm,
                                 bool is_scale_mode_smcid)
        = 0;
    virtual la_status destroy() = 0;
    const la_device* get_device() const;

    // Protected member information
    struct protected_member_info {
        la_multicast_protection_group_wcptr prot_group;
        la_next_hop_wcptr next_hop;
        bool is_primary = true;
        la_multicast_protection_monitor_wcptr monitor;

        protected_member_info()
        {
        }
        protected_member_info(la_multicast_protection_group_wcptr pg,
                              la_next_hop_wcptr nh,
                              bool ip,
                              la_multicast_protection_monitor_wcptr mon)
            : prot_group(pg), next_hop(nh), is_primary(ip), monitor(mon)
        {
        }

        bool operator<(const protected_member_info& other) const
        {
            return std::tie(prot_group, next_hop, is_primary, monitor)
                   < std::tie(other.prot_group, other.next_hop, other.is_primary, other.monitor);
        }
        bool operator==(const protected_member_info& other) const
        {
            return std::tie(prot_group, next_hop, is_primary, monitor)
                   == std::tie(other.prot_group, other.next_hop, other.is_primary, other.monitor);
        }
    };

    // Group member descriptor
    struct group_member_desc {
        la_l3_port_wcptr l3_port;
        la_l2_destination_wcptr l2_dest;
        la_l2_multicast_group_wptr l2_mcg;
        la_ip_multicast_group_wcptr ip_mcg;
        la_mpls_multicast_group_wcptr mpls_mcg;
        bool is_punt = false;
        la_next_hop_wcptr next_hop;
        vxlan_type_e vxlan_type = vxlan_type_e::INVALID;
        la_prefix_object_wcptr prefix_object;
        protected_member_info prot_info;
        la_stack_port_wcptr stackport;
        la_counter_set_wptr counter;
        la_slice_ifg counter_slice_ifg = {0, 0};

        explicit group_member_desc(const la_l3_port_wcptr l3p, const la_l2_destination_wcptr l2d) : l3_port(l3p), l2_dest(l2d)
        {
        }
        explicit group_member_desc(const la_l3_port_wcptr l3p, const la_l2_destination_wcptr l2d, bool is_punt)
            : l3_port(l3p), l2_dest(l2d), is_punt(is_punt)
        {
        }
        explicit group_member_desc(const la_l2_destination_wcptr l2d) : l2_dest(l2d)
        {
        }
        explicit group_member_desc(const la_l3_port_wcptr l3p, const la_l2_multicast_group_wptr l2mcg) : l3_port(l3p), l2_mcg(l2mcg)
        {
        }
        explicit group_member_desc(const la_ip_multicast_group_wcptr ipmcg) : ip_mcg(ipmcg)
        {
        }
        explicit group_member_desc(const la_mpls_multicast_group_wcptr mplsmcg) : mpls_mcg(mplsmcg)
        {
        }
        // Non-protected MPLS MC members
        explicit group_member_desc(const la_prefix_object_wcptr& pfx_obj) : prefix_object(pfx_obj)
        {
        }
        // Protected MPLS MC member (member per path)
        explicit group_member_desc(const la_prefix_object_wcptr& pfx_obj, protected_member_info pi)
            : prefix_object(pfx_obj), prot_info(pi)
        {
        }
        explicit group_member_desc(const la_counter_set_wptr& _counter, la_slice_ifg _counter_slice_ifg)
            : counter(_counter), counter_slice_ifg(_counter_slice_ifg)
        {
        }
        explicit group_member_desc(const la_stack_port_wcptr _stackport) : stackport(_stackport)
        {
        }
        explicit group_member_desc(const la_l3_port_wcptr l3p) : l3_port(l3p)
        {
        }
        group_member_desc()
        {
        }
        bool operator<(const group_member_desc& other) const
        {
            return std::tie(l3_port, l2_dest, l2_mcg, ip_mcg, mpls_mcg, prefix_object, is_punt, prot_info, counter, stackport)
                   < std::tie(other.l3_port,
                              other.l2_dest,
                              other.l2_mcg,
                              other.ip_mcg,
                              other.mpls_mcg,
                              other.prefix_object,
                              other.is_punt,
                              other.prot_info,
                              other.counter,
                              other.stackport);
        }
        bool operator==(const group_member_desc& other) const
        {
            return std::tie(l3_port, l2_dest, l2_mcg, ip_mcg, mpls_mcg, prefix_object, is_punt, prot_info, counter, stackport)
                   == std::tie(other.l3_port,
                               other.l2_dest,
                               other.l2_mcg,
                               other.ip_mcg,
                               other.mpls_mcg,
                               other.prefix_object,
                               other.is_punt,
                               other.prot_info,
                               other.counter,
                               other.stackport);
        }

        std::string to_string() const;
    };

    struct ir_member {
        la_multicast_group_gid_t mcid;
        la_slice_id_t slice;
        group_member_desc member;

        ir_member()
        {
        }

        ir_member(la_multicast_group_gid_t member_mcid, la_slice_id_t member_slice, group_member_desc ir_member)
            : mcid(member_mcid), slice(member_slice), member(ir_member)
        {
        }
        bool operator<(const ir_member& other) const
        {
            return std::tie(mcid, slice) < std::tie(other.mcid, other.slice);
        }
        bool operator==(const ir_member& other) const
        {
            return std::tie(mcid, slice) == std::tie(other.mcid, other.slice);
        }
    };

    virtual la_status configure_egress_rep_common(const group_member_desc& member,
                                                  const la_system_port_wcptr& dsp,
                                                  uint64_t mc_copy_id)
        = 0;
    virtual la_status teardown_egress_rep_common(const group_member_desc& member, const la_system_port_wcptr& dsp) = 0;
    virtual la_status set_member_dsp(const group_member_desc& member,
                                     const la_system_port_wcptr& curr_dsp,
                                     const la_system_port_wcptr& new_dsp,
                                     uint64_t old_mc_copy_id,
                                     uint64_t new_mc_copy_id)
        = 0;
    virtual la_status verify_dsp(const la_ethernet_port_wcptr& eth, const la_system_port_wcptr& dsp) const = 0;

    // Update member struct in slice data - this is needed if member data changes in MCG
    virtual la_status update_member_slice_data(const group_member_desc& old_member,
                                               const group_member_desc& new_member,
                                               la_slice_id_t slice)
        = 0;

    virtual bool is_dsp_remote(const la_system_port_wcptr& dsp) const = 0;

    virtual la_status configure_ingress_rep_common(const group_member_desc& member, la_slice_id_t slice) = 0;
    virtual la_status teardown_ingress_rep_common(const group_member_desc& member, la_slice_id_t slice) = 0;
    la_status configure_mc_slice_bitmap();
    la_status set_replication_paradigm(la_replication_paradigm_e rep_paradigm);

    enum {
        MC_GROUP_ID_LENGTH = 16,
        MC_MCID_SCALE_THRESHOLD_DEFAULT = (1 << 16), // 64 k
        FABRIC_SLICE = 5,
    };

    virtual void set_local_mcid(la_multicast_group_gid_t local_mcid) = 0;
    la_multicast_group_gid_t get_local_mcid(const group_member_desc& member);
    size_t get_slice_bitmap();

    // Configure CUD mapping table
    virtual la_status configure_cud_mapping(const group_member_desc& member, la_slice_id_t dest_slice, uint64_t mc_copy_id) = 0;
    virtual la_status teardown_cud_mapping(const group_member_desc& member, la_slice_id_t dest_slice, uint64_t mc_copy_id) = 0;
    virtual la_status reconfigure_mcemdb_entry(group_member_desc member, const la_system_port_base_wcptr dsp, uint64_t mc_copy_id)
        = 0;

protected:
    struct slice_data {
        slice_data() : use_count(0)
        {
        }

        // Slice use count - used to update mc_slice_bitmap table
        size_t use_count;

        // MC EM entries mapping for fast <dlp,dsp> lookup
        std::map<group_member_desc, npl_mc_em_db_entry_wptr_t> mc_em_entries_map;

        // MC EM entries vector for fast last element lookup
        std::vector<group_member_desc> mc_em_entries;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(slice_data);

    struct ir_data {
        // map for member-entry
        std::map<ir_member, npl_mc_em_db_entry_wptr_t> mc_em_entries_map;
        // vector for members
        std::vector<ir_member> mc_em_entries;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(ir_data);

    // Helper functions for configuring TM tables
    size_t get_group_size_for_ingress_rep();

    // Configure the number of group members in a TM table. This function is called when adding
    // a member to the group or removing a member from the group. The number of group members is
    // deduced from the size of the per-slice entries-vector.
    //
    // param[in]  adjustment   A value to add the the number of elements in the entries-vector.
    //                         This parameter is useful when calling the function before the
    //                         entries-vector is actually changed.
    la_status configure_mc_list_size_table_per_slice(la_slice_id_t slice, ssize_t adjustment);

    // initialize the entries for all slices to zero. uninitilzed entries causes a loop when
    // reading mc_em_db table.
    la_status initialize_mc_list_size_table();
    la_status teardown_mc_list_size_table();

    // Update the slice use count when a member is added/removed
    bool add_slice_user(std::vector<slice_data>& sd, la_slice_id_t slice);
    bool remove_slice_user(std::vector<slice_data>& sd, la_slice_id_t slice);

    // Helper functions for configring the MC EM DB
    virtual la_status add_mc_em_db_entry_egress_rep(const la_system_port_wcptr& dsp,
                                                    const group_member_desc& member,
                                                    uint64_t mc_copy_id)
        = 0;
    virtual la_status remove_mc_em_db_entry_egress_rep(const la_system_port_wcptr& dsp, const group_member_desc& tbr_member) = 0;
    virtual la_status insert_entry_to_mc_em_db_tx_format_0(uint64_t entry_index,
                                                           uint64_t dest_slice,
                                                           uint64_t tc_map_profile,
                                                           uint64_t oq_group,
                                                           uint64_t mc_copy_id,
                                                           npl_mc_em_db_entry_wptr_t& out_entry)
        = 0;
    virtual la_status remove_entry_from_mc_em_db_tx_format_0(size_t member_index, npl_mc_em_db_key_t key) = 0;
    virtual la_status update_entry_in_mc_em_db_tx_format_0(npl_mc_em_db_entry_wptr_t entry,
                                                           size_t member_index_in_entry,
                                                           const npl_mc_em_db_value_t& value,
                                                           size_t member_index_in_value)
        = 0;
    virtual la_status do_add_mc_em_db_entry_egress_rep(const la_system_port_wcptr& dsp,
                                                       uint64_t member_index,
                                                       uint64_t mc_copy_id,
                                                       npl_mc_em_db_entry_wptr_t& out_entry)
        = 0;

    uint64_t calculate_oqg_index(const la_system_port_wcptr& dsp);

    // Ingress replication helper functions
    virtual la_status add_mc_em_db_entry_ingress_rep(const group_member_desc& member, la_slice_id_t slice, uint64_t member_mcid)
        = 0;
    virtual la_status do_add_mc_em_db_entry_ingress_rep(uint64_t member_index,
                                                        uint64_t slice,
                                                        uint64_t member_mcid,
                                                        npl_mc_em_db_entry_wptr_t& out_entry)
        = 0;
    virtual la_status insert_entry_to_mc_em_db_rx_result(uint64_t member_index,
                                                         uint64_t slice,
                                                         uint64_t tc_map_profile,
                                                         uint64_t base_voq_nr,
                                                         uint64_t member_mcid,
                                                         npl_mc_em_db_entry_wptr_t& out_entry)
        = 0;
    virtual void populate_mc_em_db_rx_result_value(bool is_0,
                                                   uint64_t tc_map_profile,
                                                   uint64_t base_voq_nr,
                                                   uint64_t member_mcid,
                                                   npl_mc_em_db_value_t& out_value)
        = 0;
    virtual la_status remove_mc_em_db_entry_ingress_rep(const group_member_desc& member, la_slice_id_t slice) = 0;
    virtual la_status update_entry_in_mc_em_db_rx_result(la_slice_id_t slice,
                                                         size_t dst_index,
                                                         npl_mc_em_db_entry_wptr_t& dst_entry,
                                                         size_t src_index,
                                                         npl_mc_em_db_entry_wptr_t& src_entry)
        = 0;
    virtual la_status remove_entry_from_mc_em_db_rx_result(la_slice_id_t slice,
                                                           size_t member_index,
                                                           npl_mc_em_db_entry_wptr_t& entry)
        = 0;

protected:
    // Containing device
    la_device_impl_wptr m_device;

    // Global ID
    la_multicast_group_gid_t m_gid;

    // Local MCID
    la_multicast_group_gid_t m_local_mcid;

    // True if this is a scaled mode MCID
    bool m_is_scale_mode_smcid;

    // Replication paradigm
    la_replication_paradigm_e m_rep_paradigm;

    // This value will be written to table instances that belong to fabric slices in LC.
    npl_mc_slice_bitmap_table_value_t m_mc_fabric_slice_bitmap_table_value;
    // In standalone mode, this value will be written to all table instances,
    // and it will be a bitmap to slices should recieve a MC packet (per MCID).
    // In LC mode, it will be written to network slices only.
    npl_mc_slice_bitmap_table_value_t m_mc_network_slice_bitmap_table_value;
    npl_mc_slice_bitmap_table_key_t m_mc_slice_bitmap_table_key;

    // Per slice data
    // TODO it actually can be based on the number of NETWORK slices
    std::vector<slice_data> m_slice_data;
    ir_data m_ir_data;

    // Bitmap indicator mask
    static const uint8_t BITMAP_INDICATOR_MASK = 0x1f;
    static const uint8_t FABRIC_BITMAP = (1 << 5);
    static const uint16_t NULL_GROUP_SIZE = (BITMAP_INDICATOR_MASK << 6);
    static const uint16_t NULL_GROUP_SIZE_FOR_FABRIC = (NULL_GROUP_SIZE | FABRIC_BITMAP);
};

} // namespace silicon_one

#endif // __LA_MULTICAST_GROUP_COMMON_BASE_H__
