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

#include <sstream>

#include "api/npu/la_mpls_multicast_group.h"
#include "common/defines.h"
#include "common/math_utils.h"
#include "common/transaction.h"
#include "hld_utils.h"
#include "la_multicast_group_common_base.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_ip_multicast_group_base.h"
#include "npu/la_l2_multicast_group_base.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_multicast_protection_group_base.h"
#include "npu/la_multicast_protection_monitor_base.h"
#include "npu/resolution_utils.h"
#include "system/la_device_impl.h"
#include "system/la_spa_port_base.h"
#include "system/la_system_port_base.h"
#include "tm/la_unicast_tc_profile_impl.h"
namespace silicon_one
{

std::string
la_multicast_group_common_base::group_member_desc::to_string() const
{
    std::stringstream ss;
    bool is_empty = true;

    if (l3_port != nullptr) {
        ss << l3_port->to_string() << " ";
        is_empty = false;
    }

    if (l2_dest != nullptr) {
        ss << l2_dest->to_string() << " ";
        is_empty = false;
    }

    if (l2_mcg != nullptr) {
        ss << l2_mcg->to_string() << " ";
        is_empty = false;
    }

    if (ip_mcg != nullptr) {
        ss << ip_mcg->to_string() << " ";
        is_empty = false;
    }

    if (is_punt) {
        ss << "punt";
        is_empty = false;
    }

    if (prefix_object) {
        ss << prefix_object->to_string() << " ";
        is_empty = false;
    }

    if (prot_info.prot_group) {
        ss << prot_info.prot_group->to_string() << " ";
        is_empty = false;
        if (prot_info.next_hop) {
            ss << prot_info.next_hop->to_string() << " ";
        }
        if (prot_info.monitor) {
            ss << prot_info.monitor->to_string() << " ";
        }
        if (prot_info.is_primary == true) {
            ss << "primary"
               << " ";
        } else {
            ss << "backup"
               << " ";
        }
    }

    if (is_empty) {
        ss << "empty";
    }

    return ss.str();
}

la_multicast_group_common_base::la_multicast_group_common_base(const la_device_impl_wptr& device)
    : m_device(device),
      m_gid((la_multicast_group_gid_t)-1),
      m_local_mcid((la_multicast_group_gid_t)-1),
      m_slice_data(ASIC_MAX_SLICES_PER_DEVICE_NUM, slice_data()),
      m_ir_data(ir_data())
{
}

la_multicast_group_common_base::~la_multicast_group_common_base()
{
}

bool
la_multicast_group_common_base::add_slice_user(std::vector<slice_data>& sd, la_slice_id_t slice)
{
    bool new_slice_added = false;

    if (sd[slice].use_count == 0) {
        new_slice_added = true;
    }

    sd[slice].use_count++;

    return new_slice_added;
}

la_status
la_multicast_group_common_base::configure_mc_list_size_table_per_slice(la_slice_id_t slice, ssize_t adjustment)
{
    const auto& table(m_device->m_tables.txpdr_mc_list_size_table[slice]);
    npl_txpdr_mc_list_size_table_key_t key;

    key.rxpdr_output_rxrq_cud_rxrq_cud_encoding_mcid_mcid = m_local_mcid;

    uint64_t new_size = m_slice_data[slice].mc_em_entries.size() + adjustment;
    npl_txpdr_mc_list_size_table_value_t value;
    npl_txpdr_mc_list_size_table_entry_wptr_t entry = nullptr;
    value.action = NPL_TXPDR_MC_LIST_SIZE_TABLE_ACTION_WRITE;

    la_status status;
    if (new_size == 0) {
        status = table->erase(key);
    } else {
        value.payloads.txpdr_local_vars_mc_group_size = div_round_up(new_size, 2);
        status = table->set(key, value, entry);
    }

    return status;
}

size_t
la_multicast_group_common_base::get_group_size_for_ingress_rep()
{
    uint64_t num_entries = m_ir_data.mc_em_entries.size();
    if (num_entries == 0) {
        if (m_device->m_device_mode == device_mode_e::STANDALONE) {
            return NULL_GROUP_SIZE;
        } else {
            return NULL_GROUP_SIZE_FOR_FABRIC;
        }
    } else {
        return (div_round_up(num_entries, 2));
    }
}

size_t
la_multicast_group_common_base::get_slice_bitmap()
{
    size_t bitmap_value(0);
    // get the slices on which this egress group has members on
    for (size_t i : m_device->get_used_slices()) {
        if (m_slice_data[i].use_count > 0) {
            bitmap_value |= (1 << i);
        }
    }
    return bitmap_value;
}

la_status
la_multicast_group_common_base::configure_mc_slice_bitmap()
{
    const auto& tables(m_device->m_tables.mc_slice_bitmap_table);

    size_t bitmap_value(0);
    for (size_t i : m_device->get_used_slices()) {
        if (m_slice_data[i].use_count > 0) {
            bitmap_value |= (1 << i);
        }
    }

    la_status status;
    if (m_device->m_device_mode == device_mode_e::STANDALONE) {
        if (m_rep_paradigm == la_replication_paradigm_e::EGRESS) {
            // For standalone, egres group, mc_bitmap should be set to member slices.
            // Reset group_size before setting mc_bitmap in the union
            m_mc_network_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.group_size = 0;
            m_mc_network_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.mc_bitmap
                .bitmap_indicator
                |= 0xFF;
            m_mc_network_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.mc_bitmap.bitmap
                = bitmap_value;
        }
        if (m_rep_paradigm == la_replication_paradigm_e::INGRESS) {
            // For standalone, egres group, set group_size
            // Reset mc_bitmap before setting group_size in the union
            m_mc_network_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.mc_bitmap
                .bitmap_indicator
                = 0;
            m_mc_network_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.mc_bitmap.bitmap = 0;
            m_mc_network_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.group_size
                = get_group_size_for_ingress_rep();
        }
        status = per_slice_tables_set(m_device->m_slice_mode,
                                      tables,
                                      {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC},
                                      m_mc_slice_bitmap_table_key,
                                      m_mc_network_slice_bitmap_table_value);
        return_on_error(status);
    } else if (m_device->m_device_mode == device_mode_e::LINECARD) {
        if (m_rep_paradigm == la_replication_paradigm_e::EGRESS) {
            if (m_is_scale_mode_smcid) {
                // For scale mode egress paradigm, the local MCID bitmap is programmed to the
                // network slices for the egress linecard to replicate to the
                // member slices.
                m_mc_network_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.group_size = 0;
                m_mc_network_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.mc_bitmap
                    .bitmap_indicator
                    |= 0xFF;
                m_mc_network_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.mc_bitmap.bitmap
                    = bitmap_value;

                status = per_slice_tables_set(m_device->m_slice_mode,
                                              tables,
                                              {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC},
                                              m_mc_slice_bitmap_table_key,
                                              m_mc_network_slice_bitmap_table_value);
                return_on_error(status);
            } else {
                // non scale mode egress paradigm, the MCID bitmap is programmed to the fabric
                // slices for the egress linecard to replicate to the member
                // slices.
                m_mc_network_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.group_size = 0;
                m_mc_network_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.mc_bitmap
                    .bitmap_indicator
                    |= 0xFF;
                m_mc_network_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.mc_bitmap.bitmap
                    = FABRIC_BITMAP;

                m_mc_fabric_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.group_size = 0;
                m_mc_fabric_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.mc_bitmap
                    .bitmap_indicator
                    |= 0xFF;
                m_mc_fabric_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.mc_bitmap.bitmap
                    = bitmap_value;

                status = per_slice_tables_set(m_device->m_slice_mode,
                                              tables,
                                              {la_slice_mode_e::CARRIER_FABRIC},
                                              m_mc_slice_bitmap_table_key,
                                              m_mc_fabric_slice_bitmap_table_value);
                return_on_error(status);

                status = per_slice_tables_set(m_device->m_slice_mode,
                                              tables,
                                              {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC},
                                              m_mc_slice_bitmap_table_key,
                                              m_mc_network_slice_bitmap_table_value);
                return_on_error(status);
            }
        } else {
            // Ingress paradigm
            m_mc_fabric_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.group_size = 0;
            m_mc_fabric_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.mc_bitmap
                .bitmap_indicator
                |= 0xFF;
            m_mc_fabric_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.mc_bitmap.bitmap
                = bitmap_value;
            status = per_slice_tables_set(m_device->m_slice_mode,
                                          tables,
                                          {la_slice_mode_e::CARRIER_FABRIC},
                                          m_mc_slice_bitmap_table_key,
                                          m_mc_fabric_slice_bitmap_table_value);
            return_on_error(status);

            // For ingress replication, network slice update is required.
            // to program group size
            m_mc_network_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.mc_bitmap.bitmap = 0;
            m_mc_network_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.group_size
                = get_group_size_for_ingress_rep();
            m_mc_network_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.mc_bitmap
                .bitmap_indicator
                = 0;
            status = per_slice_tables_set(m_device->m_slice_mode,
                                          tables,
                                          {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC},
                                          m_mc_slice_bitmap_table_key,
                                          m_mc_network_slice_bitmap_table_value);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

uint64_t
la_multicast_group_common_base::calculate_oqg_index(const la_system_port_wcptr& dsp)
{
    auto actual_dsp = get_actual_dsp(dsp);
    // OQs are configured statically (la_device_impl::configure_pdoq_oq_ifc_mapping). They are
    // a function of the IFG/PIF on which the system port resides
    // There are 2 OQs in each OQG, so the OQG is OQ/2
    // TODO - check the relevancy of this (and the caller function) when the sysport is port_type_e::REMOTE
    la_oq_id_t oq = actual_dsp->get_ifg() * NUM_OQ_PER_IFG + actual_dsp->get_base_pif() * NUM_TC_CLASSES;
    la_oq_id_t oqg = oq / 2;

    return oqg;
}

bool
la_multicast_group_common_base::remove_slice_user(std::vector<slice_data>& sd, la_slice_id_t slice)
{
    bool slice_removed = false;

    dassert_crit(sd[slice].use_count != 0);
    sd[slice].use_count--;

    if (sd[slice].use_count == 0) {
        slice_removed = true;
    }

    return slice_removed;
}

const la_device*
la_multicast_group_common_base::get_device() const
{
    return m_device.get();
}

la_multicast_group_gid_t
la_multicast_group_common_base::get_local_mcid(const group_member_desc& member)
{
    uint64_t local_mcid = ((la_multicast_group_gid_t)-1);
    if (member.l2_mcg != nullptr) {
        // l2 does not have local mcid
        local_mcid = member.l2_mcg->get_gid();
    }

    if (member.ip_mcg != nullptr) {
        const la_ip_multicast_group_base* ip_mcg_base = static_cast<const la_ip_multicast_group_base*>(member.ip_mcg.get());
        local_mcid = ip_mcg_base->get_local_mcid();
    }

    if (member.mpls_mcg != nullptr) {
        // mpls does not have local mcid
        local_mcid = member.mpls_mcg->get_gid();
    }

    return local_mcid;
}

la_status
la_multicast_group_common_base::set_replication_paradigm(la_replication_paradigm_e rep_paradigm)
{
    m_rep_paradigm = rep_paradigm;
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
