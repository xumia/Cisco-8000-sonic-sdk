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

#include "la_system_port_pacgb.h"
#include "nplapi/npl_constants.h"
#include "system/la_device_impl.h"
#include "system/la_mac_port_pacgb.h"
#include "system/la_npu_host_port_base.h"
#include "system/la_pci_port_base.h"
#include "system/la_recycle_port_base.h"
#include "system/la_remote_port_impl.h"
#include "tm/la_interface_scheduler_impl.h"
#include "tm/la_unicast_tc_profile_impl.h"
#include "tm/la_voq_set_impl.h"

#include "hld_utils.h"
#include "npu/resolution_utils.h"
#include "tm/la_system_port_scheduler_impl.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_system_port_pacgb::la_system_port_pacgb(const la_device_impl_wptr& device) : la_system_port_base(device)
{
}

la_system_port_pacgb::~la_system_port_pacgb()
{
}

la_status
la_system_port_pacgb::teardown_tm_tables()
{
    // Clean DSP lookup table
    const auto& table(m_device->m_tables.rxpdr_dsp_lookup_table);
    npl_rxpdr_dsp_lookup_table_key_t key;
    key.fwd_destination_lsb = m_gid;

    la_status status = table->erase(key);
    return_on_error(status);

    // Clean VOQ->device/slice/OQ table
    for (la_slice_id_t slice_id : m_device->get_used_slices()) {
        if (!m_device->is_network_slice(slice_id)) {
            continue;
        }

        const auto& table(m_device->m_tables.filb_voq_mapping[slice_id]);
        npl_filb_voq_mapping_t::key_type key;

        for (size_t voq_offset = 0; voq_offset < m_voq_set->get_set_size(); voq_offset++) {
            key.rxpdr_output_voq_nr = m_voq_set->get_base_voq_id() + voq_offset;

            status = table->erase(key);
            return_on_error(status);
        }
    }

    status = teardown_tm_tables_ect();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_pacgb::initialize_for_pci(la_object_id_t oid,
                                         const la_pci_port_wptr& pci_port,
                                         la_system_port_gid_t gid,
                                         const la_voq_set_wptr& voq_set,
                                         const la_tc_profile_wcptr& tc_profile)
{
    la_status status = pre_initialize(oid, pci_port, gid, voq_set);
    return_on_error(status);

    m_pci_port = pci_port.weak_ptr_static_cast<la_pci_port_base>();
    m_port_type = port_type_e::PCI;
    m_slice_id = m_pci_port->get_slice();
    m_ifg_id = m_pci_port->get_ifg();
    m_pif_base = HOST_PIF_ID;
    m_pif_count = 1;
    m_intf_scheduler = m_device->get_sptr(m_pci_port->get_scheduler());

    // PACKET-DMA-WA
    // Punting thru a PCI port requires recycle, which is not possible to do on PIF 18 because of
    // a HW bug. PIF 19 is used for that purpose as a workaround.
    m_punt_recycle_port = m_device->allocate_punt_recycle_port(m_device->get_sptr(this));
    if (m_punt_recycle_port == nullptr) {
        log_err(HLD, "PCI port requires a recycle port on the same slice pair. Recycle port was not found");
        return LA_STATUS_ENOTFOUND;
    }

    status = initialize_common_local(pci_port, voq_set, tc_profile);
    if (status != LA_STATUS_SUCCESS) {
        m_pci_port = nullptr;
        return status;
    }

    npl_initial_pd_nw_rx_data_t init_data;
    memset(&init_data, 0, sizeof(npl_initial_pd_nw_rx_data_t)); // Empty struct. We only need slice, ifg and pif.

    status = set_inject_up_entry(init_data);
    if (status != LA_STATUS_SUCCESS) {
        m_recycle_port = nullptr;
        return status;
    }

    m_device->add_object_dependency(m_punt_recycle_port, this);

    status = set_slice_rx_obm_code(); // PACKET-DMA-WA
    return_on_error(status);

    status = set_rx_obm_code_for_tests();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_pacgb::configure_pif_source_pif_table(npl_source_pif_hw_table_value_t value, la_uint_t pif)
{
    npl_source_pif_hw_table_entry_t* entry = nullptr;

    npl_source_pif_hw_table_key_t key;
    key.rxpp_npu_input_ifg = get_physical_ifg(m_slice_id, m_ifg_id);
    key.rxpp_npu_input_ifg_rx_fd_source_pif = pif;

    la_status status = m_device->m_tables.source_pif_hw_table[m_slice_id]->set(key, value, entry);

    return status;
}

la_status
la_system_port_pacgb::erase_pif_source_pif_table_entry(la_uint_t pif)
{

    npl_source_pif_hw_table_key_t key;
    key.rxpp_npu_input_ifg = get_physical_ifg(m_slice_id, m_ifg_id);
    key.rxpp_npu_input_ifg_rx_fd_source_pif = pif;

    la_status status = m_device->m_tables.source_pif_hw_table[m_slice_id]->erase(key);
    return status;
}

la_status
la_system_port_pacgb::configure_port_extender_map_rx_data_table(npl_source_pif_hw_table_value_t value)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_system_port_pacgb::set_source_pif_table(npl_source_pif_hw_table_value_t value)
{
    if (m_port_type == port_type_e::PCI) {
        value.payloads.init_rx_data.initial_rx_data.init_fields.init_data.initial_npp_attributes_index = 0;
        value.payloads.init_rx_data.initial_rx_data.init_fields.init_data.initial_slice_id = m_slice_id;
    } else {
        value.payloads.init_rx_data.initial_rx_data.init_fields.init_data.initial_slice_id
            = 0; // no need to set this, as this is part of a union with npp_attributes_index
        value.payloads.init_rx_data.initial_rx_data.init_fields.init_data.initial_npp_attributes_index = m_npp_attributes_index;
    }

    value.payloads.init_rx_data.initial_rx_data.init_fields.pfc_enable = (m_pfc_enabled) ? 1 : 0;

    la_uint_t num_of_entries = (m_port_extender_vid == NON_EXTENDED_PORT) ? m_pif_count : 1;
    for (la_uint_t pif_offset = 0; pif_offset < num_of_entries; pif_offset++) {
        la_status status = (m_port_extender_vid == NON_EXTENDED_PORT)
                               ? configure_pif_source_pif_table(value, m_pif_base + pif_offset)
                               : configure_port_extender_map_rx_data_table(value);

        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_pacgb::erase_port_extender_map_rx_data_table()
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_system_port_pacgb::program_voq_mapping(const la_voq_set_wptr& voq_set, bool is_lp) const
{
    // By default, set the dest_dev to indicate a "local device"
    la_device_id_t dest_dev = NPL_LOCAL_DEVICE_ID;

    bool lc_force_forward_through_fabric_mode;
    la_status status = m_device->get_bool_property(la_device_property_e::LC_FORCE_FORWARD_THROUGH_FABRIC_MODE,
                                                   lc_force_forward_through_fabric_mode);
    return_on_error(status);

    bool send_to_fabric = false;
    // Remote port is always forwarded to fabric.
    send_to_fabric = (m_port_type == port_type_e::REMOTE);
    // Recycle port is always forwarded locally, any other port is controlled by the force_fabric flag
    // Recycle port's effect of ignoring the force_fabric behavior must by synced with how the VOQ write itself to
    // pdvoq_slice_voq_properties. So, upon creating a system_port over recycle port, its VOQ is forced to be local.
    send_to_fabric |= ((m_port_type != port_type_e::RECYCLE) && (lc_force_forward_through_fabric_mode == true));

    if (send_to_fabric) {
        dest_dev = m_destination_device_id;
    }
    // Map the VOQ to device/slice/OQ
    for (la_slice_id_t slice_id : m_device->get_used_slices()) {
        if (!m_device->is_network_slice(slice_id)) {
            continue;
        }

        const auto& table(m_device->m_tables.filb_voq_mapping[slice_id]);
        npl_filb_voq_mapping_t::key_type key;
        npl_filb_voq_mapping_t::value_type value;
        npl_filb_voq_mapping_t::entry_pointer_type entry = nullptr;

        for (size_t voq_offset = 0; voq_offset < voq_set->get_set_size(); voq_offset++) {
            key.rxpdr_output_voq_nr = voq_set->get_base_voq_id() + voq_offset;
            value.payloads.filb_voq_mapping_result.dest_dev = dest_dev;
            value.payloads.filb_voq_mapping_result.dest_slice = m_slice_id;
            value.payloads.filb_voq_mapping_result.dest_oq = get_base_oq() + (is_lp ? 0 : voq_offset);
            value.payloads.filb_voq_mapping_result.packing_eligible = 1;

            status = table->insert(key, value, entry);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_pacgb::set_tc_profile_core(const la_tc_profile_wcptr& tc_profile)
{
    if (tc_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    // Map the DSP to VOQ
    const auto& table(m_device->m_tables.rxpdr_dsp_lookup_table);
    npl_rxpdr_dsp_lookup_table_value_t value;
    npl_rxpdr_dsp_lookup_table_key_t key;
    npl_rxpdr_dsp_lookup_table_entry_t* entry = nullptr;

    key.fwd_destination_lsb = m_gid;
    const auto& tc_profile_impl = tc_profile.weak_ptr_static_cast<const la_tc_profile_impl>();
    value.payloads.rxpdr_dsp_lookup_table_result.tc_map_profile = tc_profile_impl->get_id();
    value.payloads.rxpdr_dsp_lookup_table_result.base_voq_num = m_voq_set->get_base_voq_id();
    value.payloads.rxpdr_dsp_lookup_table_result.dest_device = 0; // This has meaning only for FLB - currenly unused.

    la_status status = table->set(key, value, entry);
    return_on_error(status);

    status = set_tc_profile_core_ect(tc_profile);
    return_on_error(status);

    m_device->remove_object_dependency(m_tc_profile, this);

    m_tc_profile = tc_profile;

    m_device->add_object_dependency(m_tc_profile, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_pacgb::configure_ibm_command(la_uint_t ibm_cmd,
                                            la_uint_t sampling_rate,
                                            bool mirror_to_dest,
                                            la_uint_t voq_offset) const
{
    if ((m_port_type != port_type_e::MAC) && (m_port_type != port_type_e::PCI) && (m_port_type != port_type_e::NPU_HOST)
        && (m_port_type != port_type_e::REMOTE)
        && (m_port_type != port_type_e::RECYCLE)) {
        log_err(HLD, "%s: Port type %s doesn't support IBM", __func__, silicon_one::to_string(m_port_type).c_str());

        return LA_STATUS_EINVAL;
    }

    const auto& table(m_device->m_tables.ibm_cmd_table);
    npl_ibm_cmd_table_key_t key;
    npl_ibm_cmd_table_value_t value;
    npl_ibm_cmd_table_entry_t* entry = nullptr;

    key.rxpp_to_txpp_local_vars_mirror_command = ibm_cmd;
    value.payloads.ibm_cmd_table_result.sampling_probability = sampling_rate;
    value.payloads.ibm_cmd_table_result.is_mc = 0;
    if (mirror_to_dest) {
        value.payloads.ibm_cmd_table_result.mirror_to_dest = 1;
    }
    value.payloads.ibm_cmd_table_result.tc_map_profile = la_device_impl::IBM_TC_PROFILE;

    la_voq_set* voq_set = m_voq_set.get();
    if (m_port_type == port_type_e::PCI) {
        // PACKET-DMA-WA - not applicable to all asic's
        voq_set = (m_punt_recycle_port != nullptr) ? m_punt_recycle_port->get_voq_set() : this->get_voq_set();
    }

    value.payloads.ibm_cmd_table_result.voq_or_bitmap.base_voq = voq_set->get_base_voq_id() + voq_offset;

    la_status status = table->set(key, value, entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_pacgb::program_stack_control_traffic_voq_mapping(const la_voq_set_wptr& voq_set) const
{
    if (m_port_type != port_type_e::MAC) {
        log_err(HLD, "%s: Port type %s doesn't support", __func__, silicon_one::to_string(m_port_type).c_str());
        return LA_STATUS_EINVAL;
    }

    npl_filb_voq_mapping_t::key_type key;
    npl_filb_voq_mapping_t::value_type value;

    const auto& tables(m_device->m_tables.filb_voq_mapping);

    for (size_t voq_offset = 0; voq_offset < voq_set->get_set_size(); voq_offset++) {
        key.rxpdr_output_voq_nr = voq_set->get_base_voq_id() + voq_offset;
        value.payloads.filb_voq_mapping_result.dest_dev = NPL_LOCAL_DEVICE_ID;
        value.payloads.filb_voq_mapping_result.dest_slice = m_slice_id;
        value.payloads.filb_voq_mapping_result.dest_oq = get_base_oq() + (NUM_OQ_PER_PIF - 1);
        value.payloads.filb_voq_mapping_result.packing_eligible = 1;

        la_status status = per_slice_tables_insert(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK}, key, value);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
