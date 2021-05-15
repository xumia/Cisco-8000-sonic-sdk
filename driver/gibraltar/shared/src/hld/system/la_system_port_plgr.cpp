// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "la_system_port_plgr.h"

#include "tm/tm_utils.h"

namespace silicon_one
{

la_system_port_plgr::la_system_port_plgr(const la_device_impl_wptr& device) : la_system_port_akpg(device)
{
}

la_system_port_plgr::~la_system_port_plgr()
{
}

la_status
la_system_port_plgr::teardown_tm_tables()
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

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_plgr::configure_pif_source_pif_table(npl_ifg0_ssp_mapping_table_value_t value, la_uint_t pif)
{
    la_status status;

    // According to Rishy, all subports be programmed for non-subports.
    for (int i = 0; i < NUM_PCH_SUB_PORT_PER_PIF; i++) {

        value.payloads.init_rx_data.slice_source_system_port.value = get_slice_system_port_value(pif);

        if (!get_physical_ifg(m_slice_id, m_ifg_id)) {
            npl_ifg0_ssp_mapping_table_entry_t* entry = nullptr;
            npl_ifg0_ssp_mapping_table_key_t key;
            key.rx_pd_init_local_vars_sub_port_index = i;
            key.rxpp_npu_input_ifg_rx_fd_source_pif = pif;
            status = m_device->m_tables.ifg0_ssp_mapping_table[m_slice_id]->set(key, value, entry);
        } else {
            npl_ifg1_ssp_mapping_table_value_t value_ifg1;
            npl_ifg1_ssp_mapping_table_entry_t* entry = nullptr;
            npl_ifg1_ssp_mapping_table_key_t key;
            value_ifg1.unpack(value.pack()); // Ugly but effective
            key.rx_pd_init_local_vars_sub_port_index = i;
            key.rxpp_npu_input_ifg_rx_fd_source_pif = pif;
            status = m_device->m_tables.ifg1_ssp_mapping_table[m_slice_id]->set(key, value_ifg1, entry);
        }
    }

    return status;
}

la_status
la_system_port_plgr::erase_pif_source_pif_table_entry(la_uint_t pif)
{
    la_status status;

    for (int i = 0; i < NUM_PCH_SUB_PORT_PER_PIF; i++) {
        if (!get_physical_ifg(m_slice_id, m_ifg_id)) {
            npl_ifg0_ssp_mapping_table_key_t key;
            key.rx_pd_init_local_vars_sub_port_index = i;
            key.rxpp_npu_input_ifg_rx_fd_source_pif = pif;
            status = m_device->m_tables.ifg0_ssp_mapping_table[m_slice_id]->erase(key);
        } else {
            npl_ifg1_ssp_mapping_table_key_t key;
            key.rx_pd_init_local_vars_sub_port_index = i;
            key.rxpp_npu_input_ifg_rx_fd_source_pif = pif;
            status = m_device->m_tables.ifg1_ssp_mapping_table[m_slice_id]->erase(key);
        }
    }

    return status;
}

la_status
la_system_port_plgr::set_tc_profile_core(const la_tc_profile_wcptr& tc_profile)
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

    m_device->remove_object_dependency(m_tc_profile, this);

    m_tc_profile = tc_profile;

    m_device->add_object_dependency(m_tc_profile, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_plgr::configure_ibm_command(la_uint_t ibm_cmd,
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
        // PACKET-DMA-WA
        voq_set = (m_punt_recycle_port != nullptr) ? m_punt_recycle_port->get_voq_set() : this->get_voq_set();
    }

    value.payloads.ibm_cmd_table_result.voq_or_bitmap.base_voq = voq_set->get_base_voq_id() + voq_offset;

    la_status status = table->set(key, value, entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_plgr::program_stack_control_traffic_voq_mapping(const la_voq_set_wptr& voq_set) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

} // namespace silicon_one
