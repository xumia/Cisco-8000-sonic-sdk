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

#include "restricted_voq_set_impl.h"
#include "common/bit_utils.h"
#include "lld/gibraltar_tree.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

restricted_voq_set_impl::restricted_voq_set_impl(const la_device_impl_wptr& device) : la_voq_set_impl(device)
{
}

restricted_voq_set_impl::~restricted_voq_set_impl()
{
}

la_status
restricted_voq_set_impl::read_and_parse_vsc_voq_mapping_value()
{
    bit_vector mem_value;
    la_slice_id_vec_t nw_slices = get_slices(m_device, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC});
    for (auto slice : nw_slices) {
        lld_memory_scptr voq_mem;
        size_t line;
        get_voq_map_info(m_base_voq, slice, voq_mem, line);
        la_status status = m_device->m_ll_device->read_memory(voq_mem, line, mem_value);
        return_on_error(status);
        // We extract the vsc value by applying the opposite of the config in populate_vsc_voq_mapping_value
        size_t vsc_msbs = mem_value.bits(10, 0).get_value();
        m_base_vsc_vec[slice] = vsc_msbs << 4;
    }
    // We update the dest_ifg and dest_slice according to the last memory value assuming all memories have the same value for them.
    m_dest_ifg = mem_value.bits(11, 11).get_value();
    m_dest_slice = mem_value.bits(14, 12).get_value();

    return LA_STATUS_SUCCESS;
}

la_status
restricted_voq_set_impl::read_and_parse_dev_dest_map_value()
{
    bit_vector mem_value;
    la_slice_id_t slice = m_device->first_active_slice_id();
    // we work with slice 0, assuming that memories of all network slices have the same value of dest_device.
    dassert_crit(m_device->is_network_slice(slice));

    lld_memory_scptr dev_mem;
    size_t line;
    get_dev_dest_map_info(m_base_voq, slice, dev_mem, line);

    gibraltar::csms_dst_dev_map_mem_memory mem_entry;
    la_status status = m_device->m_ll_device->read_memory(dev_mem, line, mem_entry);
    return_on_error(status);

    m_dest_device = mem_entry.fields.dst_dev;

    return LA_STATUS_SUCCESS;
}

la_status
restricted_voq_set_impl::read_voq_cgm_profile_ids()
{
    la_slice_id_t rep_sid = m_device->first_active_slice_id();
    size_t profiles_num_in_hw_line = gibraltar::pdvoq_slice_voq_properties_memory::fields::get_profile_array_size(); // 16
    size_t current_line = m_base_voq / profiles_num_in_hw_line;
    gibraltar::pdvoq_slice_voq_properties_memory current_entry;
    // We read the memory of slice 0 which is a network slice for sure.
    lld_memory_scptr voq_properties_mem(m_device->m_gb_tree->slice[rep_sid]->pdvoq->voq_properties);
    la_status status = m_device->m_ll_device->read_memory(voq_properties_mem, current_line, current_entry);
    return_on_error(status);
    for (size_t voq_index = 0; voq_index < m_set_size; voq_index++) {
        size_t line = (m_base_voq + voq_index) / profiles_num_in_hw_line;
        if (line != current_line) { // we moved to a new hardware line, need to read it.
            status = m_device->m_ll_device->read_memory(voq_properties_mem, line, current_entry);
            return_on_error(status);
            current_line = line;
        }
        size_t voq_index_in_line = (m_base_voq + voq_index) % profiles_num_in_hw_line;
        size_t profile = current_entry.fields.get_profile(voq_index_in_line);
        // 5 LSBs = profile, 3 MSBs = type
        size_t cgm_profile_id = bit_utils::get_bits(profile, 4 /*msb*/, 0 /*lsb*/);
        dassert_crit(cgm_profile_id < la_device_impl::FIRST_ALLOCATABLE_VOQ_CGM_PROFILE_ID);
        m_cgm_profile_ids[voq_index] = cgm_profile_id;
    }

    return LA_STATUS_SUCCESS;
}

uint64_t
restricted_voq_set_impl::get_voq_cgm_profile_id(size_t voq_index) const
{
    return m_cgm_profile_ids[voq_index];
}

la_status
restricted_voq_set_impl::initialize_from_memories(la_object_id_t oid, la_voq_gid_t base_voq_id, size_t set_size)
{
    m_oid = oid;

    m_base_voq = base_voq_id;
    m_set_size = set_size;
    m_cgm_profiles.resize(set_size, nullptr);
    m_cgm_profile_ids.resize(set_size, la_device_impl::VOQ_CGM_DROP_PROFILE);
    m_per_voq_index_state.resize(set_size, state_e::ACTIVE);
    m_indx_is_during_flush_process.resize(set_size, false);

    la_status status = read_and_parse_vsc_voq_mapping_value();
    return_on_error(status);

    status = read_and_parse_dev_dest_map_value();
    return_on_error(status);

    status = read_voq_cgm_profile_ids();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
restricted_voq_set_impl::initialize(la_object_id_t oid,
                                    la_voq_gid_t base_voq_id,
                                    size_t set_size,
                                    la_vsc_gid_vec_t base_vsc_vec,
                                    la_device_id_t dest_device,
                                    la_slice_id_t dest_slice,
                                    la_ifg_id_t dest_ifg)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
restricted_voq_set_impl::set_cgm_profile(size_t voq_index, la_voq_cgm_profile* cgm_profile)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
restricted_voq_set_impl::get_cgm_profile(size_t voq_index, la_voq_cgm_profile*& out_cgm_profile) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
restricted_voq_set_impl::set_fabric_priority(size_t voq_index, bool is_high_priority)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
restricted_voq_set_impl::get_fabric_priority(size_t voq_index, bool& out_is_high_priority) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
restricted_voq_set_impl::force_local_voq_enable(bool enable)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
restricted_voq_set_impl::flush(bool block)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}
}
