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

#include "rx_cgm_handler.h"
#include "common/bit_utils.h"
#include "common/math_utils.h"
#include "common/ranged_index_generator.h"
#include "hld_utils.h"
#include "lld/ll_device.h"
#include "lld/pacific_mem_structs.h"
#include "lld/pacific_reg_structs.h"
#include "lld/pacific_tree.h"
#include "system/la_device_impl.h"
#include "system/slice_id_manager_base.h"
#include "tm/tm_utils.h"

namespace silicon_one
{

static la_uint_t
get_sq_base(la_uint_t ifg, la_uint_t serdes)
{
    return (ifg * tm_utils::IFG_SYSTEM_PORT_SCHEDULERS + serdes) * NUM_TC_CLASSES;
}

rx_cgm_handler::rx_cgm_handler(const la_device_impl_wptr& device)
    : m_device(device), m_hr_management_mode(la_rx_cgm_headroom_mode_e::TIMER)
{
    for (la_slice_id_t slice = 0; slice < m_profile_id_generator.size(); slice++) {
        m_profile_id_generator[slice] = ranged_index_generator(0, LA_RX_CGM_SQ_PROFILE_MAX_ID);
    }
    m_slice_id_manager = m_device->get_slice_id_manager();
}

rx_cgm_handler::~rx_cgm_handler()
{
}

la_status
rx_cgm_handler::set_rx_cgm_sms_bytes_quantization(const la_rx_cgm_sms_bytes_quantization_thresholds& thresholds)
{
    la_status status = validate_thresholds(thresholds);
    return_on_error(status);

    auto counter_thresholds_reg_1 = m_device->m_pacific_tree->rx_pdr->counters_thresholds_reg1;
    rx_pdr_counters_thresholds_reg1_register reg;

    status = m_device->m_ll_device->read_register(counter_thresholds_reg_1, reg);
    return_on_error(status);

    reg.fields.rx_cgm_counter_a_thr0 = div_round_nearest(thresholds.thresholds[0], la_device_impl::SMS_BLOCK_SIZE_IN_BYTES);
    reg.fields.rx_cgm_counter_a_thr1 = div_round_nearest(thresholds.thresholds[1], la_device_impl::SMS_BLOCK_SIZE_IN_BYTES);
    reg.fields.rx_cgm_counter_a_thr2 = div_round_nearest(thresholds.thresholds[2], la_device_impl::SMS_BLOCK_SIZE_IN_BYTES);

    status = m_device->m_ll_device->write_register(counter_thresholds_reg_1, reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
rx_cgm_handler::get_rx_cgm_sms_bytes_quantization(la_rx_cgm_sms_bytes_quantization_thresholds& out_thresholds)
{
    auto counter_thresholds_reg_1 = m_device->m_pacific_tree->rx_pdr->counters_thresholds_reg1;
    rx_pdr_counters_thresholds_reg1_register reg;

    la_status status = m_device->m_ll_device->read_register(counter_thresholds_reg_1, reg);
    return_on_error(status);

    out_thresholds.thresholds[0] = reg.fields.rx_cgm_counter_a_thr0 * la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;
    out_thresholds.thresholds[1] = reg.fields.rx_cgm_counter_a_thr1 * la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;
    out_thresholds.thresholds[2] = reg.fields.rx_cgm_counter_a_thr2 * la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;

    return LA_STATUS_SUCCESS;
}

la_status
rx_cgm_handler::set_rx_cgm_sqg_thresholds(la_uint_t sqg_index, const la_rx_cgm_sqg_thresholds& thresholds)
{
    la_status status = validate_thresholds(thresholds);
    return_on_error(status);

    auto nw_slices = get_slices(m_device, la_slice_mode_e::NETWORK);
    for (la_slice_id_t slice : nw_slices) {
        auto sqg_profile_lookup_table = (*m_device->m_pacific_tree->rx_cgm->sq_group_profile_lut)[slice];
        rx_cgm_sq_group_profile_lut_memory sqg_profile;

        sqg_profile.fields.slice_sq_group_thr0
            = div_round_nearest(thresholds.thresholds[0], la_device_impl::SMS_BLOCK_SIZE_IN_BYTES);
        sqg_profile.fields.slice_sq_group_thr1
            = div_round_nearest(thresholds.thresholds[1], la_device_impl::SMS_BLOCK_SIZE_IN_BYTES);
        sqg_profile.fields.slice_sq_group_thr2
            = div_round_nearest(thresholds.thresholds[2], la_device_impl::SMS_BLOCK_SIZE_IN_BYTES);

        status = m_device->m_ll_device->write_memory(sqg_profile_lookup_table, sqg_index, sqg_profile);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
rx_cgm_handler::get_rx_cgm_sqg_thresholds(la_uint_t sqg_index, la_rx_cgm_sqg_thresholds& out_thresholds)
{
    auto sqg_profile_lookup_table = (*m_device->m_pacific_tree->rx_cgm->sq_group_profile_lut)[0];
    rx_cgm_sq_group_profile_lut_memory sqg_profile;

    la_status status = m_device->m_ll_device->read_memory(sqg_profile_lookup_table, sqg_index, sqg_profile);
    return_on_error(status);

    out_thresholds.thresholds[0] = sqg_profile.fields.slice_sq_group_thr0 * la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;
    out_thresholds.thresholds[1] = sqg_profile.fields.slice_sq_group_thr1 * la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;
    out_thresholds.thresholds[2] = sqg_profile.fields.slice_sq_group_thr2 * la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;

    return LA_STATUS_SUCCESS;
}

la_status
rx_cgm_handler::allocate_rx_cgm_sq_profile_id(la_slice_id_t slice, la_uint_t& out_profile_id)
{
    la_status status = m_slice_id_manager->is_slice_valid(slice);
    return_on_error(status);

    if (!m_device->is_network_slice(slice)) {
        return LA_STATUS_EUNKNOWN;
    }

    la_uint64_t id = m_profile_id_generator[slice].allocate();
    if (id == ranged_index_generator::INVALID_INDEX) {
        return LA_STATUS_ERESOURCE;
    }
    out_profile_id = id;

    return LA_STATUS_SUCCESS;
}

la_status
rx_cgm_handler::release_rx_cgm_sq_profile_id(la_slice_id_t slice, la_uint_t profile_id)
{
    la_status status = m_slice_id_manager->is_slice_valid(slice);
    return_on_error(status);

    if (!m_device->is_network_slice(slice)) {
        return LA_STATUS_EUNKNOWN;
    }

    if (profile_id > LA_RX_CGM_SQ_PROFILE_MAX_ID) {
        return LA_STATUS_EINVAL;
    }

    // If profile ID already released, will assert
    m_profile_id_generator[slice].release(profile_id);

    return LA_STATUS_SUCCESS;
}

la_status
rx_cgm_handler::set_rx_cgm_sq_profile_thresholds(la_slice_id_t slice,
                                                 la_uint_t profile_id,
                                                 const la_rx_cgm_sq_profile_thresholds& thresholds)
{
    la_status status = m_slice_id_manager->is_slice_valid(slice);
    return_on_error(status);
    if (!m_device->is_network_slice(slice)) {
        return LA_STATUS_EINVAL;
    }
    if (profile_id > LA_RX_CGM_SQ_PROFILE_MAX_ID) {
        return LA_STATUS_EINVAL;
    }

    status = validate_thresholds(thresholds);
    return_on_error(status);

    auto sq_profile_lookup_table = (*m_device->m_pacific_tree->rx_cgm->sq_profile_lut)[slice];
    rx_cgm_sq_profile_lut_memory profile_lut_entry;
    status = m_device->m_ll_device->read_memory(sq_profile_lookup_table, profile_id, profile_lut_entry);
    return_on_error(status);

    profile_lut_entry.fields.slice_sq_thr0 = div_round_nearest(thresholds.thresholds[0], la_device_impl::SMS_BLOCK_SIZE_IN_BYTES);
    profile_lut_entry.fields.slice_sq_thr1 = div_round_nearest(thresholds.thresholds[1], la_device_impl::SMS_BLOCK_SIZE_IN_BYTES);
    profile_lut_entry.fields.slice_sq_thr2 = div_round_nearest(thresholds.thresholds[2], la_device_impl::SMS_BLOCK_SIZE_IN_BYTES);

    status = m_device->m_ll_device->write_memory(sq_profile_lookup_table, profile_id, bit_vector(profile_lut_entry));
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
rx_cgm_handler::set_rx_cgm_sq_profile_policy(la_slice_id_t slice,
                                             la_uint_t profile_id,
                                             const la_rx_cgm_policy_status& rx_cgm_status,
                                             bool flow_control,
                                             bool drop_yellow,
                                             bool drop_green,
                                             bool fc_trig)
{
    la_status status = m_slice_id_manager->is_slice_valid(slice);
    return_on_error(status);
    if (!m_device->is_network_slice(slice)) {
        return LA_STATUS_EINVAL;
    }
    if (profile_id > LA_RX_CGM_SQ_PROFILE_MAX_ID) {
        return LA_STATUS_EINVAL;
    }

    auto source_cgm_policy_lut = (*m_device->m_pacific_tree->rx_cgm->source_cgm_policy_lut)[slice];

    // Bit offsets for statuses in memory
    const size_t counter_a_offset = 6;
    const size_t sq_profile_offset = 4;
    const size_t sq_group_offset = 2;

    la_uint_t counter_a_status = (rx_cgm_status.counter_a_region << counter_a_offset);
    la_uint_t sq_status = (rx_cgm_status.sq_profile_region << sq_profile_offset);
    la_uint_t sqg_status = (rx_cgm_status.sq_group_region << sq_group_offset);

    /* Table line is CtrAStat(2) + SQStat(2) + SQGStat(2) + 2 MSBs of profile(2), 4 entries per line */
    la_uint_t line = counter_a_status | sq_status | sqg_status | (profile_id >> 2);
    la_uint_t line_idx = profile_id & 0x3;

    rx_cgm_source_cgm_policy_lut_memory source_cgm_policy_line;
    status = m_device->m_ll_device->read_memory(source_cgm_policy_lut, line, source_cgm_policy_line);
    return_on_error(status);

    bit_vector bv = bit_vector(source_cgm_policy_line);
    bv.set_bit(3 * line_idx, flow_control);
    bv.set_bit(3 * line_idx + 1, drop_yellow);
    bv.set_bit(3 * line_idx + 2, drop_green);

    status = m_device->m_ll_device->write_memory(source_cgm_policy_lut, line, bv);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
rx_cgm_handler::set_rx_cgm_hr_timer_or_threshold_value(la_slice_id_t slice, la_uint_t profile_id, la_uint_t hr_value)
{
    la_status status = m_slice_id_manager->is_slice_valid(slice);
    return_on_error(status);
    if (!m_device->is_network_slice(slice)) {
        return LA_STATUS_EINVAL;
    }
    if (profile_id > LA_RX_CGM_SQ_PROFILE_MAX_ID) {
        return LA_STATUS_EINVAL;
    }

    la_rx_cgm_headroom_mode_e mode;
    status = get_rx_cgm_hr_management_mode(mode);
    return_on_error(status);
    /* If in bytes - convert to buffers. If in nanoseconds, convert to 4ns resolution. */
    hr_value = (mode == la_rx_cgm_headroom_mode_e::THRESHOLD) ? div_round_nearest(hr_value, la_device_impl::SMS_BLOCK_SIZE_IN_BYTES)
                                                              : hr_value / 4;

    if (hr_value > bit_utils::ones(rx_cgm_sq_profile_lut_memory::fields::SLICE_HR_THRESHOLD_OR_TIMER_MAX_WIDTH)) {
        return LA_STATUS_EINVAL;
    }

    auto sq_profile_lookup_table = (*m_device->m_pacific_tree->rx_cgm->sq_profile_lut)[slice];
    rx_cgm_sq_profile_lut_memory profile_lut_entry;
    status = m_device->m_ll_device->read_memory(sq_profile_lookup_table, profile_id, profile_lut_entry);
    return_on_error(status);

    profile_lut_entry.fields.slice_hr_threshold_or_timer_max = hr_value;

    status = m_device->m_ll_device->write_memory(sq_profile_lookup_table, profile_id, bit_vector(profile_lut_entry));
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
rx_cgm_handler::set_rx_cgm_sq_profile_mapping(la_slice_id_t slice,
                                              la_ifg_id_t ifg,
                                              la_uint_t serdes,
                                              la_traffic_class_t tc,
                                              la_uint_t profile_id)
{
    la_status status = m_slice_id_manager->is_slice_ifg_valid(slice, ifg);
    return_on_error(status);
    if (!m_device->is_network_slice(slice)) {
        return LA_STATUS_EINVAL;
    }
    if (tc >= NUM_TC_CLASSES || serdes >= MAX_NUM_SERDES_PER_IFG) {
        return LA_STATUS_EINVAL;
    }
    if (profile_id > LA_RX_CGM_SQ_PROFILE_MAX_ID) {
        return LA_STATUS_EINVAL;
    }

    la_uint_t sq_base = get_sq_base(ifg, serdes);
    la_uint_t sq = sq_base + tc;
    /* 4 entries per line */
    la_uint_t line = sq >> 2;
    la_uint_t line_idx = sq & 0x3;

    rx_cgm_profile_map_table_memory map_table_line;
    status = read_profile_map_table_line(slice, line, map_table_line);
    return_on_error(status);

    if (line_idx == 0) {
        map_table_line.fields.slice_entry0_sq_profile = profile_id;
    } else if (line_idx == 1) {
        map_table_line.fields.slice_entry1_sq_profile = profile_id;
    } else if (line_idx == 2) {
        map_table_line.fields.slice_entry2_sq_profile = profile_id;
    } else if (line_idx == 3) {
        map_table_line.fields.slice_entry3_sq_profile = profile_id;
    }

    status = write_profile_map_table_line(slice, line, map_table_line);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
rx_cgm_handler::set_rx_cgm_sq_drop_counter_mapping(la_slice_id_t slice,
                                                   la_ifg_id_t ifg,
                                                   la_uint_t serdes,
                                                   la_traffic_class_t tc,
                                                   la_uint_t counter_index)
{
    la_status status = m_slice_id_manager->is_slice_ifg_valid(slice, ifg);
    return_on_error(status);
    if (!m_device->is_network_slice(slice)) {
        return LA_STATUS_EINVAL;
    }

    if (tc >= NUM_TC_CLASSES || serdes >= MAX_NUM_SERDES_PER_IFG) {
        return LA_STATUS_EINVAL;
    }

    if (counter_index >= LA_RX_CGM_MAX_NUM_DROP_COUNTERS) {
        return LA_STATUS_EINVAL;
    }

    la_uint_t sq_base = get_sq_base(ifg, serdes);
    la_uint_t sq = sq_base + tc;
    /* 4 entries per line */
    la_uint_t line = sq >> 2;
    la_uint_t line_idx = sq & 0x3;

    rx_cgm_profile_map_table_memory map_table_line;
    status = read_profile_map_table_line(slice, line, map_table_line);
    return_on_error(status);

    if (line_idx == 0) {
        map_table_line.fields.slice_entry0_sq_drop_cnt_index = counter_index;
    } else if (line_idx == 1) {
        map_table_line.fields.slice_entry1_sq_drop_cnt_index = counter_index;
    } else if (line_idx == 2) {
        map_table_line.fields.slice_entry2_sq_drop_cnt_index = counter_index;
    } else if (line_idx == 3) {
        map_table_line.fields.slice_entry3_sq_drop_cnt_index = counter_index;
    }

    status = write_profile_map_table_line(slice, line, map_table_line);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
rx_cgm_handler::set_rx_cgm_sq_group_mapping(la_slice_id_t slice,
                                            la_ifg_id_t ifg,
                                            la_uint_t serdes,
                                            la_traffic_class_t tc,
                                            la_uint_t group_index)
{
    la_status status = m_slice_id_manager->is_slice_ifg_valid(slice, ifg);
    return_on_error(status);
    if (!m_device->is_network_slice(slice)) {
        return LA_STATUS_EINVAL;
    }

    if (tc >= NUM_TC_CLASSES || serdes >= MAX_NUM_SERDES_PER_IFG) {
        return LA_STATUS_EINVAL;
    }

    if (group_index >= LA_RX_CGM_MAX_NUM_SQ_GROUPS) {
        return LA_STATUS_EINVAL;
    }

    la_uint_t sq_base = get_sq_base(ifg, serdes);
    la_uint_t sq = sq_base + tc;
    /* 4 entries per line */
    la_uint_t line = sq >> 2;
    la_uint_t line_idx = sq & 0x3;

    rx_cgm_profile_map_table_memory map_table_line;
    status = read_profile_map_table_line(slice, line, map_table_line);
    return_on_error(status);

    if (line_idx == 0) {
        map_table_line.fields.slice_entry0_sq_group = group_index;
    } else if (line_idx == 1) {
        map_table_line.fields.slice_entry1_sq_group = group_index;
    } else if (line_idx == 2) {
        map_table_line.fields.slice_entry2_sq_group = group_index;
    } else if (line_idx == 3) {
        map_table_line.fields.slice_entry3_sq_group = group_index;
    }

    status = write_profile_map_table_line(slice, line, map_table_line);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
rx_cgm_handler::set_rx_cgm_sq_mapping(la_slice_id_t slice,
                                      la_ifg_id_t ifg,
                                      la_uint_t serdes,
                                      la_traffic_class_t tc,
                                      la_uint_t profile_id,
                                      la_uint_t group_index,
                                      la_uint_t counter_index)
{
    la_status status = m_slice_id_manager->is_slice_ifg_valid(slice, ifg);
    return_on_error(status);
    if (!m_device->is_network_slice(slice)) {
        return LA_STATUS_EINVAL;
    }

    if (tc >= NUM_TC_CLASSES || serdes >= MAX_NUM_SERDES_PER_IFG) {
        return LA_STATUS_EINVAL;
    }

    if (group_index >= LA_RX_CGM_MAX_NUM_SQ_GROUPS || counter_index >= LA_RX_CGM_MAX_NUM_DROP_COUNTERS
        || profile_id > LA_RX_CGM_SQ_PROFILE_MAX_ID) {
        return LA_STATUS_EINVAL;
    }

    la_uint_t sq_base = get_sq_base(ifg, serdes);
    la_uint_t sq = sq_base + tc;
    /* 4 entries per line */
    la_uint_t line = sq >> 2;
    la_uint_t line_idx = sq & 0x3;

    rx_cgm_profile_map_table_memory map_table_line;
    status = read_profile_map_table_line(slice, line, map_table_line);
    return_on_error(status);

    if (line_idx == 0) {
        map_table_line.fields.slice_entry0_sq_group = group_index;
        map_table_line.fields.slice_entry0_sq_profile = profile_id;
        map_table_line.fields.slice_entry0_sq_drop_cnt_index = counter_index;
    } else if (line_idx == 1) {
        map_table_line.fields.slice_entry1_sq_group = group_index;
        map_table_line.fields.slice_entry1_sq_profile = profile_id;
        map_table_line.fields.slice_entry1_sq_drop_cnt_index = counter_index;
    } else if (line_idx == 2) {
        map_table_line.fields.slice_entry2_sq_group = group_index;
        map_table_line.fields.slice_entry2_sq_profile = profile_id;
        map_table_line.fields.slice_entry2_sq_drop_cnt_index = counter_index;
    } else if (line_idx == 3) {
        map_table_line.fields.slice_entry3_sq_group = group_index;
        map_table_line.fields.slice_entry3_sq_profile = profile_id;
        map_table_line.fields.slice_entry3_sq_drop_cnt_index = counter_index;
    }

    status = write_profile_map_table_line(slice, line, map_table_line);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
rx_cgm_handler::set_rx_cgm_hr_management_mode(la_rx_cgm_headroom_mode_e mode)
{
    auto nw_slices = get_slices(m_device, la_slice_mode_e::NETWORK);
    for (la_slice_id_t slice : nw_slices) {
        auto rx_cgm_global_config = (*m_device->m_pacific_tree->rx_cgm->global_configuration)[slice];
        rx_cgm_global_configuration_register reg;

        la_status status = m_device->m_ll_device->read_register(rx_cgm_global_config, reg);
        return_on_error(status);

        reg.fields.slice_hr_management_mode = static_cast<la_uint64_t>(mode);

        status = m_device->m_ll_device->write_register(rx_cgm_global_config, reg);
        return_on_error(status);
    }

    m_hr_management_mode = mode;

    return LA_STATUS_SUCCESS;
}

la_status
rx_cgm_handler::get_rx_cgm_hr_management_mode(la_rx_cgm_headroom_mode_e& mode) const
{
    mode = m_hr_management_mode;

    return LA_STATUS_SUCCESS;
}

la_status
rx_cgm_handler::read_rx_cgm_drop_counter(la_slice_id_t slice, la_uint_t counter_index, la_uint_t& out_packet_count)
{
    la_status status = m_slice_id_manager->is_slice_valid(slice);
    return_on_error(status);
    if (!m_device->is_network_slice(slice)) {
        return LA_STATUS_EINVAL;
    }
    if (counter_index >= LA_RX_CGM_MAX_NUM_DROP_COUNTERS) {
        return LA_STATUS_EINVAL;
    }

    /* In RXCGM drop counters table, counters 0-7 belong to slice 0, 8-15 belong to slice 1, etc, 8 per slice */
    la_uint_t idx = (slice * 8) + counter_index;

    auto rx_cgm_drop_counters_reg = (*m_device->m_pacific_tree->rx_cgm->rx_cgm_drop_counters1)[idx];

    bit_vector counter_value;
    status = m_device->m_ll_device->read_register(rx_cgm_drop_counters_reg, counter_value);
    return_on_error(status);

    out_packet_count = counter_value.get_value();

    return LA_STATUS_SUCCESS;
}

la_status
rx_cgm_handler::read_profile_map_table_line(la_slice_id_t slice, la_uint_t line, rx_cgm_profile_map_table_memory& out_mem)
{
    auto profile_map_table = (*m_device->m_pacific_tree->rx_cgm->profile_map_table)[slice];
    rx_cgm_profile_map_table_memory profile_map_line;

    la_status status = m_device->m_ll_device->read_memory(profile_map_table, line, profile_map_line);
    return_on_error(status);

    out_mem = profile_map_line;

    return LA_STATUS_SUCCESS;
}

la_status
rx_cgm_handler::write_profile_map_table_line(la_slice_id_t slice, la_uint_t line, rx_cgm_profile_map_table_memory& mem)
{
    auto profile_map_table = (*m_device->m_pacific_tree->rx_cgm->profile_map_table)[slice];

    la_status status = m_device->m_ll_device->write_memory(profile_map_table, line, bit_vector(mem));
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
rx_cgm_handler::validate_thresholds(const la_rx_cgm_sqg_thresholds& thresholds) const
{
    la_uint_t threshold_max = bit_utils::ones(rx_cgm_sq_group_profile_lut_memory::fields::SLICE_SQ_GROUP_THR0_WIDTH);
    la_uint_t threshold_max_bytes = threshold_max * la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;

    for (size_t i = 0; i < LA_RX_CGM_NUM_SQG_CONFIGURABLE_THRESHOLDS; i++) {
        if (thresholds.thresholds[i] > threshold_max_bytes) {
            return LA_STATUS_EINVAL;
        }
        la_uint_t prev = (i == 0) ? 0 : thresholds.thresholds[i - 1];
        if (thresholds.thresholds[i] < prev) {
            return LA_STATUS_EINVAL;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
rx_cgm_handler::validate_thresholds(const la_rx_cgm_sq_profile_thresholds& thresholds) const
{
    la_uint_t threshold_max = bit_utils::ones(rx_cgm_sq_profile_lut_memory::fields::SLICE_SQ_THR0_WIDTH);
    la_uint_t threshold_max_bytes = threshold_max * la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;

    for (size_t i = 0; i < LA_RX_CGM_NUM_SQ_PROFILE_CONFIGURABLE_THRESHOLDS; i++) {
        if (thresholds.thresholds[i] > threshold_max_bytes) {
            return LA_STATUS_EINVAL;
        }
        la_uint_t prev = (i == 0) ? 0 : thresholds.thresholds[i - 1];
        if (thresholds.thresholds[i] < prev) {
            return LA_STATUS_EINVAL;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
rx_cgm_handler::validate_thresholds(const la_rx_cgm_sms_bytes_quantization_thresholds& thresholds) const
{
    la_uint_t threshold_max = bit_utils::ones(rx_cgm_sq_profile_lut_memory::fields::SLICE_HR_THRESHOLD_OR_TIMER_MAX_WIDTH);
    la_uint_t threshold_max_bytes = threshold_max * la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;

    for (size_t i = 0; i < LA_CGM_NUM_SMS_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS; i++) {
        if (thresholds.thresholds[i] > threshold_max_bytes) {
            return LA_STATUS_EINVAL;
        }
        la_uint_t prev = (i == 0) ? 0 : thresholds.thresholds[i - 1];
        if (thresholds.thresholds[i] < prev) {
            return LA_STATUS_EINVAL;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
rx_cgm_handler::get_rx_cgm_sq_buffer_count(la_slice_id_t slice,
                                           la_ifg_id_t ifg,
                                           la_uint_t serdes,
                                           la_traffic_class_t tc,
                                           size_t& out_buffers)
{
    la_uint_t sq_base = get_sq_base(ifg, serdes);
    la_uint_t sq = sq_base + tc;

    auto sq_counters_table = (*m_device->m_pacific_tree->rx_cgm->sq_counters_table)[slice];
    rx_cgm_sq_counters_table_memory sq_counters_table_memory;

    la_status status = m_device->m_ll_device->read_memory(sq_counters_table, sq, sq_counters_table_memory);
    return_on_error(status);

    out_buffers = sq_counters_table_memory.fields.slice_sq_buffer_counter;

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
