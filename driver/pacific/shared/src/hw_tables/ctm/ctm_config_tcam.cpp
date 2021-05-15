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

#include "ctm_config_tcam.h"

#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "ctm_string.h"
#include "lld/ll_device.h"

namespace silicon_one
{

void
ctm_config_tcam::map_input_interfaces()
{
    for (size_t ring_idx = 0; ring_idx < ctm::NUM_RINGS; ++ring_idx) {
        for (size_t key_ch_idx = 0; key_ch_idx < ctm::NUM_CHANNELS_PER_CORE; ++key_ch_idx) {
            const ctm::slice_interface_input_desc& in_desc = m_ctm_slice_ifs_mapping_in[ring_idx][key_ch_idx];

            if (in_desc.input_interface == INTERFACE_INVAL) {
                continue;
            }

            size_t abs_interface = in_desc.slice_id * ctm::NUM_INTERFACES_PER_SLICE + in_desc.input_interface;
            m_key_channel_to_abs_input_interface[ring_idx][key_ch_idx] = abs_interface;
        }
    }
}

void
ctm_config_tcam::map_output_interfaces()
{
    for (size_t slice_idx = 0; slice_idx < m_num_of_slices; ++slice_idx) {
        for (size_t out_if_idx = 0; out_if_idx < ctm::NUM_INTERFACES_PER_SLICE; ++out_if_idx) {
            const ctm::slice_interface_out_desc& out_desc = m_ctm_slice_ifs_mapping_out[slice_idx][out_if_idx];
            if (out_desc.result_channel == CHANNEL_INVAL) {
                dassert_crit(out_desc.cdb_core_idx == IDX_INVAL);
                continue;
            }

            dassert_crit(out_desc.cdb_core_idx != IDX_INVAL);
            size_t abs_channel;
            if (out_desc.result_channel >= ctm::RES_CHAN_DBM0) {
                // database mergers. Value is absolute
                abs_channel = out_desc.result_channel;
            } else {
                abs_channel = out_desc.cdb_core_idx * ctm::NUM_CHANNELS_PER_CORE + out_desc.result_channel;
            }

            if (m_output_interface_to_abs_result_channel[slice_idx][out_if_idx] != INVALID_ABS_OUTPUT_INTERFACE_VALUE) {
                // It's possible that several TCAMs are mapped to the same result channel,
                // However, in this case, all of them must be mapped to the same output interface.
                dassert_crit(m_output_interface_to_abs_result_channel[slice_idx][out_if_idx] == abs_channel);
            }

            m_output_interface_to_abs_result_channel[slice_idx][out_if_idx] = abs_channel;
        }
    }

    // config db merger
    for (size_t slice_idx = 0; slice_idx < m_num_of_slices; slice_idx++) {
        group_desc dbm_group(slice_idx, DBM_INTERFACE);
        const vector_alloc<size_t>& eligible_rings = get_eligible_rings_for_group(dbm_group);
        if (eligible_rings.size() > 1) {
            size_t dbm_index = m_ctm_slice_ifs_mapping_out[dbm_group.slice_idx][dbm_group.interface].result_channel;
            dassert_crit(ctm::RES_CHAN_DBM0 <= dbm_index && dbm_index <= ctm::RES_CHAN_DBM3, "Not enough DB mergers.");
            for (size_t ring_idx : eligible_rings) {
                m_dbm[dbm_index - ctm::RES_CHAN_DBM0] |= 1ULL << ring_idx;
            }
        }
    }
}

void
ctm_config_tcam::map_init()
{
    ctm_config_tcam_desc default_tcam_desc = {.narrow_group = nullptr, .wide_group = nullptr};
    m_rings_tcams.resize(ctm::NUM_RINGS);
    for (size_t ring_idx = 0; ring_idx < ctm::NUM_RINGS; ring_idx++) {
        for (size_t subring_idx = 0; subring_idx < get_number_of_subrings(); subring_idx++) {
            m_rings_tcams[ring_idx].push_back(tcams_vec(ctm::NUM_MEMS_PER_SUBRING, default_tcam_desc));
        }
    }

    init_sram_allocator();

    // Map input/output interfaces to ring key/result channels
    map_input_interfaces();
    map_output_interfaces();
}

size_t
ctm_config_tcam::get_lsb_tcam(size_t tcam_idx) const
{
    if (!is_msb_tcam(tcam_idx)) {
        return tcam_idx;
    }
    return (tcam_idx - get_key_320_tcam_offset());
}

size_t
ctm_config_tcam::get_msb_tcam(size_t tcam_idx) const
{
    if (is_msb_tcam(tcam_idx)) {
        return tcam_idx;
    }
    return (tcam_idx + get_key_320_tcam_offset());
}

size_t
ctm_config_tcam::get_paired_tcam(const size_t tcam_idx) const
{
    if (is_msb_tcam(tcam_idx)) {
        return get_lsb_tcam(tcam_idx);
    } else {
        return get_msb_tcam(tcam_idx);
    }
}

ctm_config_tcam::ctm_config_tcam(const ll_device_sptr& ldevice,
                                 bool is_linecard_mode,
                                 size_t lpm_tcam_num_banksets,
                                 size_t number_of_slices)
    : ctm_config(ldevice, number_of_slices),
      m_sram_allocator(nullptr),
      m_slice_groups(number_of_slices),
      m_rings_tcams(),
      m_lpm_tcam_num_banksets(lpm_tcam_num_banksets),
      m_is_stand_alone(!is_linecard_mode)
{

    if (m_is_stand_alone) {
        m_ctm_slice_ifs_mapping_in = s_ctm_slice_ifs_mapping_stand_alone_in;
        m_ctm_slice_ifs_mapping_out = s_ctm_slice_ifs_mapping_stand_alone_out;
    } else /* Line card mode */ {

        m_ctm_slice_ifs_mapping_in = s_ctm_slice_ifs_mapping_line_card_in;
        m_ctm_slice_ifs_mapping_out = s_ctm_slice_ifs_mapping_line_card_out;
    }

    for (size_t ring = 0; ring < ctm::NUM_RINGS; ring++) {
        for (size_t chan = 0; chan < ctm::NUM_CHANNELS_PER_CORE; chan++) {
            m_key_channel_to_abs_input_interface[ring][chan] = INVALID_ABS_INPUT_INTERFACE_VALUE;
        }
    }

    for (size_t slice_idx = 0; slice_idx < m_num_of_slices; ++slice_idx) {
        for (size_t if_idx = 0; if_idx < ctm::NUM_INTERFACES_PER_SLICE; ++if_idx) {
            m_output_interface_to_abs_result_channel[slice_idx][if_idx] = INVALID_ABS_OUTPUT_INTERFACE_VALUE;
        }
        for (size_t group_ifs = 0; group_ifs < group_desc::group_ifs_e::NUMBER_OF_GROUPS_IFS; group_ifs++) {
            const group_desc group(slice_idx, (group_desc::group_ifs_e)group_ifs);
            m_slice_groups[slice_idx].emplace_back(std::make_shared<ctm_config_group>(group));
        }
    }

    for (size_t idx = 0; idx < ctm::NUM_DB_MERGERS; ++idx) {
        m_dbm[idx] = 0;
    }

    // TODO remove this once GB decreased LPM mode is ready
    if (is_gibraltar(m_ll_device->get_device_revision())) {
        // currently we always use increased lpm mode in GB
        m_lpm_tcam_num_banksets = 2;
    }
}

ctm_config_tcam::ctm_tcam_location
ctm_config_tcam::get_tcam_160_key_hw_location(size_t ring_idx, size_t subring_idx, size_t tcam_idx) const
{
    ctm_config_tcam::ctm_tcam_location ret_entry;

    const ctm_config_group_sptr& narrow_group = m_rings_tcams[ring_idx][subring_idx][tcam_idx].narrow_group;
    if (narrow_group == nullptr) {
        ret_entry.is_valid = false;
        return ret_entry;
    }

    ret_entry.is_valid = true;

    ret_entry.ring_idx = ring_idx;
    ret_entry.subring_idx = subring_idx;
    // tcam
    ret_entry.lsb_tcam_idx = tcam_idx;
    ret_entry.msb_tcam_idx = MEM_IDX_INVAL;

    // SRAM
    size_t sram_ring_idx = cdb_ring_to_sram_allcoator_ring(ring_idx, subring_idx);
    ctm_sram_pair srams = m_sram_allocator->get_srams_by_tcam(sram_ring_idx, tcam_idx);

    if (srams.lsb_sram_idx == MEM_IDX_INVAL) {
        ret_entry.is_valid = false;
        return ret_entry;
    }

    const group_desc desc = narrow_group->get_group_desc();
    ctm::num_srams num_of_srams = get_ifs_payload_srams_number(desc.interface);

    ret_entry.sram_offset = (srams.sram_half == ctm_sram_half::FIRST_HALF) ? 0 : 512;
    if (num_of_srams == ctm::num_srams::TWO_SRAMS) { // 64b result
        ret_entry.sram_lsb_idx = srams.lsb_sram_idx;
        ret_entry.sram_msb_idx = srams.msb_sram_idx;

    } else {
        ret_entry.sram_lsb_idx = srams.lsb_sram_idx;
        ret_entry.sram_msb_idx = MEM_IDX_INVAL;
    }

    return ret_entry;
}

ctm_config_tcam::ctm_tcam_location
ctm_config_tcam::get_tcam_320_key_hw_location(size_t ring_idx, size_t subring_idx, size_t tcam_idx) const
{
    ctm_config_tcam::ctm_tcam_location ret_entry;

    const ctm_config_group_sptr& wide_group = m_rings_tcams[ring_idx][subring_idx][tcam_idx].wide_group;
    if (wide_group == nullptr || !is_msb_tcam(tcam_idx)) {
        ret_entry.is_valid = false;
        return ret_entry;
    }
    ret_entry.is_valid = true;

    ret_entry.ring_idx = ring_idx;
    ret_entry.subring_idx = subring_idx;

    // tcam
    ret_entry.msb_tcam_idx = tcam_idx;
    size_t lsb_tcam_idx = get_lsb_tcam(tcam_idx);
    ret_entry.lsb_tcam_idx = lsb_tcam_idx;

    // SRAM

    // SRAM payload should be written under the msb TCAM, thus we request the MSB TCAM's SRAM desc.
    size_t sram_ring_idx = cdb_ring_to_sram_allcoator_ring(ring_idx, subring_idx);
    ctm_sram_pair srams = m_sram_allocator->get_srams_by_tcam(sram_ring_idx, ret_entry.msb_tcam_idx);

    if (srams.lsb_sram_idx == MEM_IDX_INVAL) {
        ret_entry.is_valid = false;
        return ret_entry;
    }

    const group_desc desc = wide_group->get_group_desc();
    ctm::num_srams num_of_srams = get_ifs_payload_srams_number(desc.interface);

    dassert_crit(num_of_srams != num_srams::NUM_SRAMS_INVAL);

    ret_entry.sram_offset = (srams.sram_half == ctm_sram_half::FIRST_HALF) ? 0 : 512;
    if (num_of_srams == ctm::num_srams::TWO_SRAMS) { // 64b result
        ret_entry.sram_lsb_idx = srams.lsb_sram_idx;
        ret_entry.sram_msb_idx = srams.msb_sram_idx;
    } else {
        ret_entry.sram_lsb_idx = MEM_IDX_INVAL;

        // When SRAM pair contains only one SRAM, it's located in the LSB.
        ret_entry.sram_msb_idx = srams.lsb_sram_idx;
    }

    return ret_entry;
}

size_t
ctm_config_tcam::get_group_result_channel(size_t ring_idx, const group_desc& group) const
{
    // TODO: This is assuming the interfaces are encoded the same as HW on both mapping and group_desc.

    // In case of a wide group, we would like to return the result channel of the MSB narrow group.
    size_t group_ifs = group.interface;
    if (group.is_wide()) {
        group_desc msb_desc = get_msb_narrow_group_from_wide_group(group);
        group_ifs = msb_desc.interface;
    }
    size_t result_channel = m_ctm_slice_ifs_mapping_out[group.slice_idx][group_ifs].result_channel;

    if (result_channel == CHANNEL_INVAL) {
        return result_channel;
    }

    if (result_channel < RES_CHAN_DBM0 && ring_idx != m_ctm_slice_ifs_mapping_out[group.slice_idx][group_ifs].cdb_core_idx) {
        return CHANNEL_INVAL;
    }

    if (result_channel >= RES_CHAN_DBM0) {
        dassert_crit(result_channel < RES_CHAN_DBM0 + NUM_DB_MERGERS);
        result_channel = 0;
    }
    return result_channel;
}

void
ctm_config_tcam::add_tcam_to_group(const group_desc& group, size_t ring_idx, size_t subring_idx, size_t tcam_idx)
{
    ctm_config_group_sptr ctm_group = m_slice_groups[group.slice_idx][group.interface];
    size_t lsb_tcam_idx = IDX_INVAL;
    if (group.is_wide()) {
        dassert_crit(is_msb_tcam(tcam_idx));
        dassert_crit(m_rings_tcams[ring_idx][subring_idx][tcam_idx].wide_group == nullptr);
        lsb_tcam_idx = get_lsb_tcam(tcam_idx);
        dassert_crit(tcam_idx != lsb_tcam_idx);
        dassert_crit(m_rings_tcams[ring_idx][subring_idx][lsb_tcam_idx].wide_group == nullptr);
        m_rings_tcams[ring_idx][subring_idx][tcam_idx].wide_group = ctm_group;
        m_rings_tcams[ring_idx][subring_idx][lsb_tcam_idx].wide_group = ctm_group;
    } else {
        dassert_crit(m_rings_tcams[ring_idx][subring_idx][tcam_idx].narrow_group == nullptr);
        m_rings_tcams[ring_idx][subring_idx][tcam_idx].narrow_group = ctm_group;
    }
    ctm_group->add_tcam(ring_idx, subring_idx, tcam_idx, lsb_tcam_idx);
}

const std::vector<tcam_desc>&
ctm_config_tcam::get_eligible_tcams_for_group(const group_desc& desc) const
{
    const ctm_config_group& group = *m_slice_groups[desc.slice_idx][desc.interface];

    const std::vector<tcam_desc>& ret_list = group.get_msb_tcams();

    return ret_list;
}

const std::vector<tcam_desc>&
ctm_config_tcam::get_eligible_lsb_tcams_for_wide_group(const group_desc& desc) const
{
    dassert_crit(desc.is_wide());
    const ctm_config_group& group = *m_slice_groups[desc.slice_idx][desc.interface];

    const std::vector<tcam_desc>& ret_list = group.get_lsb_tcams();

    return ret_list;
}

std::vector<group_desc>
ctm_config_tcam::get_groups_by_tcam(const tcam_desc& tcam) const
{
    std::vector<group_desc> ret_vec;
    const ctm_config_tcam_desc& config_desc = m_rings_tcams[tcam.ring_idx][tcam.subring_idx][tcam.tcam_idx];
    if (config_desc.narrow_group) {
        ret_vec.push_back(config_desc.narrow_group->get_group_desc());
    }
    if (config_desc.wide_group) {
        ret_vec.push_back(config_desc.wide_group->get_group_desc());
    }
    return ret_vec;
}

bool
ctm_config_tcam::is_tcam_free(size_t ring_idx, size_t subring_idx, size_t tcam_idx) const
{
    if (is_lpm_tcam(ring_idx, subring_idx, tcam_idx)) {
        return false;
    }
    const ctm_config_tcam_desc& desc = m_rings_tcams[ring_idx][subring_idx][tcam_idx];
    return (desc.narrow_group == nullptr) && (desc.wide_group == nullptr);
}

bool
ctm_config_tcam::is_lpm_tcam(size_t ring_idx, size_t subring_idx, size_t tcam_idx) const
{
    dassert_crit(m_lpm_tcams_ring0.size() > 0);
    dassert_crit(m_lpm_tcams_ring1.size() > 0);
    if ((ring_idx % 2) == 1) {
        return contains(m_lpm_tcams_ring1, tcam_idx);
    } else {
        return contains(m_lpm_tcams_ring0, tcam_idx);
    }
}

bool
ctm_config_tcam::is_group_connected_to_ring_input(size_t ring_idx, const group_desc& group) const
{
    for (size_t key_channel = 0; key_channel < ctm::NUM_CHANNELS_PER_CORE; key_channel++) {
        if (m_ctm_slice_ifs_mapping_in[ring_idx][key_channel].slice_id == group.slice_idx
            && m_ctm_slice_ifs_mapping_in[ring_idx][key_channel].input_interface == group.interface) {
            return true;
        }
    }
    return false;
}

vector_alloc<size_t>
ctm_config_tcam::get_eligible_rings_for_group(const group_desc& group) const
{
    // For a narrow group main group can be LSB/MSB narrow group, in case of wide group, main group will contain the MSB group and
    // secondary group will contain the LSB group.
    group_desc main_group = group;
    group_desc secondary_group = group_desc();
    dassert_crit(secondary_group.interface == group_desc::NUMBER_OF_GROUPS_IFS);

    if (group.is_wide()) {
        main_group = get_msb_narrow_group_from_wide_group(group);
        secondary_group = get_lsb_narrow_group_from_wide_group(group);
    }
    vector_alloc<size_t> ret_eligible_rings;
    for (size_t ring_idx = 0; ring_idx < ctm::NUM_RINGS; ring_idx++) {
        // It's assumed that both the static input interface and the group interface are defined as HW definitions, and
        // therefore they can be compared.
        if (is_group_connected_to_ring_input(ring_idx, main_group)) {

            size_t result_channel = get_group_result_channel(ring_idx, main_group);
            if (result_channel == CHANNEL_INVAL) {
                // Main group must have both input and output channel.
                continue;
            }

            if (secondary_group.interface != group_desc::NUMBER_OF_GROUPS_IFS
                && is_group_connected_to_ring_input(ring_idx, secondary_group) == false) {
                // Group is wide but only MSB interface mapped to ring's key channel.
                dassert_crit(false, "Based on current static mapping, MSB and LSB interfaces are epected to be mapped together.");
                continue;
            }

            dassert_crit(!contains(ret_eligible_rings, ring_idx));
            ret_eligible_rings.push_back(ring_idx);
        }
    }
    return ret_eligible_rings;
}

la_status
ctm_config_tcam::find_best_tcam_to_allocate_in_ring_for_wide_group(size_t ring_idx,
                                                                   size_t subring_idx,
                                                                   const group_desc& group,
                                                                   size_t& out_msb_tcam_idx,
                                                                   size_t& out_lsb_tcam_idx,
                                                                   allocation_priority_e& out_priority)
{
    dassert_crit(group.is_wide());
    const group_desc& msb_narrow_group = get_msb_narrow_group_from_wide_group(group);
    const group_desc& lsb_narrow_group = get_lsb_narrow_group_from_wide_group(group);
    size_t msb_result_channel = get_group_result_channel(ring_idx, msb_narrow_group);
    dassert_crit(msb_result_channel != CHANNEL_INVAL);

    out_msb_tcam_idx = IDX_INVAL;
    out_lsb_tcam_idx = IDX_INVAL;
    out_priority = allocation_priority_e::INVAL_PRIORITY;

    la_status status;

    status = find_create_pair_tcam_to_allocate(ring_idx, subring_idx, lsb_narrow_group, out_lsb_tcam_idx);
    if (status == LA_STATUS_SUCCESS) {
        dassert_crit(!is_msb_tcam(out_lsb_tcam_idx));
        out_priority = allocation_priority_e::NEW_PAIR;
        return LA_STATUS_SUCCESS;
    }

    size_t sram_ring_idx = cdb_ring_to_sram_allcoator_ring(ring_idx, subring_idx);
    bool can_allocate_sram_in_ring = m_sram_allocator->can_allocate_srams(sram_ring_idx, msb_result_channel);
    if (!can_allocate_sram_in_ring) {
        return LA_STATUS_ERESOURCE;
    }

    status = find_create_pair_tcam_to_allocate(ring_idx, subring_idx, msb_narrow_group, out_msb_tcam_idx);
    if (status == LA_STATUS_SUCCESS) {
        dassert_crit(is_tcam_eligible_for_group(ring_idx, out_msb_tcam_idx, msb_narrow_group));
        dassert_crit(is_msb_tcam(out_msb_tcam_idx));
        out_priority = allocation_priority_e::NEW_PAIR;
        return LA_STATUS_SUCCESS;
    }

    status = find_free_pair_tcam_to_allocate(ring_idx, subring_idx, msb_narrow_group, out_msb_tcam_idx);
    if (status == LA_STATUS_SUCCESS) {
        out_lsb_tcam_idx = get_lsb_tcam(out_msb_tcam_idx);
        dassert_crit(out_msb_tcam_idx != out_lsb_tcam_idx);
        dassert_crit(is_tcam_free(ring_idx, subring_idx, out_msb_tcam_idx)
                     && is_tcam_free(ring_idx, subring_idx, out_lsb_tcam_idx));

        out_priority = allocation_priority_e::ANY_TCAM;
        return LA_STATUS_SUCCESS;
    }

    return LA_STATUS_ERESOURCE;
}

la_status
ctm_config_tcam::find_best_tcam_to_allocate_for_wide_group(const group_desc& group,
                                                           tcam_desc& out_msb_tcam_desc,
                                                           tcam_desc& out_lsb_tcam_desc)
{
    dassert_crit(group.is_wide());

    const vector_alloc<size_t> eligible_rings_for_group = get_eligible_rings_for_group(group);

    allocation_priority_e best_prio = allocation_priority_e::INVAL_PRIORITY;
    out_msb_tcam_desc = tcam_desc(IDX_INVAL, IDX_INVAL, IDX_INVAL);
    out_lsb_tcam_desc = tcam_desc(IDX_INVAL, IDX_INVAL, IDX_INVAL);

    for (size_t ring_idx : eligible_rings_for_group) {

        for (size_t subring_idx = get_number_of_subrings(); subring_idx-- > 0;) {

            size_t out_msb_tcam_idx;
            size_t out_lsb_tcam_idx;
            allocation_priority_e out_prio = allocation_priority_e::INVAL_PRIORITY;
            la_status status = find_best_tcam_to_allocate_in_ring_for_wide_group(
                ring_idx, subring_idx, group, out_msb_tcam_idx, out_lsb_tcam_idx, out_prio);
            if (status == LA_STATUS_SUCCESS && best_prio < out_prio) {
                out_msb_tcam_desc = tcam_desc(ring_idx, subring_idx, out_msb_tcam_idx);
                out_lsb_tcam_desc = tcam_desc(ring_idx, subring_idx, out_lsb_tcam_idx);
                best_prio = out_prio;
                if (best_prio == allocation_priority_e::HIGHEST_PRIORITY) {
                    return LA_STATUS_SUCCESS;
                }
            }
        }
    }

    if (out_lsb_tcam_desc.ring_idx == IDX_INVAL && out_msb_tcam_desc.ring_idx == IDX_INVAL) {
        return LA_STATUS_ERESOURCE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
ctm_config_tcam::allocate_tcam_for_wide_group(const group_desc& wide_group, tcam_desc& out_tcam)
{
    dassert_crit(wide_group.is_wide());

    size_t ring_to_allocate = IDX_INVAL;
    size_t subring_to_allocate = IDX_INVAL;
    size_t lsb_idx_to_allocate = IDX_INVAL;
    size_t msb_idx_to_allocate = IDX_INVAL;

    tcam_desc out_msb_desc;
    tcam_desc out_lsb_desc;

    la_status status = find_best_tcam_to_allocate_for_wide_group(wide_group, out_msb_desc, out_lsb_desc);
    if (status != LA_STATUS_SUCCESS) {
        dassert_crit(status == LA_STATUS_ERESOURCE);
        return status;
    }

    // Found TCAM/s to allcoate.
    ring_to_allocate = out_msb_desc.ring_idx;
    dassert_crit(ring_to_allocate != IDX_INVAL);
    subring_to_allocate = out_msb_desc.subring_idx;
    dassert_crit(subring_to_allocate != IDX_INVAL);
    lsb_idx_to_allocate = out_lsb_desc.tcam_idx;
    msb_idx_to_allocate = out_msb_desc.tcam_idx;

    dassert_crit(lsb_idx_to_allocate != IDX_INVAL || msb_idx_to_allocate != IDX_INVAL);

    size_t lsb_tcam = IDX_INVAL;
    size_t sram_ring_idx = cdb_ring_to_sram_allcoator_ring(ring_to_allocate, subring_to_allocate);
    if (lsb_idx_to_allocate != IDX_INVAL) {
        const group_desc& lsb_desc = get_lsb_narrow_group_from_wide_group(wide_group);

        bool configure_sram = false;
        if (is_tcam_eligible_for_group(ring_to_allocate, lsb_idx_to_allocate, lsb_desc)) {
            add_tcam_to_group(lsb_desc, ring_to_allocate, subring_to_allocate, lsb_idx_to_allocate);
            size_t lsb_result_channel = get_group_result_channel(ring_to_allocate, lsb_desc);
            dassert_crit(lsb_result_channel != CHANNEL_INVAL);
            la_status status = m_sram_allocator->allocate_srams(sram_ring_idx, lsb_idx_to_allocate, lsb_result_channel);
            dassert_crit(status == LA_STATUS_SUCCESS);
            configure_sram = true;
        }
        size_t lsb_key_channel = get_group_key_channel(lsb_desc);

        // HW writing shouldn't fail.
        configure_tcam(ring_to_allocate, subring_to_allocate, lsb_idx_to_allocate, lsb_key_channel, configure_sram);

        lsb_tcam = lsb_idx_to_allocate;
        dassert_crit(!is_msb_tcam(lsb_tcam));
    }

    if (msb_idx_to_allocate != IDX_INVAL) {
        const group_desc& msb_desc = get_msb_narrow_group_from_wide_group(wide_group);

        dassert_crit(lsb_tcam == IDX_INVAL || lsb_tcam == get_lsb_tcam(msb_idx_to_allocate));
        if (lsb_tcam == IDX_INVAL) {
            lsb_tcam = get_lsb_tcam(msb_idx_to_allocate);
        }

        add_tcam_to_group(msb_desc, ring_to_allocate, subring_to_allocate, msb_idx_to_allocate);

        size_t msb_result_channel = get_group_result_channel(ring_to_allocate, msb_desc);
        dassert_crit(msb_result_channel != CHANNEL_INVAL);
        la_status status = m_sram_allocator->allocate_srams(sram_ring_idx, msb_idx_to_allocate, msb_result_channel);
        dassert_crit(status == LA_STATUS_SUCCESS);

        size_t msb_key_channel = get_group_key_channel(msb_desc);
        // HW writing shouldn't fail.
        configure_tcam(ring_to_allocate, subring_to_allocate, msb_idx_to_allocate, msb_key_channel, true /* configure SRAM */);
    }

    dassert_crit(lsb_tcam != IDX_INVAL);
    dassert_crit(!is_msb_tcam(lsb_tcam));

    add_tcam_to_group(wide_group, ring_to_allocate, subring_to_allocate, get_msb_tcam(lsb_tcam));

    out_tcam.tcam_idx = lsb_tcam;
    out_tcam.subring_idx = subring_to_allocate;
    out_tcam.ring_idx = ring_to_allocate;
    return LA_STATUS_SUCCESS;
}

la_status
ctm_config_tcam::allocate_tcam_for_group(const group_desc& group, tcam_desc& out_tcam)
{
    la_status status;
    if (group.is_wide()) {
        status = allocate_tcam_for_wide_group(group, out_tcam);
    } else {
        status = allocate_tcam_for_narrow_group(group, out_tcam);
    }
    if (status == LA_STATUS_SUCCESS) {
        log_debug(RA,
                  "ctm_config allocated ring %zu subring %zu TCAM %zu for %s",
                  out_tcam.ring_idx,
                  out_tcam.subring_idx,
                  out_tcam.tcam_idx,
                  to_string(group).c_str());
    } else {
        log_debug(RA, "ctm_config failed to allocate TCAM for %s", to_string(group).c_str());
    }

    return status;
}

la_status
ctm_config_tcam::find_best_tcam_to_allocate_for_narrow_group(const group_desc& group, tcam_desc& out_tcam_desc)
{

    const vector_alloc<size_t> eligible_rings_for_group = get_eligible_rings_for_group(group);

    size_t out_tcam_idx;
    allocation_priority_e out_priority;
    allocation_priority_e best_priority = allocation_priority_e::INVAL_PRIORITY;
    out_tcam_desc.ring_idx = IDX_INVAL;
    out_tcam_desc.subring_idx = IDX_INVAL;
    out_tcam_desc.tcam_idx = IDX_INVAL;

    for (size_t ring_idx : eligible_rings_for_group) {
        size_t result_channel = get_group_result_channel(ring_idx, group);
        for (size_t subring_idx = get_number_of_subrings(); subring_idx-- > 0;) {

            dassert_crit(result_channel != CHANNEL_INVAL); // When allocating for narrow group, TCAM is expected to have payload.

            size_t sram_ring_idx = cdb_ring_to_sram_allcoator_ring(ring_idx, subring_idx);
            bool can_allocate_srams = m_sram_allocator->can_allocate_srams(sram_ring_idx, result_channel);
            if (!can_allocate_srams) {
                log_debug(RA,
                          "ctm_config can't allocate SRAM for %s on ring %zu subring %zu.",
                          to_string(group).c_str(),
                          ring_idx,
                          subring_idx);
                continue;
            }

            la_status status
                = find_best_tcam_to_allocate_in_ring_for_narrow_group(ring_idx, subring_idx, group, out_tcam_idx, out_priority);
            if (status == LA_STATUS_SUCCESS && out_priority > best_priority) {
                best_priority = out_priority;
                out_tcam_desc.ring_idx = ring_idx;
                out_tcam_desc.subring_idx = subring_idx;
                out_tcam_desc.tcam_idx = out_tcam_idx;
                if (best_priority == allocation_priority_e::HIGHEST_PRIORITY) {
                    return LA_STATUS_SUCCESS;
                }
            }
        }
    }

    if (out_tcam_desc.ring_idx == IDX_INVAL) {
        return LA_STATUS_ERESOURCE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
ctm_config_tcam::allocate_specific_tcam_for_narrow_group(const group_desc& group, const tcam_desc& tcam)
{
    dassert_crit(!group.is_wide());
    dassert_crit(m_rings_tcams[tcam.ring_idx][tcam.subring_idx][tcam.tcam_idx].narrow_group == nullptr);

    size_t result_channel = get_group_result_channel(tcam.ring_idx, group);
    if (result_channel != CHANNEL_INVAL) {
        size_t sram_ring_idx = cdb_ring_to_sram_allcoator_ring(tcam.ring_idx, tcam.subring_idx);
        bool can_allocate_srams = m_sram_allocator->can_allocate_srams(sram_ring_idx, result_channel);
        if (!can_allocate_srams) {
            return LA_STATUS_ERESOURCE;
        }

        do_allocate_tcam_for_narrow_group(group, tcam);
    }
    return LA_STATUS_SUCCESS;
}

la_status
ctm_config_tcam::allocate_tcam_for_narrow_group(const group_desc& group, tcam_desc& out_tcam)
{
    dassert_crit(!group.is_wide());
    la_status status;
    status = find_best_tcam_to_allocate_for_narrow_group(group, out_tcam);
    if (status != LA_STATUS_SUCCESS) {
        dassert_crit(status == LA_STATUS_ERESOURCE);
        return status;
    }

    do_allocate_tcam_for_narrow_group(group, out_tcam);

    return LA_STATUS_SUCCESS;
}

void
ctm_config_tcam::do_allocate_tcam_for_narrow_group(const group_desc& group, const tcam_desc& tcam)
{
    add_tcam_to_group(group, tcam.ring_idx, tcam.subring_idx, tcam.tcam_idx);

    size_t result_channel = get_group_result_channel(tcam.ring_idx, group);
    dassert_crit(result_channel != CHANNEL_INVAL); // When allocating for narrow group, TCAM is always expected to have payload.
    size_t sram_ring_idx = cdb_ring_to_sram_allcoator_ring(tcam.ring_idx, tcam.subring_idx);
    la_status status = m_sram_allocator->allocate_srams(sram_ring_idx, tcam.tcam_idx, result_channel);
    dassert_crit(status == LA_STATUS_SUCCESS);

    size_t key_channel = get_group_key_channel(group);

    // HW writing shouldn't fail.
    configure_tcam(tcam.ring_idx, tcam.subring_idx, tcam.tcam_idx, key_channel, true);

    if (can_insert_tcam_to_wide_group(tcam.ring_idx, tcam.subring_idx, tcam.tcam_idx)) {
        group_desc::group_ifs_e wide_ifs = get_wide_ifs(group.interface);
        group_desc wide_desc(group.slice_idx, wide_ifs);
        add_tcam_to_group(wide_desc, tcam.ring_idx, tcam.subring_idx, get_msb_tcam(tcam.tcam_idx));
    }
}

la_status
ctm_config_tcam::find_best_tcam_to_allocate_in_ring_for_narrow_group(size_t ring_idx,
                                                                     size_t subring_idx,
                                                                     const group_desc& group,
                                                                     size_t& out_tcam_idx,
                                                                     allocation_priority_e& out_priority)
{
    la_status status;
    // Finda TCAM to allocate which completes a pair for a wide group.
    status = find_create_pair_tcam_to_allocate(ring_idx, subring_idx, group, out_tcam_idx);
    if (status == LA_STATUS_SUCCESS) {
        out_priority = allocation_priority_e::NEW_PAIR;
        return status;
    }

    // Find TCAM to allocate which is part of free part, so the pair can be completed on future allcoations.
    status = find_free_pair_tcam_to_allocate(ring_idx, subring_idx, group, out_tcam_idx);
    if (status == LA_STATUS_SUCCESS) {
        out_priority = allocation_priority_e::POSSIBLE_PAIR;
        return status;
    }

    // Find TCAM to allocate which can never be paired because of LPM.
    status = find_lpm_blocked_pair_tcam_to_allocate(ring_idx, subring_idx, group, out_tcam_idx);
    if (status == LA_STATUS_SUCCESS) {
        out_priority = allocation_priority_e::LPM_BLOCKED_PAIR;
        return status;
    }

    // Find any TCAM to allocate.
    status = find_any_tcam_to_allocate(ring_idx, subring_idx, group, out_tcam_idx);
    if (status == LA_STATUS_SUCCESS) {
        out_priority = allocation_priority_e::ANY_TCAM;
        return status;
    }
    return LA_STATUS_ERESOURCE;
}

bool
ctm_config_tcam::is_msb_ifs(group_desc::group_ifs_e interface) const
{
    return (interface == group_desc::group_ifs_e::GROUP_IFS_FW0_NARROW)
           || (interface == group_desc::group_ifs_e::GROUP_IFS_TX0_NARROW);
}

la_status
ctm_config_tcam::find_any_tcam_to_allocate(size_t ring_idx, size_t subring_idx, const group_desc& group, size_t& out_tcam_idx) const
{
    for (size_t tcam_idx = NUM_MEMS_PER_SUBRING; tcam_idx-- > 0;) {
        if (is_tcam_free(ring_idx, subring_idx, tcam_idx)) {
            out_tcam_idx = tcam_idx;
            return LA_STATUS_SUCCESS;
        }
    }
    return LA_STATUS_ERESOURCE;
}

la_status
ctm_config_tcam::find_lpm_blocked_pair_tcam_to_allocate(size_t ring_idx,
                                                        size_t subring_idx,
                                                        const group_desc& group,
                                                        size_t& out_tcam_idx) const
{
    for (size_t lpm_tcam_idx = NUM_MEMS_PER_SUBRING; lpm_tcam_idx-- > 0;) {
        if (!is_lpm_tcam(ring_idx, subring_idx, lpm_tcam_idx)) {
            continue;
        }
        size_t candidate_tcam = is_msb_tcam(lpm_tcam_idx) ? get_lsb_tcam(lpm_tcam_idx) : get_msb_tcam(lpm_tcam_idx);
        if (is_tcam_free(ring_idx, subring_idx, candidate_tcam)) {
            out_tcam_idx = candidate_tcam;
            return LA_STATUS_SUCCESS;
        }
    }
    return LA_STATUS_ERESOURCE;
}

la_status
ctm_config_tcam::find_free_pair_tcam_to_allocate(size_t ring_idx,
                                                 size_t subring_idx,
                                                 const group_desc& group,
                                                 size_t& out_tcam_idx) const
{
    dassert_crit(!group.is_wide());
    if (group.interface == group_desc::group_ifs_e::GROUP_IFS_TERM) {
        return LA_STATUS_ERESOURCE;
    }
    for (size_t lsb_tcam_idx = NUM_MEMS_PER_SUBRING; lsb_tcam_idx-- > 0;) {
        if (is_msb_tcam(lsb_tcam_idx)) {
            continue;
        }
        size_t msb_tcam_idx = get_msb_tcam(lsb_tcam_idx);

        if (is_tcam_free(ring_idx, subring_idx, lsb_tcam_idx) && is_tcam_free(ring_idx, subring_idx, msb_tcam_idx)) {
            out_tcam_idx = is_msb_ifs(group.interface) ? msb_tcam_idx : lsb_tcam_idx;
            return LA_STATUS_SUCCESS;
        }
    }

    return LA_STATUS_ERESOURCE;
}

la_status
ctm_config_tcam::find_create_pair_tcam_to_allocate(size_t ring_idx,
                                                   size_t subring_idx,
                                                   const group_desc& group,
                                                   size_t& out_tcam_idx) const
{
    if (group.interface == group_desc::group_ifs_e::GROUP_IFS_TERM) {
        return LA_STATUS_ERESOURCE;
    }
    for (size_t tcam_idx = NUM_MEMS_PER_SUBRING; tcam_idx-- > 0;) {
        if (!is_tcam_free(ring_idx, subring_idx, tcam_idx)) {
            continue;
        }
        if (will_allocation_create_pair(ring_idx, subring_idx, tcam_idx, group)) {
            out_tcam_idx = tcam_idx;
            return LA_STATUS_SUCCESS;
        }
    }
    return LA_STATUS_ERESOURCE;
}

bool
ctm_config_tcam::will_allocation_create_pair(size_t ring_idx, size_t subring_idx, size_t tcam_idx, const group_desc& group) const
{
    dassert_crit(is_tcam_free(ring_idx, subring_idx, tcam_idx));

    if (group.interface == group_desc::group_ifs_e::GROUP_IFS_TERM) {
        dassert_crit(false);
        return false;
    }

    size_t msb_tcam = get_msb_tcam(tcam_idx);
    size_t lsb_tcam = get_lsb_tcam(tcam_idx);

    if (is_lpm_tcam(ring_idx, subring_idx, msb_tcam) || is_lpm_tcam(ring_idx, subring_idx, lsb_tcam)) {
        return false;
    }

    bool is_new_tcam_msb = (tcam_idx == msb_tcam);

    if (is_new_tcam_msb && is_tcam_free(ring_idx, subring_idx, lsb_tcam)) {
        return false;
    }

    if (!is_new_tcam_msb && is_tcam_free(ring_idx, subring_idx, msb_tcam)) {
        return false;
    }

    const group_desc& msb_desc = is_new_tcam_msb ? group : get_tcam_narrow_group_desc(ring_idx, subring_idx, msb_tcam);
    const group_desc& lsb_desc = is_new_tcam_msb ? get_tcam_narrow_group_desc(ring_idx, subring_idx, lsb_tcam) : group;

    if (msb_desc.slice_idx != lsb_desc.slice_idx) {
        return false;
    }

    return is_ifs_eligible_tcam_pair(msb_desc.interface, lsb_desc.interface);
};

group_desc
ctm_config_tcam::get_tcam_narrow_group_desc(size_t ring_idx, size_t subring_idx, size_t tcam_idx) const
{
    const ctm_config_group_sptr& group_ptr = m_rings_tcams[ring_idx][subring_idx][tcam_idx].narrow_group;
    dassert_crit(group_ptr);
    return group_ptr->get_group_desc();
}

bool
ctm_config_tcam::is_ifs_eligible_tcam_pair(group_desc::group_ifs_e msb_ifs, group_desc::group_ifs_e lsb_ifs) const
{
    bool is_fw
        = (msb_ifs == group_desc::group_ifs_e::GROUP_IFS_FW0_NARROW) && (lsb_ifs == group_desc::group_ifs_e::GROUP_IFS_FW1_NARROW);
    bool is_tx
        = (msb_ifs == group_desc::group_ifs_e::GROUP_IFS_TX0_NARROW) && (lsb_ifs == group_desc::group_ifs_e::GROUP_IFS_TX1_NARROW);

    return is_tx || is_fw;
}

bool
ctm_config_tcam::is_tcam_part_of_pair(size_t ring_idx, size_t subring_idx, size_t tcam_idx) const
{
    return m_rings_tcams[ring_idx][subring_idx][tcam_idx].wide_group != nullptr;
}

bool
ctm_config_tcam::can_insert_tcam_to_wide_group(size_t ring_idx, size_t subring_idx, size_t tcam_idx) const
{
    size_t msb_tcam = get_msb_tcam(tcam_idx);
    size_t lsb_tcam = get_lsb_tcam(tcam_idx);

    if (is_lpm_tcam(ring_idx, subring_idx, msb_tcam) || is_lpm_tcam(ring_idx, subring_idx, lsb_tcam)) {
        return false;
    }
    if (is_tcam_free(ring_idx, subring_idx, msb_tcam) || is_tcam_free(ring_idx, subring_idx, lsb_tcam)) {
        return false;
    }
    const group_desc& msb_desc = get_tcam_narrow_group_desc(ring_idx, subring_idx, msb_tcam);
    const group_desc& lsb_desc = get_tcam_narrow_group_desc(ring_idx, subring_idx, lsb_tcam);

    if (msb_desc.slice_idx != lsb_desc.slice_idx) {
        return false;
    }
    return is_ifs_eligible_tcam_pair(msb_desc.interface, lsb_desc.interface);
}

group_desc::group_ifs_e
ctm_config_tcam::get_wide_ifs(group_desc::group_ifs_e interface) const
{
    switch (interface) {
    case group_desc::group_ifs_e::GROUP_IFS_FW0_NARROW:
    case group_desc::group_ifs_e::GROUP_IFS_FW1_NARROW:
        return group_desc::group_ifs_e::GROUP_IFS_FW_WIDE;
    case group_desc::group_ifs_e::GROUP_IFS_TX0_NARROW:
    case group_desc::group_ifs_e::GROUP_IFS_TX1_NARROW:
        return group_desc::group_ifs_e::GROUP_IFS_TX_WIDE;
    default:
        dassert_crit(false);
        return group_desc::group_ifs_e::NUMBER_OF_GROUPS_IFS;
    }
}

size_t
ctm_config_tcam::get_group_key_channel(const group_desc& group) const
{
    dassert_crit(!group.is_wide());
    size_t out_key_channel = INVALID_ABS_INPUT_INTERFACE_VALUE;
    for (size_t ring_idx = 0; ring_idx < ctm::NUM_RINGS; ++ring_idx) {
        for (size_t key_ch_idx = 0; key_ch_idx < ctm::NUM_CHANNELS_PER_CORE; ++key_ch_idx) {
            const ctm::slice_interface_input_desc& in_desc = m_ctm_slice_ifs_mapping_in[ring_idx][key_ch_idx];

            if (in_desc.input_interface == INTERFACE_INVAL) {
                continue;
            }

            if (in_desc.slice_id == group.slice_idx
                && in_desc.input_interface == group.interface) { // Assuming interface enums both encoded as HW.
                dassert_crit(out_key_channel == INVALID_ABS_INPUT_INTERFACE_VALUE || out_key_channel == key_ch_idx);
                out_key_channel = key_ch_idx;
            }
        }
    }

    return out_key_channel;
}

num_srams
ctm_config_tcam::get_ifs_payload_srams_number(group_desc::group_ifs_e interface) const
{
    // TODO, this is currently static, consider of doing it better.
    if (interface == group_desc::group_ifs_e::GROUP_IFS_FW0_NARROW || interface == group_desc::group_ifs_e::GROUP_IFS_FW1_NARROW
        || interface == group_desc::group_ifs_e::GROUP_IFS_FW_WIDE) {
        return num_srams::TWO_SRAMS;
    }
    return num_srams::ONE_SRAM;
}

void
ctm_config_tcam::init_sram_allocator()
{
    dassert_crit(m_sram_allocator == nullptr);
    size_t num_subrings = get_number_of_subrings();
    m_sram_allocator = make_unique<ctm_sram_allocator>(ctm::NUM_RINGS * num_subrings,
                                                       ctm::NUM_MEMS_PER_SUBRING /* TCAMs */,
                                                       ctm::NUM_MEMS_PER_SUBRING /* SRAMs */,
                                                       ctm::NUM_CHANNELS_PER_CORE);

    for (size_t ring_idx = 0; ring_idx < ctm::NUM_RINGS; ring_idx++) {
        for (size_t subring_idx = 0; subring_idx < get_number_of_subrings(); subring_idx++) {
            for (size_t res_channel = 0; res_channel < ctm::NUM_CHANNELS_PER_CORE; res_channel++) {
                size_t res_channel_ifs_idx = m_ctm_slice_ifs_mapping_in[ring_idx][res_channel].input_interface;
                if (res_channel_ifs_idx == INTERFACE_INVAL) {
                    continue;
                }
                dassert_crit(res_channel_ifs_idx < group_desc::NUMBER_OF_GROUPS_IFS);
                group_desc::group_ifs_e res_channel_ifs = (group_desc::group_ifs_e)res_channel_ifs_idx;
                num_srams payload_width = get_ifs_payload_srams_number(res_channel_ifs);
                size_t sram_ring_idx = cdb_ring_to_sram_allcoator_ring(ring_idx, subring_idx);
                m_sram_allocator->set_result_channel_payload_width(sram_ring_idx, res_channel, payload_width);
            }
        }
    }
}

group_desc
ctm_config_tcam::get_msb_narrow_group_from_wide_group(const group_desc& wide_group) const
{
    group_desc ret_desc = wide_group;
    switch (wide_group.interface) {
    case group_desc::GROUP_IFS_FW_WIDE:
        ret_desc.interface = group_desc::GROUP_IFS_FW0_NARROW;
        break;
    case group_desc::GROUP_IFS_TX_WIDE:
        ret_desc.interface = group_desc::GROUP_IFS_TX0_NARROW;
        break;
    default:
        dassert_crit(false);
        ret_desc.interface = group_desc::NUMBER_OF_GROUPS_IFS;
    }
    return ret_desc;
}

group_desc
ctm_config_tcam::get_lsb_narrow_group_from_wide_group(const group_desc& wide_group) const
{
    group_desc ret_desc = wide_group;
    switch (wide_group.interface) {
    case group_desc::GROUP_IFS_FW_WIDE:
        ret_desc.interface = group_desc::GROUP_IFS_FW1_NARROW;
        break;
    case group_desc::GROUP_IFS_TX_WIDE:
        ret_desc.interface = group_desc::GROUP_IFS_TX1_NARROW;
        break;
    default:
        dassert_crit(false);
        ret_desc.interface = group_desc::NUMBER_OF_GROUPS_IFS;
    }
    return ret_desc;
}

group_desc
ctm_config_tcam::get_wide_group_from_narrow_group(const group_desc& narrow_group) const
{
    dassert_crit(!narrow_group.is_wide());
    group_desc::group_ifs_e wide_ifs = get_wide_ifs(narrow_group.interface);
    group_desc wide_desc(narrow_group.slice_idx, wide_ifs);
    return wide_desc;
}

size_t
ctm_config_tcam::cdb_ring_to_sram_allcoator_ring(size_t ring_idx, size_t subring_idx) const
{
    size_t num_subrings = get_number_of_subrings();
    return num_subrings * ring_idx + subring_idx;
}

bool
ctm_config_tcam::is_tcam_eligible_for_group(size_t ring_idx, size_t tcam_idx, const group_desc& group) const
{
    vector_alloc<size_t> eligible_rings = get_eligible_rings_for_group(group);
    bool is_eligible = contains(eligible_rings, ring_idx);
    return is_eligible;
}

size_t
ctm_config_tcam::get_max_group_scale(const ctm::group_desc& group) const
{
    const vector_alloc<size_t>& eligible_rings = get_eligible_rings_for_group(group);
    size_t number_of_rings = eligible_rings.size();
    size_t size = 0;

    if (group.is_wide()) {
        size = number_of_rings * get_max_wide_scale_per_ring();
    } else {
        size = number_of_rings * get_max_narrow_scale_per_ring();
    }

    return size;
}

size_t
ctm_config_tcam::get_max_narrow_scale_per_ring() const
{
    size_t number_of_subrings = get_number_of_subrings();

    size_t size = ctm::NUM_MEMS_PER_SUBRING * number_of_subrings - 2 * m_lpm_tcam_num_banksets; // 2 for the number of lpm cores

    return size * ctm::BANK_SIZE;
}

size_t
ctm_config_tcam::get_max_wide_scale_per_ring() const
{
    size_t number_of_subrings = get_number_of_subrings();

    size_t size;

    if (is_gibraltar(m_ll_device->get_device_revision())) {
        size = ((ctm::NUM_MEMS_PER_SUBRING - m_lpm_tcam_num_banksets) / 2) * number_of_subrings;
    } else /* Pacific */
    {
        size = ctm::NUM_MEMS_PER_SUBRING * number_of_subrings - 2 * m_lpm_tcam_num_banksets; // 2 for the number of lpm cores
        size = (size - 2 * m_lpm_tcam_num_banksets * number_of_subrings) / 2;                // Each LPM TCAM blocks one pair.
    }

    return size * ctm::BANK_SIZE;
}

la_status
ctm_config_tcam::free_tcam(const tcam_desc& tcam)
{
    if (is_tcam_free(tcam.ring_idx, tcam.subring_idx, tcam.tcam_idx)) {
        // Only TX1 TCAMs are expected to be freed if they are already free.
        // This phenomenon occures because TX1 TCAMs don't belong to narrow group, and they are being automatically freed when
        // freeing their TX0 pair.
        return LA_STATUS_SUCCESS;
    }
    if (is_lpm_tcam(tcam.ring_idx, tcam.subring_idx, tcam.tcam_idx)) {
        dassert_crit(false, "TCAM free invoked with LPM TCAM.");
        return LA_STATUS_EINVAL;
    }
    ctm_sram_pair srams_to_free = {.msb_sram_idx = MEM_IDX_INVAL, .lsb_sram_idx = MEM_IDX_INVAL};
    size_t result_channel = CHANNEL_INVAL;
    ctm_config_tcam_desc& config_tcam_desc = m_rings_tcams[tcam.ring_idx][tcam.subring_idx][tcam.tcam_idx];
    dassert_crit(config_tcam_desc.narrow_group != nullptr || config_tcam_desc.wide_group != nullptr);
    if (config_tcam_desc.narrow_group != nullptr) {
        config_tcam_desc.narrow_group->remove_tcam(tcam.ring_idx, tcam.subring_idx, tcam.tcam_idx, IDX_INVAL);
        const group_desc& narrow_group_desc = config_tcam_desc.narrow_group->get_group_desc();
        result_channel = get_group_result_channel(tcam.ring_idx, narrow_group_desc);
        if (result_channel != CHANNEL_INVAL) {
            size_t sram_ring_idx = cdb_ring_to_sram_allcoator_ring(tcam.ring_idx, tcam.subring_idx);
            srams_to_free = m_sram_allocator->get_srams_by_tcam(sram_ring_idx, tcam.tcam_idx);
            m_sram_allocator->free_srams(sram_ring_idx, tcam.tcam_idx);
        }
        config_tcam_desc.narrow_group = nullptr;
    }
    if (config_tcam_desc.wide_group != nullptr) {
        size_t msb_tcam_idx = get_msb_tcam(tcam.tcam_idx);
        size_t lsb_tcam_idx = get_lsb_tcam(tcam.tcam_idx);
        config_tcam_desc.wide_group->remove_tcam(tcam.ring_idx, tcam.subring_idx, msb_tcam_idx, lsb_tcam_idx);
        config_tcam_desc.wide_group = nullptr;
        // In case we are breaking a pair, we need to update the other part of the pair that it doesn't belong to WIDE group
        // anymore.
        size_t second_tcam_desc_to_update = is_msb_tcam(tcam.tcam_idx) ? lsb_tcam_idx : msb_tcam_idx;
        dassert_crit(m_rings_tcams[tcam.ring_idx][tcam.subring_idx][second_tcam_desc_to_update].wide_group != nullptr);
        m_rings_tcams[tcam.ring_idx][tcam.subring_idx][second_tcam_desc_to_update].wide_group = nullptr;
    }

    log_debug(RA, "ctm_config freed %s", to_string(tcam).c_str());

    invalidate_tcam(tcam, srams_to_free, result_channel); // HW writing shouldn't fail.
    return LA_STATUS_SUCCESS;
}

priority_to_tcams_map
ctm_config_tcam::get_tcams_to_relocate_for_group(const group_desc& group) const
{
    if (group.is_wide()) {
        return get_tcams_to_relocate_for_wide_group(group);
    } else {
        return get_tcams_to_relocate_for_narrow_group(group);
    }
}

priority_to_tcams_map
ctm_config_tcam::get_tcams_to_relocate_for_wide_group(const group_desc& group) const
{
    dassert_crit(group.is_wide());

    priority_to_tcams_map ret_map;
    constexpr size_t pairs_priority
        = 0; // Every valid priority is greater than 0, we would like to insert pairs to the lowest priority which is 0.
    const std::vector<tcam_desc>& eligible_tcams_for_group = get_eligible_tcams_for_group(group);
    const vector_alloc<size_t> elgiible_rings = get_eligible_rings_for_group(group);
    for (size_t ring_idx : elgiible_rings) {
        for (size_t subring_idx = 0; subring_idx < get_number_of_subrings(); subring_idx++) {
            for (size_t msb_tcam_idx = 0; msb_tcam_idx < NUM_MEMS_PER_SUBRING; msb_tcam_idx++) {
                if (!is_msb_tcam(msb_tcam_idx)) {
                    continue;
                }
                size_t lsb_tcam_idx = get_lsb_tcam(msb_tcam_idx);
                tcam_desc msb_tcam_desc = tcam_desc(ring_idx, subring_idx, msb_tcam_idx);
                tcam_desc lsb_tcam_desc = tcam_desc(ring_idx, subring_idx, lsb_tcam_idx);
                if (is_lpm_tcam(ring_idx, subring_idx, lsb_tcam_idx) || is_lpm_tcam(ring_idx, subring_idx, msb_tcam_idx)) {
                    continue;
                }
                if (is_tcam_free(ring_idx, subring_idx, lsb_tcam_idx) && is_tcam_free(ring_idx, subring_idx, msb_tcam_idx)) {
                    continue;
                }

                if (contains(eligible_tcams_for_group, msb_tcam_desc)) {
                    // TCAM already belongs to group.
                    continue;
                }

                size_t msb_prio = 0, lsb_prio = 0;
                if (!is_tcam_free(ring_idx, subring_idx, lsb_tcam_idx)) {
                    lsb_prio = calculate_single_tcam_free_priority_for_wide_group(group, lsb_tcam_desc);
                    if (lsb_prio > 0) {
                        const tcams_container& lsb_tcams_container = create_tcams_container(lsb_tcam_desc);
                        ret_map[lsb_prio].push_back(lsb_tcams_container);
                    }
                }

                if (!is_tcam_free(ring_idx, subring_idx, msb_tcam_idx)) {
                    msb_prio = calculate_single_tcam_free_priority_for_wide_group(group, msb_tcam_desc);
                    if (msb_prio > 0) {
                        const tcams_container& msb_tcams_container = create_tcams_container(msb_tcam_desc);
                        ret_map[msb_prio].push_back(msb_tcams_container);
                    }
                }
                if (msb_prio == 0 && lsb_prio == 0) {
                    const tcams_container& pair_container = create_tcams_container(msb_tcam_desc, lsb_tcam_desc);
                    ret_map[pairs_priority].push_back(pair_container);
                }
            }
        }
    }

    return ret_map;
}

size_t
ctm_config_tcam::calculate_single_tcam_free_priority_for_wide_group(const group_desc& destined_group, const tcam_desc& tcam) const
{
    dassert_crit(destined_group.is_wide());
    static_assert((size_t)wide_single_tcam_free_priority_e::LOWEST_PRIORITY == 0,
                  "Priorites are being used as bit indices and therefore must begin at index 0.");

    size_t complement_tcam_idx = is_msb_tcam(tcam.tcam_idx) ? get_lsb_tcam(tcam.tcam_idx) : get_msb_tcam(tcam.tcam_idx);
    dassert_crit(!is_tcam_free(tcam.ring_idx, tcam.subring_idx, tcam.tcam_idx));
    dassert_crit(!is_lpm_tcam(tcam.ring_idx, tcam.subring_idx, complement_tcam_idx));

    const ctm_config_group_sptr& tcam_narrow_group = m_rings_tcams[tcam.ring_idx][tcam.subring_idx][tcam.tcam_idx].narrow_group;
    if (tcam_narrow_group == nullptr) {
        dassert_crit(m_rings_tcams[tcam.ring_idx][tcam.subring_idx][tcam.tcam_idx].wide_group != nullptr);
        return 0; // TCAMs that belongs only to wide groups should be freed upon freeing the MSB TCAMs.
    }
    const group_desc tcam_group_desc = tcam_narrow_group->get_group_desc();
    bool is_tcam_in_proper_place_for_new_group = (is_msb_ifs(tcam_group_desc.interface) == is_msb_tcam(tcam.tcam_idx))
                                                 && (tcam_group_desc.slice_idx == destined_group.slice_idx)
                                                 && (get_wide_ifs(tcam_group_desc.interface) == destined_group.interface);
    if (is_tcam_in_proper_place_for_new_group) {
        return 0; // There is no improvemnt by freeing TCAM that is in proper place for new group.
    }

    size_t priority = 0;
    if (is_tcam_free(tcam.ring_idx, tcam.subring_idx, complement_tcam_idx)) {
        priority |= 1 << ((size_t)wide_single_tcam_free_priority_e::TCAM_COMPLEMENT_FREE);
    }

    const ctm_config_group_sptr& complement_narrow_group
        = m_rings_tcams[tcam.ring_idx][tcam.subring_idx][complement_tcam_idx].narrow_group;
    if (complement_narrow_group != nullptr) {
        // If TCAM to be freed is MSB/LSB, we consider its interface to be properly fitted after freeing, and then we check whether
        // it can be a pair together with the complement TCAM's interface.
        const group_desc& complement_group_desc = complement_narrow_group->get_group_desc();
        group_desc::group_ifs_e msb_ifs
            = is_msb_tcam(tcam.tcam_idx) ? get_msb_narrow_group_from_wide_group(destined_group).interface : complement_group_desc.interface;
        group_desc::group_ifs_e lsb_ifs
            = !is_msb_tcam(tcam.tcam_idx) ? get_lsb_narrow_group_from_wide_group(destined_group).interface : complement_group_desc.interface;

        if (destined_group.slice_idx == complement_group_desc.slice_idx && is_ifs_eligible_tcam_pair(msb_ifs, lsb_ifs)) {
            priority |= 1 << ((size_t)wide_single_tcam_free_priority_e::TCAM_COMPLEMENT_FIT);
        }
    }

    if (priority > 0) {

        size_t curr_tcam_result_channel = get_group_result_channel(tcam.ring_idx, tcam_group_desc);

        size_t sram_allcoator_ring_idx = cdb_ring_to_sram_allcoator_ring(tcam.ring_idx, tcam.subring_idx);
        const vector_alloc<size_t>& candidate_tcams_indices
            = m_sram_allocator->get_tcams_with_partially_allocated_block(sram_allcoator_ring_idx, curr_tcam_result_channel);

        if (contains(candidate_tcams_indices, tcam.tcam_idx)) {
            priority |= 1 << ((size_t)wide_single_tcam_free_priority_e::TCAM_FREES_SRAM_BLOCK);
        }
        // TODO handle case were can't allocate SRAMs after freeing
    }
    return priority;
}

size_t
ctm_config_tcam::calculate_tcam_free_priority_for_narrow_group(const group_desc& destined_group, const tcam_desc& tcam) const
{
    static_assert((size_t)free_priority_e::LOWEST_PRIORITY == 0,
                  "Priorites are being used as bit indices and therefore must begin at index 0.");

    size_t priority = 0;
    dassert_crit(!is_tcam_free(tcam.ring_idx, tcam.subring_idx, tcam.tcam_idx));
    dassert_crit(!is_lpm_tcam(tcam.ring_idx, tcam.subring_idx, tcam.tcam_idx));
    const ctm_config_group_sptr& narrow_group = m_rings_tcams[tcam.ring_idx][tcam.subring_idx][tcam.tcam_idx].narrow_group;
    const ctm_config_group_sptr& wide_group = m_rings_tcams[tcam.ring_idx][tcam.subring_idx][tcam.tcam_idx].wide_group;
    if (wide_group && !narrow_group) {
        dassert_crit(wide_group->get_group_desc().interface == group_desc::GROUP_IFS_TX_WIDE
                     || (wide_group->get_group_desc().interface == group_desc::GROUP_IFS_FW_WIDE && tcam.ring_idx % 2 == 1));
        // TCAM belong to TX1 key channel, we would like to free it only as a pair with TX0.
        return 0;
    }

    const group_desc tcam_group_desc = narrow_group->get_group_desc();

    if (tcam_group_desc == destined_group) {
        return 0;
    }

    size_t destined_group_result_channel = get_group_result_channel(tcam.ring_idx, destined_group);
    size_t curr_tcam_result_channel = get_group_result_channel(tcam.ring_idx, tcam_group_desc);

    size_t sram_allcoator_ring_idx = cdb_ring_to_sram_allcoator_ring(tcam.ring_idx, tcam.subring_idx);
    const vector_alloc<size_t>& candidate_tcams_indices
        = m_sram_allocator->get_tcams_with_partially_allocated_block(sram_allcoator_ring_idx, curr_tcam_result_channel);

    if (contains(candidate_tcams_indices, tcam.tcam_idx)) {
        priority |= 1 << ((size_t)free_priority_e::TCAM_FREES_SRAM_BLOCK);
    } else if (!m_sram_allocator->can_allocate_srams(tcam.ring_idx, destined_group_result_channel)) {
        return 0;
    }

    priority |= 1 << ((size_t)free_priority_e::ANY_TCAM); // Mark priority as valid.

    if (tcam_group_desc.interface == group_desc::GROUP_IFS_TERM) {
        return priority; // Next priorities calculations are relevant only for TX and FW.
    }

    if (is_msb_ifs(tcam_group_desc.interface) != is_msb_tcam(tcam.tcam_idx)) {
        priority |= 1 << ((size_t)free_priority_e::OLD_TCAM_NOT_IN_PLACE);
    }

    size_t paired_tcam_idx = get_paired_tcam(tcam.tcam_idx);
    // In order to give "TCAM_IN_PLACE_FOR_NEW_GROUP" we need to make sure interface match and that the pair TCAM doesn't belong to
    // LPM.
    if ((is_msb_ifs(destined_group.interface) == is_msb_tcam(tcam.tcam_idx))
        && (!is_lpm_tcam(tcam.ring_idx, tcam.subring_idx, paired_tcam_idx))) {
        priority |= 1 << ((size_t)free_priority_e::TCAM_IN_PLACE_FOR_NEW_GROUP);
    }

    if (!is_tcam_part_of_pair(tcam.ring_idx, tcam.subring_idx, tcam.tcam_idx)) {
        priority |= 1 << ((size_t)free_priority_e::TCAM_ISNT_PART_OF_PAIR);
    }

    return priority;
}

priority_to_tcams_map
ctm_config_tcam::get_tcams_to_relocate_for_narrow_group(const group_desc& group) const
{
    dassert_crit(!group.is_wide());

    priority_to_tcams_map ret_map;

    const vector_alloc<size_t> elgiible_rings = get_eligible_rings_for_group(group);
    for (size_t ring_idx : elgiible_rings) {
        for (size_t subring_idx = 0; subring_idx < get_number_of_subrings(); subring_idx++) {
            for (size_t tcam_idx = 0; tcam_idx < NUM_MEMS_PER_SUBRING; tcam_idx++) {
                if (is_tcam_free(ring_idx, subring_idx, tcam_idx) || is_lpm_tcam(ring_idx, subring_idx, tcam_idx)) {
                    continue;
                }
                tcam_desc tcam = tcam_desc(ring_idx, subring_idx, tcam_idx);
                size_t priority = calculate_tcam_free_priority_for_narrow_group(group, tcam);
                if (priority > 0) {
                    const tcams_container& wrapped_tcam = create_tcams_container(tcam);
                    ret_map[priority].push_back(wrapped_tcam);
                }
            }
        }
    }
    return ret_map;
}

tcams_container
ctm_config_tcam::create_tcams_container(const tcam_desc& tcam) const
{
    tcams_container ret_container;
    ret_container.push_back(tcam);
    return ret_container;
}

tcams_container
ctm_config_tcam::create_tcams_container(const tcam_desc& first_tcam, const tcam_desc& second_tcam) const
{
    tcams_container ret_container;
    ret_container.push_back(first_tcam);
    ret_container.push_back(second_tcam);
    return ret_container;
}

groups_container
ctm_config_tcam::get_competing_groups(const group_desc& group) const
{
    groups_container ret_groups;
    vector_alloc<size_t> eligible_rings_for_group = get_eligible_rings_for_group(group);
    for (size_t slice_idx = 0; slice_idx < NUM_SLICES; slice_idx++) {
        for (size_t group_interface = 0; group_interface < group_desc::NUMBER_OF_GROUPS_IFS; group_interface++) {
            const group_desc candidate_competing_group_desc(slice_idx, (group_desc::group_ifs_e)group_interface);
            if (candidate_competing_group_desc == group) {
                continue;
            }
            vector_alloc<size_t> candidate_competing_group_rings = get_eligible_rings_for_group(candidate_competing_group_desc);
            for (size_t ring_idx : eligible_rings_for_group) {
                if (contains(candidate_competing_group_rings, ring_idx)) {
                    dassert_crit(!contains(ret_groups, candidate_competing_group_desc));
                    ret_groups.push_back(candidate_competing_group_desc);
                    break;
                }
            }
        }
    }
    return ret_groups;
}

vector_alloc<size_t>
ctm_config_tcam::get_spaces_for_group(const group_desc& group) const
{
    const vector_alloc<size_t>& eligible_rings = get_eligible_rings_for_group(group);
    return eligible_rings; // Currently we don't do any mapping from ring to space.
}

} // namespace silicon_one
