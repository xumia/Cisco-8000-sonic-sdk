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

#include "ctm_mgr_tcam.h"
#include "api/types/la_acl_types.h"
#include "common/logger.h"
#include "ctm/ctm_config_gibraltar.h"
#include "ctm/ctm_config_pacific.h"
#include "ctm/ctm_string.h"
#include "ctm_tcam_line_mgr.h"
#include "hw_tables/memory_tcam.h"
#include "lld/ll_device.h"
#include "ra/resource_manager.h"
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace silicon_one
{

ctm_mgr_tcam::ctm_mgr_tcam(const ll_device_sptr& ldevice,
                           bool is_linecard_mode,
                           size_t lpm_tcam_num_banksets,
                           engine_block_mapper block_mapper,
                           size_t number_of_slices)
    : ctm_mgr(ldevice, block_mapper, number_of_slices)
{
    if (ldevice->is_pacific()) {
        m_ctm_config_tcam
            = std::make_shared<ctm_config_pacific>(ldevice, is_linecard_mode, lpm_tcam_num_banksets, number_of_slices);
    } else if (ldevice->is_gibraltar()) {
        m_ctm_config_tcam
            = std::make_shared<ctm_config_gibraltar>(ldevice, is_linecard_mode, lpm_tcam_num_banksets, number_of_slices);
    } else {
        dassert_crit(false); // Should never happen
    }
}

la_status
ctm_mgr_tcam::configure_hw() const
{
    return m_ctm_config_tcam->configure_hw();
}
void
ctm_mgr_tcam::create_line_mgr_for_tcam(const tcam_desc& tcam)
{
    map_alloc<tcam_desc, ctm_tcam_line_mgr>::const_iterator it = m_line_mgr.find(tcam);
    if (it == m_line_mgr.end()) {
        m_line_mgr[tcam] = ctm_tcam_line_mgr(ctm::BANK_SIZE);
    }
}

size_t
ctm_mgr_tcam::get_table_size(const table_desc& desc) const
{
    start_ctm_mgr_api_call(desc);

    dassert_crit(desc.table_id != 0);

    const group_desc& group = get_group_for_table(desc);
    size_t max_table_size = m_ctm_config_tcam->get_max_group_scale(group);
    return max_table_size;
}

set_alloc<group_desc>
ctm_mgr_tcam::get_indirect_compeeting_groups(const group_desc& subject_group, groups_container& subject_compeeting_groups)
{
    set_alloc<group_desc> indirect_competing_groups;
    size_t num_of_spaces_for_subject_group = m_ctm_config_tcam->get_spaces_for_group(subject_group).size();

    if (num_of_spaces_for_subject_group == 2) {
        // There are maximum of 2 spaces per group, so in this case there can be no indirect competing groups.
        return indirect_competing_groups;
    }

    // For each competing group check if it has more TCAM spaces than the subject group. If so it might have some
    // competing groups not in the list of competing groups for the subject group. add all of them and let set filter out copies.
    for (const group_desc& competing_group : subject_compeeting_groups) {
        size_t num_of_spaces_for_compeeting_group = m_ctm_config_tcam->get_spaces_for_group(competing_group).size();

        if (num_of_spaces_for_compeeting_group > num_of_spaces_for_subject_group) {
            groups_container comp_comp_groups = m_ctm_config_tcam->get_competing_groups(competing_group);
            indirect_competing_groups.insert(comp_comp_groups.begin(), comp_comp_groups.end());
        }
    }

    for (const group_desc& competing_group : subject_compeeting_groups) {
        set_alloc<group_desc>::iterator it = std::find(indirect_competing_groups.begin(),
                                                       indirect_competing_groups.end(),
                                                       competing_group); // Filter out subject group, if it is here.
        if (it != indirect_competing_groups.end()) {
            indirect_competing_groups.erase(it);
        }
    }

    set_alloc<group_desc>::iterator it = std::find(indirect_competing_groups.begin(),
                                                   indirect_competing_groups.end(),
                                                   subject_group); // Filter out subject group, if it is here.
    if (it != indirect_competing_groups.end()) {
        indirect_competing_groups.erase(it);
    }

    return indirect_competing_groups;
}

void
ctm_mgr_tcam::count_the_need_for_one_TCAM_space_wide_competition(
    groups_container& competing_groups,
    map_alloc<group_desc, vector_alloc<size_t> >& group_to_spaces_map,
    map_alloc<group_desc, size_t>& out_group_to_unused_space_map,
    map_alloc<size_t, tcams_per_space_s>& out_available_tcams_per_space)
{
    for (const group_desc& competing_group : competing_groups) {
        if (!competing_group.is_wide() || group_to_spaces_map[competing_group].size() == 2) {
            continue;
        }
        size_t space_for_group = group_to_spaces_map[competing_group][0];
        size_t num_of_lines = get_number_of_lines_in_group(competing_group);
        size_t num_of_needed_tcams = get_number_of_tcams_needed_to_fit_lines(num_of_lines);
        size_t num_of_unused_lines = num_of_needed_tcams * BANK_SIZE - num_of_lines;

        out_group_to_unused_space_map.emplace(competing_group, num_of_unused_lines);
        out_available_tcams_per_space[space_for_group].wide_tcams -= num_of_needed_tcams;
    }
}

void
ctm_mgr_tcam::count_the_need_for_two_TCAM_spaces_wide_competition(
    vector_alloc<size_t>& spaces_for_subject_group,
    groups_container& competing_groups,
    map_alloc<group_desc, vector_alloc<size_t> >& group_to_spaces_map,
    map_alloc<group_desc, size_t>& out_group_to_unused_space_map,
    map_alloc<size_t, tcams_per_space_s>& out_available_tcams_per_space)
{
    for (const group_desc& competing_group : competing_groups) {
        if (!competing_group.is_wide() || group_to_spaces_map[competing_group].size() == 1) {
            continue;
        }

        vector_alloc<size_t> spaces_for_competing_group = group_to_spaces_map[competing_group];
        size_t num_of_lines = get_number_of_lines_in_group(competing_group);
        size_t num_of_needed_tcams = get_number_of_tcams_needed_to_fit_lines(num_of_lines);
        size_t num_of_unused_lines = num_of_needed_tcams * BANK_SIZE - num_of_lines;

        out_group_to_unused_space_map.emplace(competing_group, num_of_unused_lines);

        if (spaces_for_subject_group.size() == 1) {
            // Reorder spaces_for_competing_group so that subject group space is last.
            // so that we will take all the possible tcams from the other space first.
            vector_alloc<size_t>::iterator it
                = std::find(spaces_for_competing_group.begin(), spaces_for_competing_group.end(), spaces_for_subject_group[0]);
            spaces_for_competing_group.erase(it);
            spaces_for_competing_group.push_back(spaces_for_subject_group[0]);
        }

        for (size_t space_id : spaces_for_competing_group) {
            size_t& num_of_wide_tcams_on_space = out_available_tcams_per_space[space_id].wide_tcams;
            if (num_of_wide_tcams_on_space > num_of_needed_tcams) {
                num_of_wide_tcams_on_space -= num_of_needed_tcams;
                num_of_needed_tcams = 0;
            } else {
                num_of_needed_tcams -= num_of_wide_tcams_on_space;
                num_of_wide_tcams_on_space = 0;
            }
        }

        dassert_crit(num_of_needed_tcams == 0); // The group must fit in memory.
    }
}

void
ctm_mgr_tcam::count_the_need_for_one_TCAM_space_narrow_competition(
    const group_desc& subject_group,
    groups_container& competing_groups,
    map_alloc<group_desc, vector_alloc<size_t> >& group_to_spaces_map,
    map_alloc<group_desc, size_t>& out_group_to_unused_space_map,
    map_alloc<size_t, tcams_per_space_s>& out_available_tcams_per_space)
{
    for (const group_desc& competing_group : competing_groups) {
        if (competing_group.is_wide() || group_to_spaces_map[competing_group].size() == 2) {
            continue;
        }
        if (subject_group.is_wide() && is_subgroup(subject_group, competing_group)) {
            continue; // If calculating for wide, skip narrow subgroups. They will be handled later.
        }

        size_t space_for_group = group_to_spaces_map[competing_group][0];
        int num_of_lines = get_number_of_lines_in_group(competing_group);
        group_desc super_group = m_ctm_config_tcam->get_wide_group_from_narrow_group(competing_group);
        dassert_crit(super_group.slice_idx != IDX_INVAL);

        size_t unused_space_in_the_supergroup = out_group_to_unused_space_map.find(super_group)->second;
        num_of_lines = std::max(static_cast<int>(num_of_lines) - static_cast<int>(unused_space_in_the_supergroup), 0);
        size_t num_of_needed_tcams = get_number_of_tcams_needed_to_fit_lines(num_of_lines);

        if (out_available_tcams_per_space[space_for_group].narrow_only_tcams >= num_of_needed_tcams) {
            out_available_tcams_per_space[space_for_group].narrow_only_tcams -= num_of_needed_tcams;
            num_of_needed_tcams = 0;
        } else { // We don't have enough narrow only tcams
            num_of_needed_tcams -= out_available_tcams_per_space[space_for_group].narrow_only_tcams;
            out_available_tcams_per_space[space_for_group].narrow_only_tcams = 0;

            size_t num_of_wide_tcams_to_break = div_round_up(num_of_needed_tcams, 2);
            dassert_crit(num_of_wide_tcams_to_break <= out_available_tcams_per_space[space_for_group].wide_tcams);
            out_available_tcams_per_space[space_for_group].wide_tcams -= num_of_wide_tcams_to_break;
            out_available_tcams_per_space[space_for_group].narrow_only_tcams = num_of_needed_tcams % 2;
            num_of_needed_tcams = 0;
        }
    }
}

void
ctm_mgr_tcam::count_the_need_for_two_TCAM_spaces_narrow_competition(
    const group_desc& subject_group,
    vector_alloc<size_t>& spaces_for_subject_group,
    groups_container& competing_groups,
    map_alloc<group_desc, vector_alloc<size_t> >& group_to_spaces_map,
    map_alloc<group_desc, size_t>& out_group_to_unused_space_map,
    map_alloc<size_t, tcams_per_space_s>& out_available_tcams_per_space)
{
    // In the fourth pass we calculate what is needed for the big narrow groups.
    for (const group_desc& competing_group : competing_groups) {
        if (competing_group.is_wide() || group_to_spaces_map[competing_group].size() == 1) {
            continue;
        }
        if (subject_group.is_wide() && is_subgroup(subject_group, competing_group)) {
            continue; // If calculating for wide, skip narrow subgroups. They will be handled later.
        }

        vector_alloc<size_t> spaces_for_competing_group = group_to_spaces_map[competing_group];
        size_t num_of_lines = get_number_of_lines_in_group(competing_group);
        group_desc super_group = m_ctm_config_tcam->get_wide_group_from_narrow_group(competing_group);
        dassert_crit(super_group.slice_idx != IDX_INVAL);

        size_t unused_space_in_the_supergroup = out_group_to_unused_space_map.find(super_group)->second;
        num_of_lines = std::max(static_cast<int>(num_of_lines) - static_cast<int>(unused_space_in_the_supergroup), 0);
        size_t num_of_needed_tcams = get_number_of_tcams_needed_to_fit_lines(num_of_lines);

        if (spaces_for_subject_group.size() == 1) {
            // Reorder spaces_for_competing_group so that subject group space is last.
            // so that we will take all the possible tcams from the other space first.
            vector_alloc<size_t>::iterator it
                = std::find(spaces_for_competing_group.begin(), spaces_for_competing_group.end(), spaces_for_subject_group[0]);
            spaces_for_competing_group.erase(it);
            spaces_for_competing_group.push_back(spaces_for_subject_group[0]);
        }

        for (size_t space_id : spaces_for_competing_group) {
            if (out_available_tcams_per_space[space_id].narrow_only_tcams >= num_of_needed_tcams) {
                out_available_tcams_per_space[space_id].narrow_only_tcams -= num_of_needed_tcams;
                num_of_needed_tcams = 0;
            } else { // We don't have enough narrow only tcams
                num_of_needed_tcams -= out_available_tcams_per_space[space_id].narrow_only_tcams;
                out_available_tcams_per_space[space_id].narrow_only_tcams = 0;

                size_t num_of_wide_tcams_to_break = div_round_up(num_of_needed_tcams, 2);
                if (out_available_tcams_per_space[space_id].wide_tcams >= num_of_wide_tcams_to_break) {
                    out_available_tcams_per_space[space_id].wide_tcams -= num_of_wide_tcams_to_break;
                    num_of_needed_tcams = 0;
                    out_available_tcams_per_space[space_id].narrow_only_tcams = num_of_needed_tcams % 2;
                } else {
                    num_of_needed_tcams -= out_available_tcams_per_space[space_id].wide_tcams * 2;
                    out_available_tcams_per_space[space_id].wide_tcams = 0;
                }
            }
            if (num_of_needed_tcams == 0) {
                break;
            }
        }

        dassert_crit(num_of_needed_tcams == 0); // This is an already in memory group, so it must fit in the eligible spaces.
    }
}

void
ctm_mgr_tcam::get_available_space_after_compeeting_groups_needs(const group_desc& subject_group,
                                                                map_alloc<group_desc, size_t>& out_group_to_unused_space_map,
                                                                map_alloc<size_t, tcams_per_space_s>& out_available_tcams_per_space)
{
    groups_container competing_groups = m_ctm_config_tcam->get_competing_groups(subject_group);
    set_alloc<group_desc> indirectly_competing_groups = get_indirect_compeeting_groups(subject_group, competing_groups);
    competing_groups.insert(competing_groups.end(), indirectly_competing_groups.begin(), indirectly_competing_groups.end());
    // At this point competing_groups contains all the directly and indirectly competing groups.

    const size_t number_of_wide_tcams_per_ring = m_ctm_config_tcam->get_max_wide_scale_per_ring() / BANK_SIZE;
    const size_t number_of_available_tcams_per_ring = m_ctm_config_tcam->get_max_narrow_scale_per_ring() / BANK_SIZE;

    map_alloc<group_desc, vector_alloc<size_t> > group_to_spaces_map;
    vector_alloc<size_t> spaces_for_subject_group = m_ctm_config_tcam->get_spaces_for_group(subject_group);

    // Do some more initialization.
    for (const group_desc& competing_group : competing_groups) {
        vector_alloc<size_t> spaces_for_group = m_ctm_config_tcam->get_spaces_for_group(competing_group);
        group_to_spaces_map.emplace(competing_group, spaces_for_group);

        for (size_t space_id : spaces_for_group) {
            // For each space initialize the out_available_tcams_per_space if uninitialized.
            if (out_available_tcams_per_space.find(space_id) == out_available_tcams_per_space.end()) {
                tcams_per_space_s per_ring_space;
                per_ring_space.wide_tcams = number_of_wide_tcams_per_ring,
                per_ring_space.narrow_only_tcams = number_of_available_tcams_per_ring - number_of_wide_tcams_per_ring * 2;
                out_available_tcams_per_space.emplace(space_id, per_ring_space);
            }
        }
    }

    // The order here matters.
    count_the_need_for_one_TCAM_space_wide_competition(
        competing_groups, group_to_spaces_map, out_group_to_unused_space_map, out_available_tcams_per_space);
    count_the_need_for_one_TCAM_space_narrow_competition(
        subject_group, competing_groups, group_to_spaces_map, out_group_to_unused_space_map, out_available_tcams_per_space);
    count_the_need_for_two_TCAM_spaces_wide_competition(spaces_for_subject_group,
                                                        competing_groups,
                                                        group_to_spaces_map,
                                                        out_group_to_unused_space_map,
                                                        out_available_tcams_per_space);
    count_the_need_for_two_TCAM_spaces_narrow_competition(subject_group,
                                                          spaces_for_subject_group,
                                                          competing_groups,
                                                          group_to_spaces_map,
                                                          out_group_to_unused_space_map,
                                                          out_available_tcams_per_space);
}

size_t
ctm_mgr_tcam::calculate_max_available_space_wide(const group_desc& subject_group,
                                                 map_alloc<size_t, tcams_per_space_s>& available_tcams_per_space)
{
    // We don't support any lsb subgroups currently. No FW1, no TX1.
    const group_desc& msb_subgroup = m_ctm_config_tcam->get_msb_narrow_group_from_wide_group(subject_group);
    dassert_crit(msb_subgroup.slice_idx != IDX_INVAL);

    size_t available_space = 0;

    vector_alloc<size_t> spaces_for_subject_group = m_ctm_config_tcam->get_spaces_for_group(subject_group);
    size_t num_of_lines = get_number_of_lines_in_group(subject_group);

    // Now calculate how many narrow lines are overflowing. And use the free narrow only tcams to reduce this number.
    size_t narrow_overflow = get_number_of_lines_in_group(msb_subgroup);

    for (size_t space_id : spaces_for_subject_group) {
        size_t narrow_overflow_in_tcams = get_number_of_tcams_needed_to_fit_lines(narrow_overflow);
        const size_t num_of_lines_in_narrow_only_tcams = available_tcams_per_space[space_id].narrow_only_tcams * BANK_SIZE;
        narrow_overflow = std::max(static_cast<int>(narrow_overflow) - static_cast<int>(num_of_lines_in_narrow_only_tcams), 0);
        available_tcams_per_space[space_id].narrow_only_tcams = std::max(
            static_cast<int>(available_tcams_per_space[space_id].narrow_only_tcams) - static_cast<int>(narrow_overflow_in_tcams),
            0); // Not needed, just for consistency.
        if (narrow_overflow == 0) {
            break;
        }
    }

    size_t total_available_wide_tcams = 0;
    for (size_t space_id : spaces_for_subject_group) {
        total_available_wide_tcams += available_tcams_per_space[space_id].wide_tcams;
    }

    // Break wide tcams until the subgroup overflow is less than one TCAM.
    size_t num_of_wide_tcams_to_break = div_round_up(narrow_overflow / BANK_SIZE, 2);
    narrow_overflow = std::max(static_cast<int>(narrow_overflow) - static_cast<int>(num_of_wide_tcams_to_break * 2 * BANK_SIZE), 0);
    dassert_crit(total_available_wide_tcams > num_of_wide_tcams_to_break);
    total_available_wide_tcams -= num_of_wide_tcams_to_break;

    size_t max_available_scale = total_available_wide_tcams * BANK_SIZE;
    dassert_crit(max_available_scale > narrow_overflow, "We must have utleast one line for the default entries of the wide group.");
    available_space = max_available_scale - narrow_overflow;
    dassert_crit(available_space >= num_of_lines, "Current lines are allready in memory, and thus must fit.");
    available_space -= num_of_lines;

    return available_space;
}

size_t
ctm_mgr_tcam::calculate_max_available_space_narrow(const group_desc& subject_group,
                                                   const map_alloc<group_desc, size_t>& group_to_unused_space_map,
                                                   const map_alloc<size_t, tcams_per_space_s>& available_tcams_per_space)
{
    group_desc super_group = m_ctm_config_tcam->get_wide_group_from_narrow_group(subject_group);
    dassert_crit(super_group.slice_idx != IDX_INVAL);

    vector_alloc<size_t> spaces_for_subject_group = m_ctm_config_tcam->get_spaces_for_group(subject_group);

    size_t available_space = 0;

    size_t num_of_lines = get_number_of_lines_in_group(subject_group);

    size_t total_available_wide_tcams = 0;
    size_t total_available_narrow_tcams = 0;
    for (size_t space_id : spaces_for_subject_group) {
        map_alloc<size_t, tcams_per_space_s>::const_iterator available_tcams_it = available_tcams_per_space.find(space_id);
        dassert_crit(available_tcams_it != available_tcams_per_space.end());
        total_available_wide_tcams += available_tcams_it->second.wide_tcams;
        total_available_narrow_tcams += available_tcams_it->second.narrow_only_tcams;
    }

    size_t total_available_tcams = total_available_narrow_tcams + total_available_wide_tcams * 2;

    size_t unused_space_in_super_group = group_to_unused_space_map.find(super_group)->second;
    size_t max_available_scale = total_available_tcams * BANK_SIZE + unused_space_in_super_group;
    dassert_crit(max_available_scale >= num_of_lines, "Current lines are allready in memory, so there must be space for them.");
    available_space = max_available_scale - num_of_lines;

    return available_space;
}

size_t
ctm_mgr_tcam::get_max_available_space(const table_desc& table)
{
    start_ctm_mgr_api_call(table);
    // Worst case scenario that is currently supported. No Fw1, no TX1:
    // Ring0: FWwide, FW0, TXwide, TX0.
    // Ring1: FWwide, FW0

    const group_desc& group = get_group_for_table(table);

    map_alloc<group_desc, size_t> group_to_unused_space_map;
    map_alloc<size_t, tcams_per_space_s> available_tcams_per_space;

    int available_space = 0;

    get_available_space_after_compeeting_groups_needs(group, group_to_unused_space_map, available_tcams_per_space);

    if (group.is_wide()) {
        available_space = calculate_max_available_space_wide(group, available_tcams_per_space);
    } else {
        available_space = calculate_max_available_space_narrow(group, group_to_unused_space_map, available_tcams_per_space);
    }

    return available_space;
}

la_status
ctm_mgr_tcam::write(table_desc table, size_t line_idx, const bit_vector& key, const bit_vector& mask, const bit_vector& value)
{
    start_ctm_mgr_api_call(table);

    log_debug(RA,
              "ctm_mgr_tcam::%s: %s, line_idx: %zu key: %s, mask: %s, val: %s",
              __FUNCTION__,
              to_string(table).c_str(),
              line_idx,
              key.to_string().c_str(),
              mask.to_string().c_str(),
              value.to_string().c_str());

    if (line_idx >= get_table_size(table)) {
        log_err(RA,
                "%s: line index is out of range. %s, table size: %zu, line_idx: %zu",
                __FUNCTION__,
                to_string(table).c_str(),
                get_table_size(table),
                line_idx);
        return LA_STATUS_EOUTOFRANGE;
    }
    la_status status = LA_STATUS_SUCCESS;
    lines_map& entries = m_entries[table];

    bool contained = contains(entries, line_idx);
    if (!contained) {
        status = allocate_lines(table, line_idx, 1);
        if (status != LA_STATUS_SUCCESS) {
            log_err(RA, "%s: could not allocate line. %s, line_idx: %zu", __FUNCTION__, to_string(table).c_str(), line_idx);
            return LA_STATUS_ERESOURCE;
        }
    }

    line_desc line = entries[line_idx];

    memory_tcam& mem = get_memory_tcam(line.tcam_id, table);
    status = mem.write_unsafe(line.line, key, mask, value, true);

    return status;
}

la_status
ctm_mgr_tcam::write_bulk(table_desc table, size_t first_line_idx, size_t bulk_size, const vector_alloc<tcam_entry_desc>& entries)
{
    start_ctm_mgr_api_call(table);

    dassert_crit(entries.size() == bulk_size);

    for (size_t i = 0; i < bulk_size; i++) {
        log_debug(RA,
                  "ctm_mgr_tcam::%s: %s, first_line_idx: %zu, bulk_size: %zu, line %zu key: %s, mask: %s, val: %s",
                  __FUNCTION__,
                  to_string(table).c_str(),
                  first_line_idx,
                  bulk_size,
                  i,
                  entries[i].key.to_string().c_str(),
                  entries[i].mask.to_string().c_str(),
                  entries[i].value.to_string().c_str());
    }

    if (first_line_idx + bulk_size - 1 >= get_table_size(table)) {
        log_err(RA,
                "%s: last line index is out of range. %s, table size: %zu, last_line_idx: %zu",
                __FUNCTION__,
                to_string(table).c_str(),
                get_table_size(table),
                first_line_idx + bulk_size - 1);
        return LA_STATUS_EOUTOFRANGE;
    }
    la_status status = LA_STATUS_SUCCESS;

    status = allocate_lines(table, first_line_idx, bulk_size);
    if (status != LA_STATUS_SUCCESS) {
        log_err(RA,
                "%s: could not allocate lines. %s, first_line_idx: %zu, bulk_size: %zu",
                __FUNCTION__,
                to_string(table).c_str(),
                first_line_idx,
                bulk_size);
        return status;
    }

    lines_map& table_entries = m_entries[table];
    for (size_t i = 0; i < bulk_size; i++) {
        line_desc line = table_entries[first_line_idx + i];

        memory_tcam& mem = get_memory_tcam(line.tcam_id, table);
        status = mem.write_unsafe(line.line, entries[i].key, entries[i].mask, entries[i].value, true);
        return_on_error(status);
    }

    return status;
}

la_status
ctm_mgr_tcam::move(table_desc table, size_t src_line_idx, size_t dest_line_idx)
{
    start_ctm_mgr_api_call(table);

    log_debug(RA,
              "ctm_mgr_tcam::%s: %s, src_line_idx: %zu dest_line_idx: %zu",
              __FUNCTION__,
              to_string(table).c_str(),
              src_line_idx,
              dest_line_idx);
    size_t table_size = get_table_size(table);
    bool contained_src = false;
    bool contained_dest = false;

    if (src_line_idx >= table_size || dest_line_idx >= table_size) {
        log_err(RA,
                "%s: line index is out of range. %s, table size: %zu, src_line_idx: %zu, dest_line_idx: %zu",
                __FUNCTION__,
                to_string(table).c_str(),
                table_size,
                src_line_idx,
                dest_line_idx);
        return LA_STATUS_EOUTOFRANGE;
    }

    la_status status = LA_STATUS_SUCCESS;
    lines_map& entries = m_entries[table];

    contained_src = contains(entries, src_line_idx);
    contained_dest = contains(entries, dest_line_idx);

    if (contained_src) {
        if (!contained_dest) {
            status = allocate_lines(table, dest_line_idx, 1);
            return_on_error(status);
        }

        status = move_one_line(table, src_line_idx, dest_line_idx);
        return_on_error(status);

    } else {
        // source line does not exist.
        // if destination line exists - invalidate it.
        // otherwise, just do nothing.
        if (contained_dest) {
            release_line(table, dest_line_idx);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
ctm_mgr_tcam::move_one_line(table_desc table, size_t src_line_idx, size_t dest_line_idx)
{
    // read from src
    bit_vector key;
    bit_vector mask;
    bit_vector value;
    bool valid = false;
    lines_map& entries = m_entries[table];
    line_desc& src_line = entries[src_line_idx];
    line_desc& dest_line = entries[dest_line_idx];

    memory_tcam& mem_src = get_memory_tcam(src_line.tcam_id, table);
    memory_tcam& mem_dest = get_memory_tcam(dest_line.tcam_id, table);

    la_status status = mem_src.read(src_line.line, key, mask, value, valid);
    return_on_error(status);
    if (valid) {
        // write to dest
        status = mem_dest.write_unsafe(dest_line.line, key, mask, value, true);
        return_on_error(status);

        // invalidate src
        status = release_line(table, src_line_idx);
        return_on_error(status);

    } else {
        // if src invalid, invalidate the dest.
        status = mem_dest.invalidate(dest_line.line);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
ctm_mgr_tcam::update(table_desc table, size_t line_idx, const bit_vector& value)
{
    start_ctm_mgr_api_call(table);

    log_debug(RA,
              "ctm_mgr_tcam::%s: %s, line_idx: %zu, value: %s",
              __FUNCTION__,
              to_string(table).c_str(),
              line_idx,
              value.to_string().c_str());

    if (line_idx >= get_table_size(table)) {
        log_err(RA,
                "%s: line index is out of range. %s, table size: %zu, line_idx: %zu",
                __FUNCTION__,
                to_string(table).c_str(),
                get_table_size(table),
                line_idx);
        return LA_STATUS_EOUTOFRANGE;
    }

    lines_map& entries = m_entries[table];

    bool contained = contains(entries, line_idx);
    if (!contained) {
        log_err(RA, "%s: table doesn't contain line index. %s, line_idx: %zu", __FUNCTION__, to_string(table).c_str(), line_idx);
        return LA_STATUS_EINVAL;
    }

    line_desc& line = entries[line_idx];

    memory_tcam& mem = get_memory_tcam(line.tcam_id, table);
    la_status status = mem.update_unsafe(line.line, value);

    return status;
}

la_status
ctm_mgr_tcam::invalidate(table_desc table, size_t line_idx)
{
    start_ctm_mgr_api_call(table);

    log_debug(RA, "ctm_mgr_tcam::%s: %s, line_idx: %zu", __FUNCTION__, to_string(table).c_str(), line_idx);

    if (line_idx >= get_table_size(table)) {
        log_err(RA,
                "%s: line index is out of range. %s, table size: %zu, line_idx: %zu",
                __FUNCTION__,
                to_string(table).c_str(),
                get_table_size(table),
                line_idx);
        return LA_STATUS_EOUTOFRANGE;
    }
    lines_map& entries = m_entries[table];

    bool contained = contains(entries, line_idx);
    if (!contained) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = release_line(table, line_idx);
    return status;
}

la_status
ctm_mgr_tcam::read(table_desc table,
                   size_t line_idx,
                   bit_vector& out_key,
                   bit_vector& out_mask,
                   bit_vector& out_value,
                   bool& out_valid)
{
    start_ctm_mgr_api_call(table);

    lines_map entries = m_entries[table];

    bool contained = contains(entries, line_idx);
    if (line_idx >= get_table_size(table) || !contained) {
        out_valid = false;
        return LA_STATUS_SUCCESS;
    }

    const line_desc& line = entries[line_idx];

    memory_tcam& mem = get_memory_tcam(line.tcam_id, table);
    la_status status = mem.read(line.line, out_key, out_mask, out_value, out_valid);

    return status;
}

la_status
ctm_mgr_tcam::set_default_value(table_desc table, const bit_vector& key, const bit_vector& mask, const bit_vector& value)
{
    start_ctm_mgr_api_call(table);

    // set the default value to the last eligibale tcam
    la_status status = LA_STATUS_SUCCESS;

    size_t line_idx = get_table_size(table);
    lines_map& entries = m_entries[table];

    bool contained = contains(entries, line_idx);
    if (contained) {
        dassert_crit(false);
    }
    status = allocate_lines(table, line_idx, 1);
    if (status != LA_STATUS_SUCCESS) {
        log_err(RA, "%s: could not allocate line. %s, line_idx: %zu", __FUNCTION__, to_string(table).c_str(), line_idx);
        return LA_STATUS_ERESOURCE;
    }

    line_desc line = entries[line_idx];

    memory_tcam& mem = get_memory_tcam(line.tcam_id, table);
    status = mem.write_unsafe(line.line, key, mask, value, true);

    return status;
}

la_status
ctm_mgr_tcam::make_space_for_group(group_desc group, size_t number_of_lines)
{
    la_status line_status = LA_STATUS_ERESOURCE; // set to SUCCESS once we find a free line of the appropriate width for the group.

    if (group == m_current_group) {
        m_tcam_already_freed_from_group
            .clear(); // clear this container at the begining of the algorithm unless its in recursive reallocation.
    }

    if (!group.is_wide()) {
        size_t free_lines = get_free_space_in_group(group);
        // if we are here, there shouldn't be enough free lines in group
        dassert_crit(number_of_lines > free_lines);

        size_t number_of_tcams = get_number_of_tcams_needed_to_fit_lines(number_of_lines - free_lines);
        line_status = allocate_new_tcams_for_group(group, number_of_tcams, true);
        log_debug(
            RA,
            "ctm_mgr_tcam::%s: narrow group: %s, allocation of: %zu lines, free lines in group: %zu. TCAM allocation status: %s",
            __FUNCTION__,
            to_string(group).c_str(),
            number_of_lines,
            free_lines,
            line_status.message().c_str());
    } else {
        size_t free_space_lsb;
        size_t free_space_msb;

        relocate_narrow_groups_for_wide_group(group, number_of_lines, free_space_lsb, free_space_msb);

        log_debug(RA,
                  "ctm_mgr_tcam::%s: group: %s, after group relocation: free lines [lsb: %zu, msb: %zu], number of lines: %zu",
                  __FUNCTION__,
                  to_string(group).c_str(),
                  free_space_lsb,
                  free_space_msb,
                  number_of_lines);

        if (free_space_lsb < number_of_lines && free_space_msb < number_of_lines) {
            size_t free_space = std::min(free_space_lsb, free_space_msb);

            // if both sides didn't relocate enough lines, then we try to get more TCAMs for the wide table.
            size_t number_of_tcams = get_number_of_tcams_needed_to_fit_lines(number_of_lines - free_space);
            la_status allocated_wide_tcam_status = allocate_new_tcams_for_group(group, number_of_tcams, false);

            if (allocated_wide_tcam_status == LA_STATUS_SUCCESS) {
                // Note that even though we allocated wide tcams,
                // it does not mean that we have enough wide free lines,
                // because one half of the new tcam could have already been allocated, and could be full.
                // So we do group relocation if needed.

                relocate_narrow_groups_for_wide_group(group, number_of_lines, free_space_lsb, free_space_msb);

                log_debug(
                    RA,
                    "ctm_mgr_tcam::%s: group: %s, allocated new wide tcam. free lines [lsb: %zu, msb: %zu], number of lines: %zu",
                    __FUNCTION__,
                    to_string(group).c_str(),
                    free_space_lsb,
                    free_space_msb,
                    number_of_lines);
            }

            if (free_space_lsb < number_of_lines || free_space_msb < number_of_lines) {
                // Here we need to check if we have enough narrow lines so that allocating narrow tcams can help.
                const size_t number_of_occupied_lines_in_wide_group = get_number_of_lines_in_group(group);
                const tcams_container& tcams_lsb = m_ctm_config_tcam->get_eligible_lsb_tcams_for_wide_group(group);
                const size_t number_of_lines_in_eligible_tcams_for_wide_group = tcams_lsb.size() * BANK_SIZE;

                if (number_of_occupied_lines_in_wide_group + number_of_lines > number_of_lines_in_eligible_tcams_for_wide_group) {
                    dassert_crit(number_of_occupied_lines_in_wide_group <= number_of_lines_in_eligible_tcams_for_wide_group);
                    log_debug(RA,
                              "ctm_mgr_tcam::%s: group: %s, \"number_of_occupied_lines_in_wide_group[%zu] + number_of_lines[%zu] > "
                              "number_of_lines_in_eligible_tcams_for_wide_group[%zu]\" is true. So we don't have enough narrow "
                              "lines in wide space for narrow tcam allocation to "
                              "help. Free lines [lsb: %zu, msb: %zu]. ",
                              __FUNCTION__,
                              to_string(group).c_str(),
                              number_of_occupied_lines_in_wide_group,
                              number_of_lines,
                              number_of_lines_in_eligible_tcams_for_wide_group,
                              free_space_lsb,
                              free_space_msb);
                    return line_status;
                }
            }
        }

        if (free_space_lsb < number_of_lines || free_space_msb < number_of_lines) {
            // Comming here:
            // We know that we still don't have enough wide free lines.
            // We know that the wide group is not occupying all of it's eligible lines.
            // We know that there are already eligible wide tcams for the wide group.
            // And there is no use in trying wide tcam allocation any more.
            // So what we will do is try to get a narrow tcam for one or both sides, depending on where we lack space.
            // If after this we have enough free space on both sides, we will align narrow free lines, so that we have enough free
            // wide lines.
            line_status = allocate_narrow_tcams_for_wide_group(group, number_of_lines, free_space_lsb, free_space_msb);
            return_on_error(line_status,
                            RA,
                            ERROR,
                            "ctm_mgr_tcam::%s: group: %s, failed in tcam allocation for subgroups. free lines [lsb: %zu, msb: "
                            "%zu], number of lines: %zu",
                            __FUNCTION__,
                            to_string(group).c_str(),
                            free_space_lsb,
                            free_space_msb,
                            number_of_lines);
            relocate_narrow_groups_for_wide_group(group, number_of_lines, free_space_lsb, free_space_msb);
        }

        if (free_space_lsb >= number_of_lines && free_space_msb >= number_of_lines) {
            line_status = make_free_wide_lines(group, number_of_lines);
            dassert_crit(line_status == LA_STATUS_SUCCESS);
        }

        return_on_error(line_status);
    }

    return line_status;
}

void
ctm_mgr_tcam::relocate_narrow_groups_for_wide_group(const group_desc& wide_group,
                                                    size_t number_of_lines,
                                                    size_t& out_free_space_lsb,
                                                    size_t& out_free_space_msb)
{
    const tcams_container& tcams_lsb = m_ctm_config_tcam->get_eligible_lsb_tcams_for_wide_group(wide_group);
    const tcams_container& tcams_msb = m_ctm_config_tcam->get_eligible_tcams_for_group(wide_group);

    out_free_space_lsb = get_free_space_in_tcams(tcams_lsb);
    out_free_space_msb = get_free_space_in_tcams(tcams_msb);

    if (out_free_space_lsb < number_of_lines && tcams_lsb.size() > 0) {
        out_free_space_lsb += relocate_groups(tcams_lsb, number_of_lines - out_free_space_lsb);
    }

    if (out_free_space_msb < number_of_lines && tcams_msb.size() > 0) {
        out_free_space_msb += relocate_groups(tcams_msb, number_of_lines - out_free_space_msb);
    }
}

la_status
ctm_mgr_tcam::allocate_narrow_tcams_for_wide_group(const group_desc& wide_group,
                                                   size_t number_of_lines,
                                                   size_t free_space_lsb,
                                                   size_t free_space_msb)
{
    la_status status;

    if (free_space_lsb < number_of_lines) {
        group_desc lsb_group = m_ctm_config_tcam->get_lsb_narrow_group_from_wide_group(wide_group);

        // we will use the status from here even for the lsb and msb side.
        size_t number_of_tcams = get_number_of_tcams_needed_to_fit_lines(number_of_lines - free_space_lsb);
        status = allocate_new_tcams_for_group(lsb_group, number_of_tcams, true);
        if (status != LA_STATUS_SUCCESS) {
            log_debug(RA,
                      "ctm_mgr_tcam::%s: unable to make more space on the lsb side of the group, by narrow tcam "
                      "relocation/allocation: %s",
                      __FUNCTION__,
                      to_string(wide_group).c_str());
            return status;
        }
    }

    if (free_space_msb < number_of_lines) {
        group_desc msb_group = m_ctm_config_tcam->get_msb_narrow_group_from_wide_group(wide_group);

        size_t number_of_tcams = get_number_of_tcams_needed_to_fit_lines(number_of_lines - free_space_msb);
        status = allocate_new_tcams_for_group(msb_group, number_of_tcams, true);
        if (status != LA_STATUS_SUCCESS) {
            log_debug(RA,
                      "ctm_mgr_tcam::%s: unable to make more space on the msb side of the group, by narrow tcam "
                      "relocation/allocation: %s",
                      __FUNCTION__,
                      to_string(wide_group).c_str());
            return status;
        }
    }

    return status;
}

const ctm_config_sptr
ctm_mgr_tcam::get_ctm_config() const
{
    return m_ctm_config_tcam; // TODO: What do we want to return here: raw ptr, shared ptr, or a reference.
}

la_status
ctm_mgr_tcam::allocate_lines(table_desc table, line_position first_line_idx, size_t number_of_lines)
{
    la_status status = LA_STATUS_ERESOURCE;

    lines_map& entries = m_entries[table];

    for (line_position line_idx = first_line_idx; line_idx < first_line_idx + number_of_lines; line_idx++) {
        bool contained = contains(entries, line_idx);
        if (contained) {
            log_err(RA,
                    "%s: line_idx %zu is already used. %s, first_line_idx: %zu, number_of_lines: %zu",
                    __FUNCTION__,
                    line_idx,
                    to_string(table).c_str(),
                    first_line_idx,
                    number_of_lines);
            return LA_STATUS_EINVAL;
        }
    }

    const group_desc& group = get_group_for_table(table);
    if (!group.is_wide()) {
        // if narrow group needs more space, try to keep FREE_THRESHOLD free lines in group (in case of need for line swapping)
        size_t space = get_free_space_in_group(group);
        if (space < number_of_lines + FREE_THRESHOLD) {
            status = make_space_for_group(group, number_of_lines + FREE_THRESHOLD);
        }
    }
    if (group.is_wide() || status != LA_STATUS_SUCCESS) {
        size_t space = get_free_space_in_group(group);
        if (space < number_of_lines) {
            status = make_space_for_group(group, number_of_lines);
            return_on_error(status);
        }
    }

    vector_alloc<line_desc> new_lines;
    // try to allocate a place between prev and next line
    status = find_and_allocate_lines_for_write(table, first_line_idx, number_of_lines, new_lines);
    return_on_error(status);

    for (size_t i = 0; i < number_of_lines; i++) {
        entries.insert({first_line_idx + i, new_lines[i]});
    }

    return LA_STATUS_SUCCESS;
}

la_status
ctm_mgr_tcam::find_and_allocate_lines_in_range_left(table_desc table,
                                                    lines_map& entries,
                                                    line_iterator& first_line,
                                                    line_iterator& last_line,
                                                    size_t& lines_to_allocate,
                                                    const tcams_container& tcams_to_avoid,
                                                    vector_alloc<line_desc>& new_lines)
{
    line_desc first_line_desc;
    line_desc last_line_desc;
    const tcams_container& eligibale_tcams = get_eligible_tcams_for_table(table);

    if (first_line == last_line) {
        first_line_desc.tcam_id = eligibale_tcams.front();
        first_line_desc.line = 0;
    } else {
        first_line_desc = first_line->second;
    }

    if (last_line == entries.end()) {
        last_line_desc.tcam_id = eligibale_tcams.back();
        last_line_desc.line = BANK_SIZE;
    } else {
        last_line_desc = last_line->second;
    }

    la_status status = LA_STATUS_SUCCESS;

    while (status == LA_STATUS_SUCCESS && lines_to_allocate > 0) {
        line_desc new_line;
        status = allocate_line_in_range(table, first_line_desc, last_line_desc, tcams_to_avoid, new_line);
        if (status == LA_STATUS_SUCCESS) {
            // new_lines.push_back(new_line);
            insert_to_sorted_line_vector(new_lines, new_line);
            first_line_desc = new_line;
            lines_to_allocate--;
        }
    }

    if (lines_to_allocate == 0) {
        return LA_STATUS_SUCCESS;
    }

    // if arrived to end at both sides return error
    if (last_line == entries.begin()) {
        return LA_STATUS_ERESOURCE;
    }
    last_line = first_line;
    if (first_line != entries.begin()) {
        first_line--;
    }
    return LA_STATUS_EOUTOFRANGE;
}

la_status
ctm_mgr_tcam::find_and_allocate_lines_in_range_right(table_desc table,
                                                     lines_map& entries,
                                                     line_iterator& first_line,
                                                     line_iterator& last_line,
                                                     size_t& lines_to_allocate,
                                                     const tcams_container& tcams_to_avoid,
                                                     vector_alloc<line_desc>& new_lines)
{
    line_desc first_line_desc;
    line_desc last_line_desc;
    if (first_line == entries.end()) {
        return LA_STATUS_ERESOURCE;
    }
    first_line_desc = first_line->second;
    if (last_line == entries.end()) {
        const tcams_container& eligibale_tcams = get_eligible_tcams_for_table(table);
        last_line_desc.tcam_id = eligibale_tcams.back();
        last_line_desc.line = BANK_SIZE;
    } else {
        last_line_desc = last_line->second;
    }

    la_status status = LA_STATUS_SUCCESS;

    while (status == LA_STATUS_SUCCESS && lines_to_allocate > 0) {
        line_desc new_line;
        status = allocate_line_in_range(table, first_line_desc, last_line_desc, tcams_to_avoid, new_line);
        if (status == LA_STATUS_SUCCESS) {
            // new_lines.push_back(new_line);
            insert_to_sorted_line_vector(new_lines, new_line);
            first_line_desc = new_line;
            lines_to_allocate--;
        }
    }

    if (lines_to_allocate == 0) {
        return LA_STATUS_SUCCESS;
    }

    // if arrived to end at both sides return error
    if (last_line == entries.end()) {
        return LA_STATUS_ERESOURCE;
    }
    first_line = last_line;
    ++last_line;

    return LA_STATUS_EOUTOFRANGE;
}

la_status
ctm_mgr_tcam::find_and_allocate_lines_for_write(table_desc table,
                                                line_position first_line_idx,
                                                size_t number_of_lines,
                                                vector_alloc<line_desc>& new_lines_out)
{
    const tcams_container empty_tcam_container;

    la_status status = find_and_allocate_lines(table, first_line_idx, number_of_lines, true, empty_tcam_container, new_lines_out);

    return status;
}

la_status
ctm_mgr_tcam::find_and_allocate_lines_for_move(table_desc table,
                                               line_position first_line_idx,
                                               size_t number_of_lines,
                                               const tcams_container& tcams_to_avoid,
                                               vector_alloc<line_desc>& new_lines_out)
{
    la_status status = find_and_allocate_lines(table, first_line_idx, number_of_lines, false, tcams_to_avoid, new_lines_out);

    return status;
}

la_status
ctm_mgr_tcam::find_and_allocate_lines(table_desc table,
                                      line_position first_line_idx,
                                      size_t number_of_lines,
                                      bool allocate_for_write,
                                      const tcams_container& tcams_to_avoid,
                                      vector_alloc<line_desc>& new_lines_out)
{
    lines_map& entries = m_entries[table];
    line_iterator left_push_stop, right_push_destination;

    line_iterator left_last = entries.lower_bound(first_line_idx);
    line_iterator left_first = left_last;
    if (left_first != entries.begin()) {
        --left_first;
    }

    left_push_stop = left_last;

    line_iterator right_first = left_last;
    line_iterator right_last = right_first;
    if (right_last != entries.end()) {
        ++right_last;
    }

    size_t lines_to_allocate = number_of_lines;
    size_t lines_allocated_left = 0;

    la_status status_left = LA_STATUS_EOUTOFRANGE;
    la_status status_right = LA_STATUS_EOUTOFRANGE;
    while (lines_to_allocate > 0 && (status_left != LA_STATUS_ERESOURCE || status_right != LA_STATUS_ERESOURCE)) {
        size_t lines_to_allocate_before = lines_to_allocate;
        status_left = find_and_allocate_lines_in_range_left(
            table, entries, left_first, left_last, lines_to_allocate, tcams_to_avoid, new_lines_out);
        lines_allocated_left += lines_to_allocate_before - lines_to_allocate;
        if (lines_to_allocate == 0) {
            break;
        }
        status_right = find_and_allocate_lines_in_range_right(
            table, entries, right_first, right_last, lines_to_allocate, tcams_to_avoid, new_lines_out);
    }

    if (allocate_for_write) {
        // When pushing left:
        // - If the first_line_idx is an allocated line the lower_bound will return it, and it should also be pushed.
        // - If it is not allocated, the lower_bound will return the next allcated line which shouldn't be moved.
        bool contained = contains(entries, first_line_idx);
        if (contained) {
            ++left_push_stop; // this is the stop line.
        }
    } else {
        // If allocation is for move (in order to clear TCAM)- we want the new allocated lines to start at first_line_idx
        // Need to push left the amount of lines allocated left of first_line_idx
        std::advance(left_push_stop, lines_allocated_left);
    }

    // First line to push right is the last line to push left (push left stops before last line)
    right_push_destination = left_push_stop;

    la_status status;
    if (lines_to_allocate == 0) {
        push_lines_left(table, left_push_stop, left_last, new_lines_out);
        push_lines_right(table, right_push_destination, right_first, new_lines_out);

        status = LA_STATUS_SUCCESS;
    } else {
        // release allocated lines
        for (line_desc& line_to_release : new_lines_out) {
            if (line_to_release.line != ctm::IDX_INVAL) {
                m_line_mgr[line_to_release.tcam_id].release_line(line_to_release.line);
            }
        }

        status = LA_STATUS_ERESOURCE;
        log_err(RA,
                "%s: could not find place to allocate lines. %s, first_line_idx: %zu, number_of_lines: %zu",
                __FUNCTION__,
                to_string(table).c_str(),
                first_line_idx,
                number_of_lines);
        dassert_crit(false);
    }

    return status;
}

la_status
ctm_mgr_tcam::push_lines_left(const table_desc& table,
                              line_iterator stop_line,
                              line_iterator next_to_move,
                              vector_alloc<line_desc>& out_in_free_lines)
{
    size_t free_lines_index = 0;

    la_status status = LA_STATUS_SUCCESS;

    lines_map& entries = m_entries[table];
    for (; next_to_move != stop_line; ++next_to_move) {
        dassert_crit(next_to_move != entries.end());

        line_desc next_free_line_desc = out_in_free_lines[free_lines_index];
        // if next_free_line is left of next_to_move, push next_to_move to next_free_line
        if (next_free_line_desc < next_to_move->second) {
            // move tcam line
            status = move_one_line(table, next_to_move->second, next_free_line_desc);
            // if the status is not success, it means we have HW failure, not clear what can we do
            dassert_crit(status == LA_STATUS_SUCCESS);

            insert_to_sorted_line_vector(out_in_free_lines, next_to_move->second);
            // update descriptor of moved line in m_entries
            next_to_move->second = next_free_line_desc;

            free_lines_index++;
        }
    }

    // the lines we moved to out_in_free_lines are no longer free, so remove them from out_in_free_lines
    out_in_free_lines.erase(out_in_free_lines.begin(), out_in_free_lines.begin() + free_lines_index);

    return status;
}

la_status
ctm_mgr_tcam::push_lines_right(const table_desc& table,
                               line_iterator stop_line,
                               line_iterator next_to_move,
                               vector_alloc<line_desc>& out_in_free_lines)
{
    size_t free_lines_index = out_in_free_lines.size() - 1;

    la_status status = LA_STATUS_SUCCESS;

    lines_map& entries = m_entries[table];

    // If the stop line is entries.end, it means we dont need to push any lines
    if (stop_line == entries.end() || next_to_move->first < stop_line->first) {
        return status;
    }

    for (;; next_to_move--) {
        dassert_crit(next_to_move != entries.end());

        line_desc next_free_line_desc = out_in_free_lines[free_lines_index];
        // if next_free_line is left of next_to_move, push next_to_move to next_free_line
        if (next_free_line_desc > next_to_move->second) {
            // move tcam line
            status = move_one_line(table, next_to_move->second, next_free_line_desc);
            // if the status is not success, it means we have HW failure, not clear what can we do
            dassert_crit(status == LA_STATUS_SUCCESS);

            insert_to_sorted_line_vector(out_in_free_lines, next_to_move->second);
            // update descriptor of moved line in m_entries
            next_to_move->second = next_free_line_desc;
        }

        if (next_to_move == stop_line) {
            break;
        }
    }

    // the lines we moved to out_in_free_lines are no longer free, so remove them from out_in_free_lines
    out_in_free_lines.erase(out_in_free_lines.begin() + free_lines_index + 1, out_in_free_lines.end());

    return status;
}

la_status
ctm_mgr_tcam::move_one_line(const table_desc& table, line_desc& src_line, line_desc& dest_line)
{
    bit_vector key;
    bit_vector mask;
    bit_vector value;
    bool valid = false;
    memory_tcam& mem_src = get_memory_tcam(src_line.tcam_id, table);
    memory_tcam& mem_dest = get_memory_tcam(dest_line.tcam_id, table);

    // read from src
    la_status status = mem_src.read(src_line.line, key, mask, value, valid);
    return_on_error(status);
    dassert_crit(valid);
    // write to dest
    status = mem_dest.write_unsafe(dest_line.line, key, mask, value, true);
    return_on_error(status);

    // To prevent illegal intermediate state we must invalidate the TCAM line first.
    status = mem_src.invalidate(src_line.line);
    return status;
}

// releases absolute tcam line mapping.
la_status
ctm_mgr_tcam::release_line(table_desc table, size_t line_idx)
{
    lines_map& entries = m_entries[table];

    bool contained = contains(entries, line_idx);
    dassert_crit(contained == true);

    line_desc& line = entries[line_idx];
    dassert_crit(line.line != ctm::IDX_INVAL);

    memory_tcam& mem = get_memory_tcam(line.tcam_id, table);
    la_status status = mem.invalidate(line.line);
    return_on_error(status);

    m_line_mgr[line.tcam_id].release_line(line.line);
    if (is_table_wide(table)) {
        // Line contains the msb side of the TCAM pair, we also need to release the lsb side.
        tcam_desc lsb_tcam = line.tcam_id;
        lsb_tcam.tcam_idx = m_ctm_config_tcam->get_lsb_tcam(line.tcam_id.tcam_idx);
        m_line_mgr[lsb_tcam].release_line(line.line);
    }
    entries.erase(line_idx);

    return LA_STATUS_SUCCESS;
}

size_t
ctm_mgr_tcam::relocate_groups(const tcams_container& destination_tcams, size_t number_of_lines_to_relocate)
{
    la_status status = LA_STATUS_SUCCESS;
    std::vector<group_desc> checked_groups;
    size_t relocated_lines = 0;
    // for all tcam's in current table
    for (const tcam_desc& tcam_desc : destination_tcams) {
        // Check if other DB which is located in current TCAM can be moved from it (save the checked DB in order not to check it
        // again later)
        const std::vector<group_desc> eligbale_groups_on_tcam = m_ctm_config_tcam->get_groups_by_tcam(tcam_desc);
        for (const group_desc& narrow_group_to_move : eligbale_groups_on_tcam) {
            if (narrow_group_to_move.is_wide()) {
                continue;
            }

            bool contained = contains(checked_groups, narrow_group_to_move);
            if (contained) {
                continue;
            }
            // Get number of free lines to relocate to
            size_t free_space_in_group = get_free_space_in_group(narrow_group_to_move, destination_tcams);
            if (free_space_in_group == 0) {
                checked_groups.push_back(narrow_group_to_move);
                continue;
            }

            // Move lines to a different TCAM
            table_vec tables = get_tables_for_group(narrow_group_to_move);
            for (table_desc& table : tables) {
                line_position first_line_to_move = 0;
                // find lines from this table that are currently located on the set of tcams to relocate
                size_t found_lines = find_allocated_lines_in_tcam(
                    table, tcam_desc, first_line_to_move, number_of_lines_to_relocate - relocated_lines);
                if (found_lines == 0) {
                    continue;
                }

                size_t lines_to_relocate_in_table
                    = std::min({free_space_in_group, number_of_lines_to_relocate - relocated_lines, found_lines});

                vector_alloc<line_desc> new_lines;
                // Call find_and_allocate_lines with tcams_to_clear=destination_tcams to avoid allocating a line in tcam we try to
                // free
                status = find_and_allocate_lines_for_move(
                    table, first_line_to_move, lines_to_relocate_in_table, destination_tcams, new_lines);
                // release lines after allocation
                for (line_desc new_line : new_lines) {
                    m_line_mgr[new_line.tcam_id].release_line(new_line.line);
                }

                relocated_lines += lines_to_relocate_in_table;
                if (relocated_lines >= number_of_lines_to_relocate) {
                    dassert_crit(relocated_lines == number_of_lines_to_relocate);
                    return relocated_lines;
                }
                free_space_in_group -= lines_to_relocate_in_table;
                if (free_space_in_group == 0) {
                    checked_groups.push_back(narrow_group_to_move);
                    break;
                }
            }
        }
    }

    return relocated_lines;
}

la_status
ctm_mgr_tcam::allocate_tcam_for_group(const group_desc& group, tcam_desc& out_tcam)
{
    la_status status = LA_STATUS_SUCCESS;
    tcam_desc tcam;
    vector_alloc<tcam_desc> reserved_tcams_allocated;

    while (status == LA_STATUS_SUCCESS) {
        // allocate tcams until a not-reserved tcam is allocated
        status = m_ctm_config_tcam->allocate_tcam_for_group(group, out_tcam);
        if (status == LA_STATUS_SUCCESS && contains(m_reserved_tcams, out_tcam)) {
            reserved_tcams_allocated.push_back(tcam);
        } else if (status == LA_STATUS_SUCCESS) {
            break;
        }
    }

    // free the reserved tcams allocated
    for (tcam_desc& reserved_tcam : reserved_tcams_allocated) {
        la_status free_status = m_ctm_config_tcam->free_tcam(reserved_tcam);
        dassert_crit(free_status == LA_STATUS_SUCCESS);
    }

    return status;
}

la_status
ctm_mgr_tcam::allocate_new_tcams_for_group(const group_desc& group, size_t number_of_tcams, bool must_allocate_all)
{
    la_status status = LA_STATUS_SUCCESS;
    size_t tcams_allocated = 0;
    while (tcams_allocated < number_of_tcams && status == LA_STATUS_SUCCESS) {
        tcam_desc tcam;
        status = allocate_tcam_for_group(group, tcam);

        if (status != LA_STATUS_SUCCESS) {
            // TCAM relocation algorithm. We did not succeed in allocating a free tcam. We need to free some.
            status = try_free_tcams(group);

            if (status != LA_STATUS_SUCCESS) {
                log_debug(RA, "ctm_mgr_tcam::%s: unable to free tcams for group: %s", __FUNCTION__, to_string(group).c_str());
                // last resort to free tcam - recursive tcam reallocation
                status = recursive_reallocation(group);
                if (status != LA_STATUS_SUCCESS) {
                    log_debug(RA,
                              "ctm_mgr_tcam::%s: unable to recursively free tcams for group: %s",
                              __FUNCTION__,
                              to_string(group).c_str());
                    break;
                }
            }

            status = allocate_tcam_for_group(group, tcam);
            dassert_crit(status == LA_STATUS_SUCCESS, "We cannot fail in getting a new TCAM if we successfully freed TCAMs");
        }

        create_line_mgr_for_tcam(tcam);
        create_mem_tcam(tcam);

        if (group.is_wide() == true) {
            tcam_desc msb_tcam;
            msb_tcam.ring_idx = tcam.ring_idx;
            msb_tcam.subring_idx = tcam.subring_idx;
            msb_tcam.tcam_idx = m_ctm_config_tcam->get_msb_tcam(tcam.tcam_idx);

            create_line_mgr_for_tcam(msb_tcam);
            create_mem_tcam(msb_tcam);
        }

        tcams_allocated++;
    }

    // if we can allocate only part of needed tcams, then we return success unless no tcams were allocated
    if (status != LA_STATUS_SUCCESS && !must_allocate_all) {
        if (tcams_allocated > 0) {
            status = LA_STATUS_SUCCESS;
        }
    }

    return status;
}

la_status
ctm_mgr_tcam::try_free_tcams(const group_desc& group_to_make_space_for)
{
    la_status status = LA_STATUS_ERESOURCE;
    priority_to_tcams_map possible_tcams_to_free = m_ctm_config_tcam->get_tcams_to_relocate_for_group(group_to_make_space_for);

    for (priority_to_tcams_map::iterator it = possible_tcams_to_free.begin(); it != possible_tcams_to_free.end(); ++it) {
        // Here we are iterating trough each priority separately.

        tcams_container_vec& tcam_pairs_vector = it->second;

        log_debug(RA,
                  "ctm_mgr_tcam::%s: tcams to clear per priority: %zu: %s",
                  __FUNCTION__,
                  it->first,
                  to_string(tcam_pairs_vector).c_str());

        // posable filtering.
        filter_tcams_to_free(tcam_pairs_vector, group_to_make_space_for);

        // possible sorting.

        for (const tcams_container& tcams_to_free : tcam_pairs_vector) {
            la_status can_be_cleared = can_tcams_be_cleared_for_reallocation(tcams_to_free);

            if (can_be_cleared == LA_STATUS_SUCCESS) {
                la_status cleared_status = clear_tcams(tcams_to_free);
                dassert_crit(cleared_status == LA_STATUS_SUCCESS);

                for (const tcam_desc& tcam : tcams_to_free) {
                    group_vec groups_on_tcam = m_ctm_config_tcam->get_groups_by_tcam(tcam);
                    for (const group_desc& group_on_tcam : groups_on_tcam) {
                        m_tcam_already_freed_from_group[group_on_tcam].push_back(tcam);
                    }

                    status = m_ctm_config_tcam->free_tcam(tcam);
                    dassert_crit(status == LA_STATUS_SUCCESS);
                }

                return status;
            }
        }
    }

    return status;
}

la_status
ctm_mgr_tcam::can_tcams_be_cleared_for_reallocation(const tcams_container& tcams_to_free)
{
    // Set up the per stack controll data.
    group_data_for_reallocation_s data = get_tcams_info_for_reallocation(tcams_to_free);

    log_debug(RA,
              "ctm_mgr_tcam::%s: tcams_to_free(paired: %d): %s %s.",
              __FUNCTION__,
              data.is_tcam_paired,
              to_string(tcams_to_free[0]).c_str(),
              tcams_to_free.size() == 2 ? to_string(tcams_to_free[1]).c_str() : "");

    // Now do all the checks for whether theese tcams can be cleared,  in order to  the space for the
    for (size_t stack_idx = 0; stack_idx < data.number_of_tcam_stacks; stack_idx++) {
        bool is_tcam_part_of_the_expanding_group
            = m_current_group.is_wide() ? is_subgroup(m_current_group, data.narrow_groups[stack_idx]) : false;
        if (is_tcam_part_of_the_expanding_group && data.is_tcam_paired) {
            log_debug(RA, "ctm_mgr_tcam::%s: we don't clear pairs belonging to the subject wide group.", __FUNCTION__);
            return LA_STATUS_ERESOURCE;
        }

        remaining_stack_space_s remaining_space = get_free_space_after_clear(data.narrow_groups[stack_idx],
                                                                             data.wide_group,
                                                                             data.num_of_narrow_tcams_to_clear_per_stack[stack_idx],
                                                                             data.num_of_wide_tcams_to_clear);

        if (remaining_space.wide_space < 0 || remaining_space.total_space < 0) {
            log_debug(RA,
                      "ctm_mgr_tcam::%s: We don't have the appropriate number of lines on the stack(wide: %s, narrow: %s) to "
                      "actually be able to "
                      "phisically clear the tcam.",
                      __FUNCTION__,
                      to_string(data.wide_group).c_str(),
                      to_string(data.narrow_groups[stack_idx]).c_str());
            return LA_STATUS_ERESOURCE;
        }

        if ((data.num_of_wide_tcams_to_clear > data.num_of_narrow_tcams_to_clear_per_stack[stack_idx]
             || is_tcam_part_of_the_expanding_group)
            && data.narrow_groups[stack_idx].is_valid()
            && remaining_space.total_space <= 0) {
            // 1. if we have more wide tcams to free than narrow. Then narrow/wide line swapping might
            // happen within the stack.
            // 2. If the tcam is part of a wide group searching for more wide lines it does not make sense to clear this tcam if no
            // free lines will remain.
            // In these 2 cases we must make sure to have at least one extra free line after the clear. Notice the = in the last
            // condition.
            log_debug(RA, "ctm_mgr_tcam::%s: error, a case where we need at least one extra free line after clear.", __FUNCTION__);
            return LA_STATUS_ERESOURCE;
        }
    }

    return LA_STATUS_SUCCESS;
}

ctm_mgr_tcam::group_data_for_reallocation_s
ctm_mgr_tcam::get_tcams_info_for_reallocation(const tcams_container& tcams_to_free)
{
    group_data_for_reallocation_s data;

    data.is_tcam_paired = m_ctm_config_tcam->is_tcam_part_of_pair(
        tcams_to_free[0].ring_idx, tcams_to_free[0].subring_idx, tcams_to_free[0].tcam_idx);

    // Set up the per stack controll data.
    if ((tcams_to_free.size() == 1 && !data.is_tcam_paired)
        || (tcams_to_free.size() == 2 && are_tcams_on_the_same_narrow_group(tcams_to_free))) {
        // If we are given just one tcam and it is not paired, or two tcams that are on the same stack. Then we only consider one
        // stack.
        data.number_of_tcam_stacks = 1;
        data.narrow_groups[0] = get_narrow_group_on_tcam(tcams_to_free[0]);
        data.wide_group = get_wide_group_on_tcams(tcams_to_free);
        if (data.narrow_groups[0].is_valid()) {
            data.num_of_narrow_tcams_to_clear_per_stack[0]
                = tcams_to_free.size() == 1 ? 1 : 2; // If we have one tcam, free one, if 2 free 2.
        } else {
            // If narrow group is invalid, no narrow tcam needs to be cleard
            data.num_of_narrow_tcams_to_clear_per_stack[0] = 0;
        }
        data.num_of_wide_tcams_to_clear = 0; // Since the tcam(s) are not paired with any other, no wide tcams are lost.
    } else {
        // we need to consider two stacks.
        data.number_of_tcam_stacks = 2;
        // For the primary stack, we consider where the first tcam is.
        // And for it we will loose one narrow tcam if the group is valid. Wide will be lost if tcam is paired.
        data.narrow_groups[0] = get_narrow_group_on_tcam(tcams_to_free[0]);
        data.wide_group = get_wide_group_on_tcams(tcams_to_free);
        data.num_of_narrow_tcams_to_clear_per_stack[0] = data.narrow_groups[0].is_valid() ? 1 : 0;
        data.num_of_wide_tcams_to_clear = data.is_tcam_paired ? 1 : 0;

        // For the secondary stack we consider the second tcam stack if it exist, or stack of the pair of the first tcam.
        // If it is given as an argument then we loose the narrow tcam, otherwise not.
        // Wide tcam is lost only if its part of a pair, no mather if it is given as an argument or is pair of the first tcam.
        tcam_desc other_tcam_from_pair = tcams_to_free[0];
        other_tcam_from_pair.tcam_idx = m_ctm_config_tcam->get_paired_tcam(tcams_to_free[0].tcam_idx);
        data.narrow_groups[1] = tcams_to_free.size() == 2 ? get_narrow_group_on_tcam(tcams_to_free[1])
                                                          : get_narrow_group_on_tcam(other_tcam_from_pair);
        if (data.narrow_groups[1].is_valid()) {
            data.num_of_narrow_tcams_to_clear_per_stack[1] = tcams_to_free.size() == 2 ? 1 : 0;
        } else {
            data.num_of_narrow_tcams_to_clear_per_stack[1] = 0;
        }

        dassert_crit(!(data.narrow_groups[0] == data.narrow_groups[1]));
    }

    return data;
}

ctm_mgr_tcam::remaining_stack_space_s
ctm_mgr_tcam::get_free_space_after_clear(const group_desc& narrow_group_on_stack,
                                         const group_desc& wide_group_on_stack,
                                         size_t num_of_narrow_tcams_to_clear,
                                         size_t num_of_wide_tcams_to_clear)
{
    remaining_stack_space_s return_value;
    group_desc wide_group;
    if (!narrow_group_on_stack.is_valid() || wide_group_on_stack.is_valid()) {
        wide_group = wide_group_on_stack;
    } else {
        const tcams_container& tcams_on_stack = m_ctm_config_tcam->get_eligible_tcams_for_group(narrow_group_on_stack);
        wide_group = get_wide_group_on_tcams(tcams_on_stack);
    }

    size_t number_of_wide_lines = get_number_of_lines_in_group(wide_group);
    size_t number_of_eligible_wide_tcams
        = wide_group.is_valid() ? m_ctm_config_tcam->get_eligible_tcams_for_group(wide_group).size() : 0;

    size_t wide_scale_after_free = (number_of_eligible_wide_tcams - num_of_wide_tcams_to_clear) * BANK_SIZE;
    return_value.wide_space = wide_scale_after_free - number_of_wide_lines;

    if (narrow_group_on_stack.is_valid()) {
        size_t number_of_narrow_lines = get_number_of_lines_in_group(narrow_group_on_stack);
        size_t number_of_eligible_narrow_tcams
            = narrow_group_on_stack.is_valid() ? m_ctm_config_tcam->get_eligible_tcams_for_group(narrow_group_on_stack).size() : 0;

        size_t scale_after_free = (number_of_eligible_narrow_tcams - num_of_narrow_tcams_to_clear) * BANK_SIZE;
        return_value.total_space = scale_after_free - (number_of_narrow_lines + number_of_wide_lines);
    } else {
        // the narrow group isn't valid which means that there is only the wide group on this stack, so the total space is equal to
        // wide space
        return_value.total_space = return_value.wide_space;
    }

    return return_value;
}

la_status
ctm_mgr_tcam::recursive_reallocation(const group_desc& group_to_make_space_for)
{
    la_status status = LA_STATUS_ERESOURCE;
    size_t groups_that_cant_reallocate_size_before = m_groups_that_cant_reallocate.size();
    if (m_current_group.is_wide() && is_subgroup(m_current_group, group_to_make_space_for)) {
        // if we try to get narrow tcams to make space for wide - don't reallocate the wide tcams either
        m_groups_that_cant_reallocate.push_back(m_current_group);
    }
    m_groups_that_cant_reallocate.push_back(group_to_make_space_for);

    priority_to_tcams_map possible_tcams_to_free = m_ctm_config_tcam->get_tcams_to_relocate_for_group(group_to_make_space_for);
    for (priority_to_tcams_map::iterator it = possible_tcams_to_free.begin(); it != possible_tcams_to_free.end(); ++it) {
        tcams_container_vec& tcam_pairs_vector = it->second;
        // posable filtering.
        filter_tcams_to_free(tcam_pairs_vector, group_to_make_space_for);

        for (const tcams_container& tcam_pair_to_free : tcam_pairs_vector) {
            // skip tcams with groups we couldnt allocate
            bool skip_tcam_pair = does_tcams_contain_a_group_from_list(tcam_pair_to_free, m_groups_that_cant_reallocate);
            if (skip_tcam_pair) {
                continue;
            }

            size_t reserved_tcams_size_before = m_reserved_tcams.size();
            const tcam_desc& first_tcam_to_free = *tcam_pair_to_free.begin();
            bool is_tcam_paired = m_ctm_config_tcam->is_tcam_part_of_pair(
                first_tcam_to_free.ring_idx, first_tcam_to_free.subring_idx, first_tcam_to_free.tcam_idx);
            if (is_tcam_paired) {
                // the tcams to free are 1 or 2 tcams that belong to a wide group
                status = try_recursive_reallocation_to_free_wide_tcams(tcam_pair_to_free);
            } else if (group_to_make_space_for.is_wide()) {
                // the tcams to free are 1 or 2 tcams that don't belong to a wide group
                // and the group to make space for is wide
                status = try_recursive_reallocation_to_free_narrow_tcams_for_wide_group(tcam_pair_to_free, group_to_make_space_for);
            } else {
                // the tcams to free are 1 tcam that don't belong to a wide group
                // and the group to make space for is narrow
                status = try_recursive_reallocation_to_free_narrow_tcams_for_narrow_group(tcam_pair_to_free);
            }
            m_reserved_tcams.erase(m_reserved_tcams.begin() + reserved_tcams_size_before, m_reserved_tcams.end());
            if (status == LA_STATUS_SUCCESS) {
                break;
            }
        }
        if (status == LA_STATUS_SUCCESS) {
            break;
        }
    }

    m_groups_that_cant_reallocate.erase(m_groups_that_cant_reallocate.begin() + groups_that_cant_reallocate_size_before,
                                        m_groups_that_cant_reallocate.end());

    return status;
}

la_status
ctm_mgr_tcam::try_recursive_reallocation_to_free_wide_tcams(const tcams_container& tcam_pair_to_free)
{
    la_status status = LA_STATUS_ERESOURCE;
    group_data_for_reallocation_s data = get_tcams_info_for_reallocation(tcam_pair_to_free);

    log_debug(RA,
              "ctm_mgr_tcam::%s: tcam_pair_to_free(paired: %d): %s %s.",
              __FUNCTION__,
              data.is_tcam_paired,
              to_string(tcam_pair_to_free[0]).c_str(),
              tcam_pair_to_free.size() == 2 ? to_string(tcam_pair_to_free[1]).c_str() : "");

    remaining_stack_space_s remaining_space_first_stack
        = get_free_space_after_clear(data.narrow_groups[FIRST_STACK_IDX],
                                     data.wide_group,
                                     data.num_of_narrow_tcams_to_clear_per_stack[FIRST_STACK_IDX],
                                     data.num_of_wide_tcams_to_clear);

    if (remaining_space_first_stack.wide_space < 0) {
        // we need another wide tcam to hold all the wide lines
        status = allocate_new_tcams_for_group(data.wide_group, 1, true);
        if (status != LA_STATUS_SUCCESS) {
            m_groups_that_cant_reallocate.push_back(data.wide_group);
            return status;
        }
    }
    // Put wide group tcams as reserved to not lose them
    const tcams_container& wide_tcams = m_ctm_config_tcam->get_eligible_tcams_for_group(data.wide_group);
    m_reserved_tcams.insert(m_reserved_tcams.end(), wide_tcams.begin(), wide_tcams.end());
    const tcams_container& wide_tcams_lsb = m_ctm_config_tcam->get_eligible_lsb_tcams_for_wide_group(data.wide_group);
    m_reserved_tcams.insert(m_reserved_tcams.end(), wide_tcams_lsb.begin(), wide_tcams_lsb.end());

    if (data.number_of_tcam_stacks > 1) {
        group_desc& narrow_group_second_stack = data.narrow_groups[SECOND_STACK_IDX];
        remaining_stack_space_s remaining_space_second_stack
            = get_free_space_after_clear(narrow_group_second_stack,
                                         data.wide_group,
                                         data.num_of_narrow_tcams_to_clear_per_stack[SECOND_STACK_IDX],
                                         data.num_of_wide_tcams_to_clear);
        if (remaining_space_second_stack.total_space < 0) {
            // if total space is <0 after making wide space there must be narrow lines on the tcam -> there is a narrow group
            dassert_crit(narrow_group_second_stack.is_valid());
            status = make_space_for_group(narrow_group_second_stack, BANK_SIZE);
            if (status != LA_STATUS_SUCCESS) {
                m_groups_that_cant_reallocate.push_back(narrow_group_second_stack);
                return status;
            }
        }

        if (narrow_group_second_stack.is_valid() && remaining_space_second_stack.total_space < BANK_SIZE) {
            // Put narrow group tcams as reserved to not lose them
            const tcams_container& narrow_tcams = m_ctm_config_tcam->get_eligible_tcams_for_group(narrow_group_second_stack);
            m_reserved_tcams.insert(m_reserved_tcams.end(), narrow_tcams.begin(), narrow_tcams.end());
        } else {
            const tcam_desc& paired_tcam = get_paired_tcam(tcam_pair_to_free[0]);
            m_reserved_tcams.push_back(paired_tcam);
        }
    }

    group_desc& narrow_group_first_stack = data.narrow_groups[FIRST_STACK_IDX];
    remaining_space_first_stack = get_free_space_after_clear(narrow_group_first_stack,
                                                             data.wide_group,
                                                             data.num_of_narrow_tcams_to_clear_per_stack[FIRST_STACK_IDX],
                                                             data.num_of_wide_tcams_to_clear);
    if (remaining_space_first_stack.total_space < 0) {
        status = make_space_for_group(narrow_group_first_stack, BANK_SIZE);
        if (status != LA_STATUS_SUCCESS) {
            m_groups_that_cant_reallocate.push_back(narrow_group_first_stack);
            return status;
        }
    }

    la_status can_be_cleared = can_tcams_be_cleared_for_reallocation(tcam_pair_to_free);
    dassert_crit(can_be_cleared == LA_STATUS_SUCCESS);
    la_status cleared_status = free_tcams(tcam_pair_to_free);
    dassert_crit(cleared_status == LA_STATUS_SUCCESS);

    return status;
}

la_status
ctm_mgr_tcam::try_recursive_reallocation_to_free_narrow_tcams_for_wide_group(const tcams_container& tcam_pair_to_free,
                                                                             const group_desc& group_to_make_space_for)
{
    la_status status = LA_STATUS_ERESOURCE;
    // possible tcams to free:
    // 1. 2 unpaired tcams
    // 2. 1 unpaired tcam (other side of the pair is a free tcam)
    // 3. 1 unpaired tcam (other side of the pair is in the correct place for the wide group)

    log_debug(RA,
              "ctm_mgr_tcam::%s: tcam_pair_to_free: %s %s.",
              __FUNCTION__,
              to_string(tcam_pair_to_free[0]).c_str(),
              tcam_pair_to_free.size() == 2 ? to_string(tcam_pair_to_free[1]).c_str() : "");

    const tcam_desc& paired_tcam = get_paired_tcam(tcam_pair_to_free[FIRST_STACK_IDX]);
    if (tcam_pair_to_free.size() == 1) {
        const group_desc& group_on_paired_tcam = get_narrow_group_on_tcam(paired_tcam);
        if (group_on_paired_tcam.is_valid()) {
            // the tcam is not free -> the group is in the correct place
            m_reserved_tcams.push_back(paired_tcam);
        }
    }

    tcam_desc tcams_in_place[2];
    size_t msb_idx = 0;
    size_t lsb_idx = 1;
    bool tcam_in_first_stack_is_msb = m_ctm_config_tcam->is_msb_tcam(tcam_pair_to_free[FIRST_STACK_IDX].tcam_idx);
    tcams_in_place[msb_idx] = tcam_in_first_stack_is_msb ? tcam_pair_to_free[FIRST_STACK_IDX] : paired_tcam;
    tcams_in_place[lsb_idx] = tcam_in_first_stack_is_msb ? paired_tcam : tcam_pair_to_free[FIRST_STACK_IDX];

    group_desc narrow_groups_of_group_to_make_space_for[2];
    narrow_groups_of_group_to_make_space_for[msb_idx]
        = m_ctm_config_tcam->get_msb_narrow_group_from_wide_group(group_to_make_space_for);
    narrow_groups_of_group_to_make_space_for[lsb_idx]
        = m_ctm_config_tcam->get_lsb_narrow_group_from_wide_group(group_to_make_space_for);

    size_t msb_tcam_count
        = m_ctm_config_tcam->get_eligible_tcams_for_group(narrow_groups_of_group_to_make_space_for[msb_idx]).size();
    size_t lsb_tcam_count
        = m_ctm_config_tcam->get_eligible_tcams_for_group(narrow_groups_of_group_to_make_space_for[lsb_idx]).size();
    size_t wide_tcam_count = m_ctm_config_tcam->get_eligible_tcams_for_group(group_to_make_space_for).size();

    size_t free_idx_order[] = {msb_idx, lsb_idx};
    if (msb_tcam_count == wide_tcam_count && lsb_tcam_count > wide_tcam_count) {
        // there is a narrow only lsb tcam to move in place (and no narrow only msb)
        free_idx_order[0] = lsb_idx;
        free_idx_order[1] = msb_idx;
    }

    if (msb_tcam_count == wide_tcam_count && lsb_tcam_count == wide_tcam_count && tcam_pair_to_free.size() == 1) {
        // we don't have narrow only tcams to move in place, so reserve the paired tcam instead
        m_reserved_tcams.push_back(paired_tcam);
    }

    for (size_t idx : free_idx_order) {
        // clear tcam (if needed)
        const group_desc& narrow_group = get_narrow_group_on_tcam(tcams_in_place[idx]);
        const group_desc& wide_group = get_wide_group_on_tcams(tcam_pair_to_free);
        bool is_group_in_place = (narrow_group == narrow_groups_of_group_to_make_space_for[idx]);
        if (narrow_group.is_valid() && !is_group_in_place) {
            // group not in place and tcam isn't free
            remaining_stack_space_s r_space = get_free_space_after_clear(narrow_group, wide_group, 1, 0);
            if (r_space.total_space < 0) {
                status = make_space_for_group(narrow_group, BANK_SIZE);
                if (status != LA_STATUS_SUCCESS) {
                    m_groups_that_cant_reallocate.push_back(narrow_group);
                    return status;
                }
            }

            // clear the tcam
            const tcams_container single_tcam_vec = {tcams_in_place[idx]};
            la_status cleared_status = free_tcams(single_tcam_vec);
            dassert_crit(cleared_status == LA_STATUS_SUCCESS);
        }

        if (idx == free_idx_order[0] && !is_group_in_place) {
            // allocate first freed tcam for the correct narrow group, in case that we need to take tcam from the narrow group
            tcam_desc& free_tcam = tcams_in_place[idx];
            m_ctm_config_tcam->allocate_specific_tcam_for_narrow_group(narrow_groups_of_group_to_make_space_for[idx], free_tcam);
            create_line_mgr_for_tcam(free_tcam);
            create_mem_tcam(free_tcam);
            m_reserved_tcams.push_back(free_tcam);
        }
    }

    return status;
}

la_status
ctm_mgr_tcam::try_recursive_reallocation_to_free_narrow_tcams_for_narrow_group(const tcams_container& tcam_pair_to_free)
{
    log_debug(RA,
              "ctm_mgr_tcam::%s: tcam_pair_to_free: %s %s.",
              __FUNCTION__,
              to_string(tcam_pair_to_free[0]).c_str(),
              tcam_pair_to_free.size() == 2 ? to_string(tcam_pair_to_free[1]).c_str() : "");
    group_data_for_reallocation_s data = get_tcams_info_for_reallocation(tcam_pair_to_free);
    dassert_crit(data.number_of_tcam_stacks == 1 && tcam_pair_to_free.size() == 1);

    la_status status = make_space_for_group(data.narrow_groups[0], BANK_SIZE);
    if (status == LA_STATUS_SUCCESS) {
        la_status cleared_status = free_tcams(tcam_pair_to_free);
        dassert_crit(cleared_status == LA_STATUS_SUCCESS);
    } else {
        m_groups_that_cant_reallocate.push_back(data.narrow_groups[0]);
    }
    return status;
}

la_status
ctm_mgr_tcam::free_tcams(const tcams_container& tcams_to_free)
{
    la_status cleared_status = clear_tcams(tcams_to_free);
    dassert_crit(cleared_status == LA_STATUS_SUCCESS);

    for (const tcam_desc& tcam : tcams_to_free) {
        group_vec groups_on_tcam = m_ctm_config_tcam->get_groups_by_tcam(tcam);
        for (const group_desc& group_on_tcam : groups_on_tcam) {
            m_tcam_already_freed_from_group[group_on_tcam].push_back(tcam);
        }

        cleared_status = m_ctm_config_tcam->free_tcam(tcam);
        dassert_crit(cleared_status == LA_STATUS_SUCCESS);
    }

    return cleared_status;
}

bool
ctm_mgr_tcam::are_tcams_on_the_same_narrow_group(const tcams_container& tcams)
{
    const group_desc& group_on_first_tcam = get_narrow_group_on_tcam(tcams[0]);

    for (const tcam_desc& tcam : tcams) {
        const group_desc& group = get_narrow_group_on_tcam(tcam);

        if (!(group == group_on_first_tcam)) { //!= op not implemented.
            return false;
        }
    }

    return true;
}

la_status
ctm_mgr_tcam::clear_tcams(const tcams_container& tcams_to_free)
{
    // For each group, each table on the group, call find_and_allocate_line for every line belonging to this tcam.
    // But first fake allocate free lines on this tcam, to help the find_and_allocate_line algorithm.

    // Fake allocate. Only if the tcam actually needs clearing.

    std::map<tcam_desc, size_t> num_of_lines_to_clear_per_tcam;
    std::map<tcam_desc, size_t> num_of_lines_cleared_per_tcam;

    for (const tcam_desc& tcam : tcams_to_free) {
        ctm_tcam_line_mgr& line_manager = m_line_mgr[tcam];

        num_of_lines_cleared_per_tcam[tcam] = 0;
        num_of_lines_to_clear_per_tcam[tcam] = line_manager.get_num_alloc_lines();

        if (num_of_lines_to_clear_per_tcam[tcam] == 0) {
            continue;
        }
        line_manager.allocate_all_lines();
    }

    // Now do tcam clearing. Again only if it actually contains lines.
    for (const tcam_desc& tcam : tcams_to_free) {
        tcam_desc tcam_pair = tcam;
        ctm_tcam_line_mgr& line_manager = m_line_mgr[tcam];

        if (line_manager.get_num_alloc_lines() == 0) {
            continue;
        }

        tcam_pair.tcam_idx = m_ctm_config_tcam->get_paired_tcam(tcam.tcam_idx);
        ctm_tcam_line_mgr& tcam_pair_line_manager = m_line_mgr[tcam_pair];

        group_vec groups_on_tcam = m_ctm_config_tcam->get_groups_by_tcam(tcam);

        // we can have one narrow, one wide group on the tcam
        for (ctm::group_desc& group : groups_on_tcam) {
            size_t max_lines_to_bulk_move = num_of_lines_to_clear_per_tcam[tcam];
            tcam_desc msb_tcam = tcam;
            if (group.is_wide()) {
                msb_tcam.tcam_idx = m_ctm_config_tcam->get_msb_tcam(tcam.tcam_idx);
                if (tcams_to_free.size() == 1) {
                    // in case we need to move wide lines from a tcam we don't clear, there might be line swapping
                    // get the max amount of lines that can be moved together
                    group_desc tcam_pair_narrow_group = get_narrow_group_on_tcam(tcam_pair);
                    if (tcam_pair_narrow_group.slice_idx != IDX_INVAL) {
                        size_t free_space = get_free_space_in_group(tcam_pair_narrow_group);
                        max_lines_to_bulk_move = std::min(free_space, max_lines_to_bulk_move);
                    }
                }
            }

            table_vec tables = get_tables_for_group(group);
            for (ctm::table_desc& table : tables) {
                // For each table we will iterate over the m_entries and find the lines belonging to the tcam.
                // We call find_and_allocate_lines_for_move to move the entries from the tcam

                line_position first_line_to_move;
                size_t found_lines = find_allocated_lines_in_tcam(table, msb_tcam, first_line_to_move, max_lines_to_bulk_move);
                while (found_lines > 0) {
                    // move max amount of table lines possible from tcam in each iteration, until no lines left
                    size_t lines_to_move = std::min(found_lines, max_lines_to_bulk_move);
                    if (group.is_wide()) {
                        size_t free_space = get_free_space_in_group(group);
                        if (free_space < lines_to_move) {
                            size_t msb_lines, lsb_lines;
                            relocate_narrow_groups_for_wide_group(group, lines_to_move, lsb_lines, msb_lines);
                            dassert_crit(lsb_lines >= lines_to_move && msb_lines >= lines_to_move);

                            tcams_container wide_tcams_to_free = {tcam, tcam_pair};
                            la_status rc = make_free_wide_lines(group, lines_to_move, wide_tcams_to_free);
                            dassert_crit(rc == LA_STATUS_SUCCESS);
                        }
                    }

                    vector_alloc<line_desc> new_lines;
                    // Call find_and_allocate_lines with tcams_to_clear=tcams_to_free to avoid allocating a line in tcam we try to
                    // free
                    la_status status
                        = find_and_allocate_lines_for_move(table, first_line_to_move, lines_to_move, tcams_to_free, new_lines);

                    dassert_crit(
                        status
                        == LA_STATUS_SUCCESS); // Do not call this method if there is not enough space to move the lines away.

                    num_of_lines_cleared_per_tcam[tcam] += lines_to_move;

                    if (is_table_wide(table)) {
                        num_of_lines_cleared_per_tcam[tcam_pair] += lines_to_move;

                        if (tcams_to_free.size() == 1) {
                            // If we are clearing a wide line but, not the paired tcam. Then release back the other half of the
                            // lines.
                            for (line_desc& line_to_release : new_lines) {
                                tcam_pair_line_manager.release_line(line_to_release.line);
                            }
                        }
                    }

                    found_lines = find_allocated_lines_in_tcam(table, msb_tcam, first_line_to_move, max_lines_to_bulk_move);
                }
            }
        }

        line_manager.release_all_lines();
        dassert_crit(num_of_lines_cleared_per_tcam[tcam] == num_of_lines_to_clear_per_tcam[tcam]);
    }

    return LA_STATUS_SUCCESS;
}

size_t
ctm_mgr_tcam::find_allocated_lines_in_tcam(const table_desc& table,
                                           const tcam_desc& tcam,
                                           line_position& out_first_line_to_move,
                                           size_t needed_number_of_lines)
{
    size_t found_lines = 0;
    lines_map& entries = m_entries[table];
    if (entries.empty()) {
        return 0;
    }

    bool first_line_found = false;

    for (std::pair<const line_position, line_desc>& line : entries) {
        if (line.second.tcam_id > tcam) {
            continue;
        }

        if (line.second.tcam_id < tcam) {
            break;
        }

        // at this point we are looking at a line from the specific TCAM
        if (!first_line_found) {
            out_first_line_to_move = line.first;
            first_line_found = true;
        }

        found_lines++;
        if (found_lines == needed_number_of_lines) {
            return found_lines;
        }
    }

    return found_lines;
}

size_t
ctm_mgr_tcam::get_free_space_in_tcams(const tcams_container& tcams)
{
    size_t free_lines_found = 0;
    for (const tcam_desc& desc : tcams) {
        const ctm_tcam_line_mgr& line_mgr = m_line_mgr[desc];
        free_lines_found += line_mgr.get_num_free_lines();
    }
    return free_lines_found;
}

la_status
ctm_mgr_tcam::find_free_line_in_tcams(const tcams_container& tcams,
                                      tcams_container::const_iterator& out_in_tcam_it,
                                      size_t& out_in_first_line)
{
    la_status rc = LA_STATUS_EOUTOFRANGE;

    for (; out_in_tcam_it != tcams.end(); ++out_in_tcam_it) {
        ctm_tcam_line_mgr& line_manager = m_line_mgr[*out_in_tcam_it];

        out_in_first_line = line_manager.get_first_free_line_in_range(out_in_first_line, BANK_SIZE);

        if (out_in_first_line < BANK_SIZE) {
            rc = LA_STATUS_SUCCESS;
            break;
        }

        // start iteration on next tcam from line 0
        out_in_first_line = 0;
    }

    return rc;
}

size_t
ctm_mgr_tcam::get_free_space_in_group(group_desc group)
{
    const tcams_container empty_tcam_container;

    return get_free_space_in_group(group, empty_tcam_container);
}

// TODO check if optimization needed for get_free_space_in_group to only count until the needed number of lines
size_t
ctm_mgr_tcam::get_free_space_in_group(group_desc group, const tcams_container& tcams_to_avoid)
{
    size_t free_space = 0;

    if (!group.is_wide()) {
        // get free space in group without lines in tcams_to_avoid
        const tcams_container& tcams = m_ctm_config_tcam->get_eligible_tcams_for_group(group);
        tcams_container filtered_tcams;
        filter_tcams(tcams, tcams_to_avoid, filtered_tcams);
        free_space = get_free_space_in_tcams(filtered_tcams);
    } else {
        const tcams_container tcams_lsb = m_ctm_config_tcam->get_eligible_lsb_tcams_for_wide_group(group);
        const tcams_container tcams_msb = m_ctm_config_tcam->get_eligible_tcams_for_group(group);

        size_t free_space_lsb = get_free_space_in_tcams(tcams_lsb);
        size_t free_space_msb = get_free_space_in_tcams(tcams_msb);

        // If we have free lines on both lsb and msb side then we ned to check if enough of them are already aligned to form wide
        // free lines.
        if (free_space_msb > 0 && free_space_lsb > 0) {
            size_t wide_free_lines_found = 0;

            // Go over each tcam pair and check for wide free lines. We only need one side of the tcam pair for the
            // find_free_wide_line_in_tcam method.
            for (tcams_container::const_iterator tcam_it_msb = tcams_msb.begin(); tcam_it_msb != tcams_msb.end(); ++tcam_it_msb) {
                line_desc start_line(0, *tcam_it_msb);
                line_desc end_line(BANK_SIZE, *tcam_it_msb);

                for (; start_line.line < BANK_SIZE; start_line.line++) {
                    start_line = find_free_wide_line_in_tcam(start_line, end_line);
                    if (start_line.line < BANK_SIZE) {
                        wide_free_lines_found++;
                    }
                }
            }
            free_space = wide_free_lines_found;
        }
    }

    return free_space;
}

size_t
ctm_mgr_tcam::get_number_of_lines_in_group(const group_desc& group) const
{
    size_t group_size = 0;

    table_vec tables_on_group = get_tables_for_group(group);

    for (const table_desc& table : tables_on_group) {
        group_size += get_table_usage(table);
    }

    return group_size;
}

size_t
ctm_mgr_tcam::get_table_usage(const table_desc& table) const
{
    table_to_lines_mapping_map::const_iterator it = m_entries.find(table);
    if (it != m_entries.end()) {
        return it->second.size();
    } else {
        return 0;
    }
}

ctm_mgr_tcam::line_desc
ctm_mgr_tcam::find_free_wide_line_in_tcam(const line_desc& start_line, const line_desc& end_line)
{
    dassert_crit(start_line.tcam_id == end_line.tcam_id);

    line_desc result_line(BANK_SIZE, start_line.tcam_id);

    tcam_desc lsb_tcam = start_line.tcam_id;
    lsb_tcam.tcam_idx = m_ctm_config_tcam->get_lsb_tcam(start_line.tcam_id.tcam_idx);
    const tcam_desc& msb_tcam = start_line.tcam_id;

    ctm_tcam_line_mgr& line_manager_lsb = m_line_mgr[lsb_tcam];
    ctm_tcam_line_mgr& line_manager_msb = m_line_mgr[msb_tcam];

    size_t line_lsb = line_manager_lsb.get_first_free_line_in_range(start_line.line, end_line.line);
    size_t line_msb = line_manager_msb.get_first_free_line_in_range(start_line.line, end_line.line);

    while (line_lsb < BANK_SIZE && line_msb < BANK_SIZE) {
        if (line_lsb == line_msb) {
            result_line.line = line_lsb;
            break;
        }

        if (line_lsb < line_msb) {
            line_lsb = line_manager_lsb.get_next_free_line(line_lsb);
        } else {
            line_msb = line_manager_msb.get_next_free_line(line_msb);
        }
    }

    return result_line;
}

la_status
ctm_mgr_tcam::make_free_wide_lines(group_desc& group, size_t number_of_lines)
{
    const tcams_container empty_tcam_container;

    la_status status = make_free_wide_lines(group, number_of_lines, empty_tcam_container);

    return status;
}

la_status
ctm_mgr_tcam::make_free_wide_lines(group_desc& group, size_t number_of_lines, const tcams_container& tcams_to_avoid)
{
    la_status status = LA_STATUS_ERESOURCE;

    const tcams_container& tcams_lsb = m_ctm_config_tcam->get_eligible_lsb_tcams_for_wide_group(group);
    const tcams_container& tcams_msb = m_ctm_config_tcam->get_eligible_tcams_for_group(group);

    size_t free_space_lsb = get_free_space_in_tcams(tcams_lsb);
    size_t free_space_msb = get_free_space_in_tcams(tcams_msb);

    dassert_crit(free_space_lsb >= number_of_lines && free_space_msb >= number_of_lines,
                 "Calling %s, without first allocating the narrow lines on lsb and msb tcams.",
                 __FUNCTION__);

    tcams_container filtered_tcams_lsb;
    filter_tcams(tcams_lsb, tcams_to_avoid, filtered_tcams_lsb);
    tcams_container filtered_tcams_msb;
    filter_tcams(tcams_msb, tcams_to_avoid, filtered_tcams_msb);

    tcams_container::const_iterator tcam_it_lsb = filtered_tcams_lsb.begin();
    tcams_container::const_iterator tcam_it_msb = filtered_tcams_msb.begin();

    size_t lsb_free_line = 0;
    size_t msb_free_line = 0;

    vector_alloc<line_desc> allocated_lines;

    for (size_t i = 0; i < number_of_lines; i++) {
        la_status found_lsb_line = find_free_line_in_tcams(filtered_tcams_lsb, tcam_it_lsb, lsb_free_line);
        la_status found_msb_line = find_free_line_in_tcams(filtered_tcams_msb, tcam_it_msb, msb_free_line);
        dassert_crit(found_lsb_line == LA_STATUS_SUCCESS || found_msb_line == LA_STATUS_SUCCESS);

        // find the tcam (lsb or msb) with the lower first free line
        tcam_desc main_tcam;
        size_t free_line = 0;
        if (found_msb_line != LA_STATUS_SUCCESS
            || (found_lsb_line == LA_STATUS_SUCCESS
                && line_desc(lsb_free_line, *tcam_it_lsb) < line_desc(msb_free_line, get_paired_tcam(*tcam_it_msb)))) {
            // lsb line comes before msb
            main_tcam = *tcam_it_lsb;
            free_line = lsb_free_line;
        } else {
            // msb line comes before lsb
            main_tcam = *tcam_it_msb;
            free_line = msb_free_line;
        }
        tcam_desc paired_tcam = get_paired_tcam(main_tcam);

        // Now try to allign the free lines to form a wide free line.
        // Free the coresponding line in the paired tcam to make a wide line.
        line_desc destination_line_desc(free_line, paired_tcam);

        ctm_tcam_line_mgr& paired_tcam_line_mgr = m_line_mgr[paired_tcam];

        if (paired_tcam_line_mgr.is_occupied(free_line) == false) {
            // if the line is free then we have the free pair of lines, allocate the line so it wouldn't be taken by the next wide
            // line freeing.
            paired_tcam_line_mgr.allocate_line(free_line);
            allocated_lines.push_back(line_desc(free_line, paired_tcam));
        } else {
            vector_alloc<line_desc> empty_line_desc;

            size_t destination_line_logical_index;

            table_desc paired_tcam_narrow_table;
            status
                = map_physical_to_logical_address(destination_line_desc, paired_tcam_narrow_table, destination_line_logical_index);
            dassert_crit(status == LA_STATUS_SUCCESS);

            // find and allocate line will bring the free line either exactly on the destination line, or on a first line before or
            // after..
            find_and_allocate_lines_for_write(paired_tcam_narrow_table, destination_line_logical_index, 1, empty_line_desc);

            // If the line is not directly on spot, move it.
            if (empty_line_desc[0] != destination_line_desc) {
                status = move_one_line(paired_tcam_narrow_table, destination_line_desc, empty_line_desc[0]);
                dassert_crit(status == LA_STATUS_SUCCESS);
                std::swap(m_entries[paired_tcam_narrow_table][destination_line_logical_index], empty_line_desc[0]);
            }

            // Find and allocate line allocates the line in the line manager, save line to release later.
            allocated_lines.push_back(line_desc(destination_line_desc.line, empty_line_desc[0].tcam_id));
        }
        free_line++;
        msb_free_line = free_line;
        lsb_free_line = free_line;
    }

    // Release the allocated lines.
    for (line_desc& line : allocated_lines) {
        m_line_mgr[line.tcam_id].release_line(line.line);
    }

    if (allocated_lines.size() == number_of_lines) {
        status = LA_STATUS_SUCCESS;
    }

    return status;
}

la_status
ctm_mgr_tcam::map_physical_to_logical_address(line_desc line, table_desc& table_out, size_t& logical_index)
{
    la_status rc = LA_STATUS_EOUTOFRANGE;
    const table_vec& eligbale_tables_on_tcam = get_tables_by_tcam(line.tcam_id);
    for (const table_desc& table : eligbale_tables_on_tcam) {
        lines_map entries = m_entries[table];
        ctm_mgr_tcam::line_iterator free_line_it = entries.begin();

        while (free_line_it != entries.end() && free_line_it->second != line) {
            ++free_line_it;
        }

        if (free_line_it != entries.end()) {
            table_out = table;
            logical_index = free_line_it->first;
            rc = LA_STATUS_SUCCESS;
            break;
        }
    }

    return rc;
}

la_status
ctm_mgr_tcam::allocate_line_in_range(table_desc table,
                                     line_desc start_line,
                                     line_desc end_line,
                                     const tcams_container& tcams_to_avoid,
                                     line_desc& out_line)
{
    la_status ret_stat = LA_STATUS_EOUTOFRANGE;

    const tcams_container& eligibale_tcams = get_eligible_tcams_for_table(table);

    tcams_container::const_iterator first_tcam = find(eligibale_tcams.begin(), eligibale_tcams.end(), start_line.tcam_id);
    dassert_crit(first_tcam != eligibale_tcams.end());
    tcams_container::const_iterator last_tcam = find(eligibale_tcams.begin(), eligibale_tcams.end(), end_line.tcam_id);
    dassert_crit(last_tcam != eligibale_tcams.end());

    // search over all tcams in range
    for (tcams_container::const_iterator tcam_it = first_tcam; tcam_it != std::next(last_tcam); tcam_it++) {
        bool is_tcam_to_avoid = contains(tcams_to_avoid, *tcam_it);
        if (is_tcam_to_avoid) {
            continue;
        }

        line_desc first_line((tcam_it == first_tcam) ? start_line.line : 0, *tcam_it);
        line_desc last_line((tcam_it == last_tcam) ? end_line.line : static_cast<size_t>(BANK_SIZE), *tcam_it);

        if (!is_table_wide(table)) {
            ctm_tcam_line_mgr& line_mgr = m_line_mgr[(*tcam_it)];

            size_t free_line = line_mgr.get_first_free_line_in_range(first_line.line, last_line.line);

            if (free_line >= BANK_SIZE) {
                continue;
            }

            line_mgr.allocate_line(free_line);
            out_line.line = free_line;
            out_line.tcam_id = (*tcam_it);

            ret_stat = LA_STATUS_SUCCESS;
            break;
        } else if (is_table_wide(table)) {
            out_line = find_free_wide_line_in_tcam(first_line, last_line);

            // Take note that this if implies that all of the line_managers have the same max capacity.
            if (out_line.line >= BANK_SIZE) {
                continue;
            }

            tcam_desc lsb_tcam = out_line.tcam_id;
            lsb_tcam.tcam_idx = m_ctm_config_tcam->get_lsb_tcam(out_line.tcam_id.tcam_idx);

            const tcam_desc& msb_tcam = out_line.tcam_id;
            dassert_crit(out_line.tcam_id.tcam_idx != lsb_tcam.tcam_idx);

            ctm_tcam_line_mgr& lsb_line_mgr = m_line_mgr[lsb_tcam];
            ctm_tcam_line_mgr& msb_line_mgr = m_line_mgr[msb_tcam];

            lsb_line_mgr.allocate_line(out_line.line);
            msb_line_mgr.allocate_line(out_line.line);
            ret_stat = LA_STATUS_SUCCESS;
            break;
        }
    }

    return ret_stat;
}

// CTM TCAMs are either:
// - LPM TCAMs, which are 1024x40, to construct 512x160 from 4 halfs of two TCAMs
// - ACL TCAMs, which are 512x160
void
ctm_mgr_tcam::append_ctm_tcam(tcam_section& section, size_t ring_idx, size_t subring_idx, size_t tcam_idx)
{
    if (ring_idx == IDX_INVAL || tcam_idx == MEM_IDX_INVAL) {
        return;
    }

    std::vector<lld_memory_scptr> tcams = m_block_mapper.get_ctm_tcam(ring_idx, subring_idx, tcam_idx);
    if (tcams.size() == 1) {
        // ACL TCAM
        physical_tcam tcam_desc = {.start_line = 0, .width = TCAM_WIDTH_ACL, .memories = {}};
        tcam_desc.memories.push_back(tcams[0]);
        section.tcams.push_back(tcam_desc);
    } else {
        // LPM TCAM
        dassert_crit(tcams.size() == 2);
        physical_tcam tcam_desc0 = {.start_line = 0, .width = TCAM_WIDTH_LPM, .memories = {}};
        tcam_desc0.memories.push_back(tcams[0]);
        section.tcams.push_back(tcam_desc0);

        physical_tcam tcam_desc1 = {.start_line = BANK_SIZE, .width = TCAM_WIDTH_LPM, .memories = {}};
        tcam_desc1.memories.push_back(tcams[0]);
        section.tcams.push_back(tcam_desc1);

        physical_tcam tcam_desc2 = {.start_line = 0, .width = TCAM_WIDTH_LPM, .memories = {}};
        tcam_desc2.memories.push_back(tcams[1]);
        section.tcams.push_back(tcam_desc2);

        physical_tcam tcam_desc3 = {.start_line = BANK_SIZE, .width = TCAM_WIDTH_LPM, .memories = {}};
        tcam_desc3.memories.push_back(tcams[1]);
        section.tcams.push_back(tcam_desc3);
    }
}

void
ctm_mgr_tcam::append_ctm_sram(tcam_section& section, size_t ring_idx, size_t subring_idx, size_t sram_idx, size_t offset)
{
    if (ring_idx == IDX_INVAL || sram_idx == MEM_IDX_INVAL) {
        return;
    }

    std::vector<lld_memory_scptr> srams = m_block_mapper.get_ctm_sram(ring_idx, subring_idx, sram_idx);
    dassert_crit(srams.size() == 1);
    physical_sram sram_desc = {.start_line = offset, .offset = 0, .width = SRAM_WIDTH, .memories = {}};
    sram_desc.memories.push_back(srams[0]);
    section.srams.push_back(sram_desc);
}

memory_tcam&
ctm_mgr_tcam::get_memory_tcam(const tcam_desc& tcam_id, const table_desc& table)
{
    memory_map& mem_tcams = (!is_table_wide(table)) ? m_mem_tcam_160 : m_mem_tcam_320;
    dassert_crit(contains(mem_tcams, tcam_id));
    return mem_tcams.find(tcam_id)->second;
}

group_desc
ctm_mgr_tcam::get_narrow_group_on_tcam(const tcam_desc& tcam) const
{
    group_vec groups = m_ctm_config_tcam->get_groups_by_tcam(tcam);

    for (group_desc& group : groups) {
        if (!group.is_wide()) {
            // if the group is narrow return it. There will be only one group of this kind on the tcams.
            return group;
        }
    }

    return group_desc(); // set to invalid in the def constructor.
}

group_desc
ctm_mgr_tcam::get_wide_group_on_tcams(const tcams_container& tcams) const
{
    for (const tcam_desc& tcam : tcams) {
        group_vec groups = m_ctm_config_tcam->get_groups_by_tcam(tcam);

        for (group_desc& group : groups) {
            if (group.is_wide()) {
                return group;
            }
        }
    }

    return group_desc();
}

groups_container
ctm_mgr_tcam::get_narrow_groups(const group_desc& wide_group) const
{
    groups_container narrow_groups;

    const group_desc& msb_subgroup = m_ctm_config_tcam->get_msb_narrow_group_from_wide_group(wide_group);
    const group_desc& lsb_subgroup = m_ctm_config_tcam->get_lsb_narrow_group_from_wide_group(wide_group);

    dassert_crit(msb_subgroup.slice_idx != IDX_INVAL);
    dassert_crit(lsb_subgroup.slice_idx != IDX_INVAL);

    narrow_groups.push_back(msb_subgroup);
    narrow_groups.push_back(lsb_subgroup);

    return narrow_groups;
}

bool
ctm_mgr_tcam::is_subgroup(const group_desc& wide_group, const group_desc& narrow_group) const
{
    group_desc subgroup = m_ctm_config_tcam->get_msb_narrow_group_from_wide_group(wide_group);
    if (narrow_group == subgroup) {
        return true;
    }

    subgroup = m_ctm_config_tcam->get_lsb_narrow_group_from_wide_group(wide_group);
    if (narrow_group == subgroup) {
        return true;
    }

    return false;
}

size_t
ctm_mgr_tcam::get_number_of_tcams_needed_to_fit_lines(const size_t number_of_lines) const
{
    // get number of tcams to hold number_of_lines (this is a calculation to get the rounded up number)
    return div_round_up(number_of_lines, BANK_SIZE);
}

const tcams_container&
ctm_mgr_tcam::get_eligible_lsb_tcams_for_wide_table(const table_desc& table) const
{
    const group_desc& group = get_group_for_table(table);
    return m_ctm_config_tcam->get_eligible_lsb_tcams_for_wide_group(group);
}

const tcams_container&
ctm_mgr_tcam::get_eligible_tcams_for_table(const table_desc& table) const
{
    const group_desc& group = get_group_for_table(table);
    return m_ctm_config_tcam->get_eligible_tcams_for_group(group);
}

std::vector<ctm::table_desc>
ctm_mgr_tcam::get_tables_by_tcam(const tcam_desc& tcam) const
{
    table_vec tables_vec;
    std::vector<group_desc> groups = m_ctm_config_tcam->get_groups_by_tcam(tcam);
    for (const group_desc& desc : groups) {
        table_vec tables;
        tables = get_tables_for_group(desc);
        tables_vec.insert(tables_vec.end(), tables.begin(), tables.end());
    }
    return tables_vec;
}

tcam_desc
ctm_mgr_tcam::get_paired_tcam(const tcam_desc& tcam)
{
    tcam_desc tcam_pair = tcam;
    tcam_pair.tcam_idx = m_ctm_config_tcam->get_paired_tcam(tcam.tcam_idx);
    return tcam_pair;
}

void
ctm_mgr_tcam::filter_tcams(const tcams_container& tcams, const tcams_container& tcams_to_remove, tcams_container& out_tcams)
{
    for (const tcam_desc& tcam : tcams) {
        if (!contains(tcams_to_remove, tcam)) {
            out_tcams.push_back(tcam);
        }
    }
}

void
ctm_mgr_tcam::filter_tcams_to_free(tcams_container_vec& in_out_tcams_pairs, const group_desc& group_to_make_space_for)
{
    // If either tcam from the tcam_pairs has already been removed from the group that we are allocating for. Then to avoid
    // infinite loop filter it.
    filter_tcams_pairs(in_out_tcams_pairs, m_tcam_already_freed_from_group[group_to_make_space_for]);

    // Filter out reserved tcams
    filter_tcams_pairs(in_out_tcams_pairs, m_reserved_tcams);

    // Filter out tcams of the original group to make space for
    filter_tcams_pairs(in_out_tcams_pairs, m_groups_that_cant_reallocate);
}

bool
ctm_mgr_tcam::does_tcams_contain_a_group_from_list(const tcams_container& tcams, const vector_alloc<group_desc>& groups)
{
    for (const tcam_desc& tcam : tcams) {
        const group_vec& groups_on_tcam = m_ctm_config_tcam->get_groups_by_tcam(tcam);
        for (const group_desc& group_on_tcam : groups_on_tcam) {
            if (contains(groups, group_on_tcam)) {
                return true;
            }
        }
    }

    return false;
}

void
ctm_mgr_tcam::filter_tcams_pairs(tcams_container_vec& in_out_tcams_pairs, const vector_alloc<group_desc>& groups_to_filter)
{
    tcams_container_vec::const_iterator tcam_pair_it = in_out_tcams_pairs.begin();
    while (tcam_pair_it != in_out_tcams_pairs.end()) {
        bool remove_tcam_pair = does_tcams_contain_a_group_from_list(*tcam_pair_it, groups_to_filter);

        if (remove_tcam_pair) {
            tcam_pair_it = in_out_tcams_pairs.erase(tcam_pair_it); // skip the entire pair if one of the elements has been freed.
        } else {
            ++tcam_pair_it;
        }
    }
}

void
ctm_mgr_tcam::filter_tcams_pairs(tcams_container_vec& in_out_tcams_pairs, const vector_alloc<tcam_desc>& tcams_to_remove)
{
    tcams_container_vec::const_iterator tcam_pair_it = in_out_tcams_pairs.begin();
    while (tcam_pair_it != in_out_tcams_pairs.end()) {
        bool remove_tcam_pair = false;

        for (tcam_desc tcam : *tcam_pair_it) {
            if (contains(tcams_to_remove, tcam)) {
                remove_tcam_pair = true;
                break;
            }
        }

        if (remove_tcam_pair) {
            tcam_pair_it = in_out_tcams_pairs.erase(tcam_pair_it); // skip the entire pair if one of the elements has been freed.
        } else {
            ++tcam_pair_it;
        }
    }
}

ctm_mgr_tcam::line_desc
ctm_mgr_tcam::line_desc::operator=(const line_desc& ref)
{
    line = ref.line;
    tcam_id = ref.tcam_id;
    return *this;
}

bool
ctm_mgr_tcam::line_desc::operator!=(const line_desc& ref) const
{
    if (line == ref.line && tcam_id == ref.tcam_id) {
        return false;
    } else {
        return true;
    }
}

bool
ctm_mgr_tcam::line_desc::operator<(const line_desc& ref) const
{
    if (!(tcam_id == ref.tcam_id))
        return tcam_id > ref.tcam_id;
    return line < ref.line;
}

bool
ctm_mgr_tcam::line_desc::operator>(const line_desc& ref) const
{
    return !(*this < ref) && (*this != ref);
}

void
ctm_mgr_tcam::insert_to_sorted_line_vector(vector_alloc<line_desc>& line_vector, line_desc& line)
{
    // finds position for line in the sorted vector
    vector_alloc<line_desc>::iterator position = std::upper_bound(line_vector.begin(), line_vector.end(), line);
    line_vector.insert(position, line);
}

void
ctm_mgr_tcam::create_mem_tcam(const tcam_desc& tcam)
{
    ctm_config_tcam::ctm_tcam_location location_160
        = m_ctm_config_tcam->get_tcam_160_key_hw_location(tcam.ring_idx, tcam.subring_idx, tcam.tcam_idx);
    ctm_config_tcam::ctm_tcam_location location_320
        = m_ctm_config_tcam->get_tcam_320_key_hw_location(tcam.ring_idx, tcam.subring_idx, tcam.tcam_idx);

    if (location_320.is_valid) {
        m_mem_tcam_320.erase(tcam); // if already contained, remove it, to create a different one.

        std::vector<tcam_section> sections_320;
        tcam_section section_320;
        section_320.size = BANK_SIZE;

        // append TCAM
        append_ctm_tcam(section_320, location_320.ring_idx, location_320.subring_idx, location_320.lsb_tcam_idx);
        append_ctm_tcam(section_320, location_320.ring_idx, location_320.subring_idx, location_320.msb_tcam_idx);

        // append SRAM
        if (location_320.sram_lsb_idx != MEM_IDX_INVAL) {
            append_ctm_sram(
                section_320, location_320.ring_idx, location_320.subring_idx, location_320.sram_lsb_idx, location_320.sram_offset);
        }
        append_ctm_sram(
            section_320, location_320.ring_idx, location_320.subring_idx, location_320.sram_msb_idx, location_320.sram_offset);
        // create memory
        sections_320.push_back(section_320);
        memory_tcam mem_tcam(m_ll_device, 0, 0, sections_320);
        tcam_desc tcam_msb(tcam.ring_idx, location_320.subring_idx, location_320.msb_tcam_idx);
        m_mem_tcam_320.insert(std::make_pair(tcam_msb, mem_tcam));
    }

    if (location_160.is_valid) {
        m_mem_tcam_160.erase(tcam); // if already contained, remove it, to create a different one.

        std::vector<tcam_section> sections_160;
        tcam_section section_160;
        section_160.size = BANK_SIZE;

        // append TCAM
        append_ctm_tcam(section_160, location_160.ring_idx, location_160.subring_idx, tcam.tcam_idx);
        // append SRAM
        append_ctm_sram(
            section_160, location_160.ring_idx, location_160.subring_idx, location_160.sram_lsb_idx, location_160.sram_offset);
        if (location_160.sram_msb_idx != MEM_IDX_INVAL) {
            append_ctm_sram(
                section_160, location_160.ring_idx, location_160.subring_idx, location_160.sram_msb_idx, location_160.sram_offset);
        }
        // create memory
        sections_160.push_back(section_160);
        memory_tcam mem_tcam(m_ll_device, 0, 0, sections_160);
        m_mem_tcam_160.insert(std::make_pair(tcam, mem_tcam));
    }
}

} // namespace silicon_one
