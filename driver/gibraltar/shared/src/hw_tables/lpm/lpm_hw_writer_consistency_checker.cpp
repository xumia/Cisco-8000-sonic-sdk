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

#include "lpm_hw_writer_consistency_checker.h"
#include "common/logger.h"

namespace silicon_one
{

la_status
lpm_hw_writer_consistency_checker::write_l2_sram_buckets(const size_t core_id, const lpm_bucket* bucket0, const lpm_bucket* bucket1)
{
    if (bucket0 == nullptr && bucket1 == nullptr) {
        dassert_crit(false);
        return LA_STATUS_EINVAL;
    }

    struct hw_index_bucket {
        lpm_bucket_index_t hw_index;
        const lpm_bucket* bucket;
    };
    std::array<hw_index_bucket, 2> bucket_and_hw_index;

    bucket_and_hw_index[0].bucket = bucket0;
    bucket_and_hw_index[1].bucket = bucket1;

    if (bucket0 != nullptr) {
        lpm_bucket_index_t hw_index0 = bucket0->get_hw_index();
        bucket_and_hw_index[0].hw_index = hw_index0;
        bucket_and_hw_index[1].hw_index = hw_index0 ^ 1;
    } else {
        lpm_bucket_index_t hw_index1 = bucket1->get_hw_index();
        bucket_and_hw_index[1].hw_index = hw_index1;
        bucket_and_hw_index[0].hw_index = hw_index1 ^ 1;
    }

    for (hw_index_bucket index_bucket : bucket_and_hw_index) {
        la_status status = verify_l2_bucket(core_id, index_bucket.hw_index, index_bucket.bucket);
        return_on_error(status);
        update_l2_data_structure(core_id, index_bucket.hw_index, index_bucket.bucket);
    }
    return LA_STATUS_SUCCESS;
}

la_status
lpm_hw_writer_consistency_checker::write_l2_hbm_bucket(const size_t core_id, const lpm_bucket* bucket)
{
    if (bucket == nullptr) {
        dassert_crit(false);
        return LA_STATUS_ENOTINITIALIZED;
    }

    lpm_bucket_index_t hw_index = bucket->get_hw_index();
    la_status status = verify_l2_bucket(core_id, hw_index, bucket);
    return_on_error(status);
    update_l2_data_structure(core_id, hw_index, bucket);

    return LA_STATUS_SUCCESS;
}

la_status
lpm_hw_writer_consistency_checker::write_l1_line(const size_t core_id, const lpm_bucket* bucket0, const lpm_bucket* bucket1)
{
    if (bucket0 == nullptr && bucket1 == nullptr) {
        dassert_crit(false);
        return LA_STATUS_EINVAL;
    }

    struct hw_index_bucket {
        lpm_bucket_index_t hw_index;
        const lpm_bucket* bucket;
    };
    std::array<hw_index_bucket, 2> bucket_and_hw_index;

    bucket_and_hw_index[0].bucket = bucket0;
    bucket_and_hw_index[1].bucket = bucket1;

    if (bucket0 != nullptr) {
        lpm_bucket_index_t hw_index0 = bucket0->get_hw_index();
        bucket_and_hw_index[0].hw_index = hw_index0;
        bucket_and_hw_index[1].hw_index = hw_index0 ^ 1;
    } else {
        lpm_bucket_index_t hw_index1 = bucket1->get_hw_index();
        bucket_and_hw_index[1].hw_index = hw_index1;
        bucket_and_hw_index[0].hw_index = hw_index1 ^ 1;
    }

    for (hw_index_bucket index_bucket : bucket_and_hw_index) {
        la_status status = verify_l1_bucket(core_id, index_bucket.hw_index, index_bucket.bucket);
        return_on_error(status);
        update_l1_data_structure(core_id, index_bucket.hw_index, index_bucket.bucket);
    }
    return LA_STATUS_SUCCESS;
}

la_status
lpm_hw_writer_consistency_checker::write_tcam(const size_t core_id,
                                              const tcam_cell_location& location,
                                              const lpm_key_t& key,
                                              lpm_payload_t payload,
                                              bool only_update_payload)
{
    if (only_update_payload) {
        la_status status = verify_modify_tcam_line(core_id, location, key, payload);
        return_on_error(status);
        update_tcam_data_structure_modify(core_id, location, key, payload);
    } else {
        la_status status = verify_insert_tcam_line(core_id, location, key, payload);
        return_on_error(status);
        update_tcam_data_structure_insert(core_id, location, key, payload);
    }
    return LA_STATUS_SUCCESS;
}

la_status
lpm_hw_writer_consistency_checker::invalidate_tcam(const size_t core_id, const tcam_cell_location& location, const lpm_key_t& key)
{
    la_status status = verify_remove_tcam_line(core_id, location, key);
    return_on_error(status);
    update_tcam_data_structure_remove(core_id, location);

    return LA_STATUS_SUCCESS;
}

void
lpm_hw_writer_consistency_checker::increase_l1_ref_count(const size_t core_id, lpm_bucket_index_t& hw_index_l1)
{
    m_l1_logical_representation[core_id][hw_index_l1].ref_count++;
    if (m_l1_logical_representation[core_id][hw_index_l1].ref_count == 1) {
        for (lpm_key_payload& entry : m_l1_logical_representation[core_id][hw_index_l1].entries) {
            lpm_bucket_index_t hw_index_l2 = entry.payload;
            m_l2_logical_representation[core_id][hw_index_l2].ref_count++;
        }
    }
}

void
lpm_hw_writer_consistency_checker::decrease_l1_ref_count(const size_t core_id, lpm_bucket_index_t& hw_index_l1)
{
    m_l1_logical_representation[core_id][hw_index_l1].ref_count--;

    if (m_l1_logical_representation[core_id][hw_index_l1].ref_count == 0) {
        for (lpm_key_payload& entry : m_l1_logical_representation[core_id][hw_index_l1].entries) {
            lpm_bucket_index_t hw_index_l2 = entry.payload;
            m_l2_logical_representation[core_id][hw_index_l2].ref_count--;
        }
    }
}

la_status
lpm_hw_writer_consistency_checker::write_expected_payloads_for_current_actions(const lpm_implementation_desc_vec& actions)
{
    m_expected_payload_for_key.clear();
    for (const lpm_action_desc_internal& action : actions) {
        payload_data curr_payload_data{};
        if (action.m_action == lpm_implementation_action_e::REMOVE) {
            curr_payload_data = {INVALID_PAYLOAD, false};
        } else {
            curr_payload_data = {action.m_payload, true};
        }
        m_expected_payload_for_key[action.m_key] = curr_payload_data;
    }

    return LA_STATUS_SUCCESS;
}

la_status
lpm_hw_writer_consistency_checker::update_distributor(const lpm_distributor::hardware_instruction_vec& instructions)
{
    for (const lpm_distributor::distributor_hw_instruction& curr : instructions) {
        auto type = boost::apply_visitor(lpm_distributor::visitor_distributor_hw_instruction(), curr.instruction_data);
        switch (type) {
        case lpm_distributor::distributor_hw_instruction::type_e::MODIFY_PAYLOAD:
            dassert_crit(false); // shouldn't happen to modify the payload(group) for pacific and Gb.
            return LA_STATUS_EUNKNOWN;

        case lpm_distributor::distributor_hw_instruction::type_e::INSERT: {
            la_status status = verify_insert_distributor_line(curr);
            return_on_error(status);
            update_distributor_insert(curr);
            break;
        }

        case lpm_distributor::distributor_hw_instruction::type_e::REMOVE: {
            la_status status = verify_remove_distributor_line(curr);
            return_on_error(status);
            update_distributor_remove(curr);
            break;
        }

        case lpm_distributor::distributor_hw_instruction::type_e::UPDATE_GROUP_TO_CORE: {
            la_status status = verify_modify_group_to_core_distributor_line(curr);
            return_on_error(status);
            update_distributor_modify_group_to_core(curr);
            break;
        }

        default:
            dassert_crit(false);
            return LA_STATUS_EUNKNOWN;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lpm_hw_writer_consistency_checker::lookup_distributor(const lpm_key_t& key, size_t& out_hit_core_id, size_t& out_location)
{
    size_t current_line = 0;
    for (distributor_data& distributor_line : m_distributor_logical_representation) {
        const lpm_key_t& line_key = distributor_line.key;
        bool match = is_contained(key, line_key);
        if (match) {
            size_t group_id = distributor_line.group_id;
            out_hit_core_id = m_group_to_core_id[group_id];
            out_location = current_line;
            return LA_STATUS_SUCCESS;
        }
        ++current_line;
    }
    dassert_crit(false);
    return LA_STATUS_ENOTFOUND;
}

la_status
lpm_hw_writer_consistency_checker::lookup_tcam(const lpm_key_t& key,
                                               size_t core_id,
                                               lpm_payload_t& out_hit_payload,
                                               tcam_cell_location& out_location)
{
    bool is_ipv6 = key.bit_from_msb(0);
    if (is_ipv6) {
        const size_t bankset0 = 0;
        const size_t bank0 = 0;
        for (uint32_t cell = 0; cell < NUM_OF_TCAM_HW_LINES; ++cell) {
            if (m_tcam_logical_representation[core_id][bankset0][bank0][cell].is_valid) {
                bool match = is_contained(key, m_tcam_logical_representation[core_id][bankset0][bank0][cell].key);
                if (match) {
                    out_hit_payload = m_tcam_logical_representation[core_id][bankset0][bank0][cell].payload;
                    out_location = {.bankset = bankset0, .bank = bank0, .cell = cell};
                    return LA_STATUS_SUCCESS;
                }
            }
        }

        const size_t bankset1 = 1;
        for (uint8_t bank : {0, 2}) {
            for (uint32_t cell = 0; cell < NUM_OF_TCAM_HW_LINES; ++cell) {
                if (m_tcam_logical_representation[core_id][bankset1][bank][cell].is_valid) {
                    bool match = is_contained(key, m_tcam_logical_representation[core_id][bankset1][bank][cell].key);
                    if (match) {
                        out_hit_payload = m_tcam_logical_representation[core_id][bankset1][bank][cell].payload;
                        out_location = {.bankset = bankset1, .bank = bank, .cell = cell};
                        return LA_STATUS_SUCCESS;
                    }
                }
            }
        }

    } else {
        for (uint8_t bankset = 0; bankset < NUM_OF_TCAM_BUNKSETS; ++bankset) {
            for (uint8_t bank = 0; bank < NUM_OF_TCAM_HW_BANKS; ++bank) {
                for (uint32_t cell = 0; cell < NUM_OF_TCAM_HW_LINES; ++cell) {
                    if (m_tcam_logical_representation[core_id][bankset][bank][cell].is_valid) {
                        bool match = is_contained(key, m_tcam_logical_representation[core_id][bankset][bank][cell].key);
                        if (match) {
                            out_hit_payload = m_tcam_logical_representation[core_id][bankset][bank][cell].payload;
                            out_location = {.bankset = bankset, .bank = bank, .cell = cell};
                            return LA_STATUS_SUCCESS;
                        }
                    }
                }
            }
        }
    }

    /// Not found - This is error
    dassert_crit(false);
    return LA_STATUS_ENOTFOUND;
}

la_status
lpm_hw_writer_consistency_checker::lookup_tcam_avoiding_specific_location(const lpm_key_t& key,
                                                                          size_t core_id,
                                                                          const tcam_cell_location& location_to_avoid,
                                                                          lpm_payload_t& out_hit_payload,
                                                                          tcam_cell_location& out_location)
{
    m_tcam_logical_representation[core_id][location_to_avoid.bankset][location_to_avoid.bank][location_to_avoid.cell].is_valid
        = false;

    tcam_cell_location hit_location;
    la_status status = lookup_tcam(key, core_id, out_hit_payload, hit_location);

    m_tcam_logical_representation[core_id][location_to_avoid.bankset][location_to_avoid.bank][location_to_avoid.cell].is_valid
        = true;

    return status;
}

la_status
lpm_hw_writer_consistency_checker::lookup_l1(const lpm_key_t& key,
                                             size_t core_id,
                                             lpm_bucket_index_t hw_index,
                                             lpm_payload_t& out_hit_payload,
                                             bool& out_l1_hit_default)
{
    bool once_matched = false;
    lpm_key_t longest_matched_key;
    for (lpm_key_payload& entry : m_l1_logical_representation[core_id][hw_index].entries) {
        bool match = is_contained(key, entry.key);
        if (match) {
            once_matched = true;
            if (entry.key.get_width() > longest_matched_key.get_width()) {
                longest_matched_key = entry.key;
                out_hit_payload = entry.payload;
            }
        }
    }

    if (once_matched) {
        if (m_device_type == device_type::pacific) {
            log_info(TABLES,
                     "%s: For key = %lu there is a longest prefix match with value of matched key: %lu",
                     __func__,
                     key.get_value(),
                     longest_matched_key.get_value());
        }
        out_l1_hit_default = false;
        return LA_STATUS_SUCCESS;
    }

    /// No match - Use default entry
    lpm_key_payload default_entry = m_l1_logical_representation[core_id][hw_index].m_default_entry;

    out_hit_payload = default_entry.payload;
    out_l1_hit_default = true;
    if (m_device_type == device_type::pacific) {
        log_info(TABLES,
                 "%s: For key = %lu there is no longest prefix match, so default entry is used with value of key: %lu",
                 __func__,
                 key.get_value(),
                 default_entry.key.get_value());
    }
    return LA_STATUS_SUCCESS;
}

la_status
lpm_hw_writer_consistency_checker::lookup_l2(const lpm_key_t& key,
                                             size_t core_id,
                                             lpm_bucket_index_t hw_index,
                                             lpm_payload_t& out_hit_payload)
{
    bool once_matched = false;
    lpm_key_t longest_matched_key;
    for (lpm_key_payload& entry : m_l2_logical_representation[core_id][hw_index].entries) {
        bool match = is_contained(key, entry.key);
        if (match) {
            once_matched = true;
            if (entry.key.get_width() > longest_matched_key.get_width()) {
                longest_matched_key = entry.key;
                out_hit_payload = entry.payload;
            }
        }
    }

    if (once_matched) {
        return LA_STATUS_SUCCESS;
    }

    /// No match - Use default entry
    lpm_key_payload default_entry = m_l2_logical_representation[core_id][hw_index].m_default_entry;
    out_hit_payload = default_entry.payload;
    return LA_STATUS_SUCCESS;
}

la_status
lpm_hw_writer_consistency_checker::lookup(const lpm_key_t& key, lpm_payload_t& out_hit_payload)
{
    la_status status;

    size_t core_id;
    size_t hit_location;
    status = lookup_distributor(key, core_id, hit_location);

    lpm_payload_t tcam_payload;
    tcam_cell_location tcam_location;
    status = lookup_tcam(key, core_id, tcam_payload, tcam_location);

    lpm_bucket_index_t hw_index_l1 = tcam_payload;
    lpm_payload_t l1_payload;
    bool l1_hit_default;
    status = lookup_l1(key, core_id, hw_index_l1, l1_payload, l1_hit_default);

    /// If device is pacific, final result is returned by the lookup_l1
    if (m_device_type == device_type::pacific && l1_hit_default) {
        out_hit_payload = l1_payload;
    } else {
        lpm_bucket_index_t hw_index_l2 = l1_payload;
        status = lookup_l2(key, core_id, hw_index_l2, out_hit_payload);
    }

    return status;
}

la_status
lpm_hw_writer_consistency_checker::verify_l1_bucket(const size_t core_id, lpm_bucket_index_t hw_index_l1, const lpm_bucket* bucket)
{
    size_t ref_count = m_l1_logical_representation[core_id][hw_index_l1].ref_count;
    if (ref_count == 0) {
        return LA_STATUS_SUCCESS;
    }

    lpm_key_t key = bucket->get_root();
    dassert_crit(key == m_l1_logical_representation[core_id][hw_index_l1].m_root);

    size_t core;
    size_t hit_location;
    lookup_distributor(key, core, hit_location);
    if (core_id != core) {
        return LA_STATUS_SUCCESS;
    }

    lpm_key_payload_vec old_prefixes;
    for (lpm_key_payload key_payload : m_l1_logical_representation[core_id][hw_index_l1].entries) {
        lpm_bucket_index_t hw_index_l2 = key_payload.payload;
        for (const lpm_key_payload& entry : m_l2_logical_representation[core_id][hw_index_l2].entries) {
            old_prefixes.push_back(entry);
        }
    }

    const lpm_buckets_bucket* buckets_bucket = reinterpret_cast<const lpm_buckets_bucket*>(bucket);
    lpm_key_payload_vec new_prefixes;
    for (const std::shared_ptr<silicon_one::lpm_nodes_bucket>& bucket_sptr : buckets_bucket->get_members()) {
        const lpm_bucket* bucket_l2 = bucket_sptr.get();
        lpm_bucket_index_t hw_index_l2 = bucket_l2->get_hw_index();
        for (const lpm_key_payload& entry : m_l2_logical_representation[core_id][hw_index_l2].entries) {
            new_prefixes.push_back(entry);
        }
    }

    for (const lpm_key_payload& old_entry : old_prefixes) {
        la_status status = verify_single_prefix(old_entry, new_prefixes);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

void
lpm_hw_writer_consistency_checker::update_l1_data_structure(const size_t core_id,
                                                            lpm_bucket_index_t hw_index_l1,
                                                            const lpm_bucket* bucket)
{
    size_t ref_count = m_l1_logical_representation[core_id][hw_index_l1].ref_count;
    if (ref_count > 0) {
        for (lpm_key_payload& entry : m_l1_logical_representation[core_id][hw_index_l1].entries) {
            lpm_bucket_index_t hw_index_l2 = entry.payload;
            dassert_crit(m_l2_logical_representation[core_id][hw_index_l2].ref_count > 0);
            m_l2_logical_representation[core_id][hw_index_l2].ref_count--;
        }
        if (bucket != nullptr) {
            for (lpm_key_payload& entry : bucket->get_entries()) {
                lpm_bucket_index_t hw_index_l2 = entry.payload;
                m_l2_logical_representation[core_id][hw_index_l2].ref_count++;
            }
        }
    }

    if (bucket == nullptr) {
        m_l2_logical_representation[core_id][hw_index_l1].m_root = lpm_key_t();
        m_l2_logical_representation[core_id][hw_index_l1].m_default_entry = lpm_key_payload();
        m_l2_logical_representation[core_id][hw_index_l1].entries = lpm_key_payload_vec();
    } else {
        m_l1_logical_representation[core_id][hw_index_l1].entries = bucket->get_entries();
        m_l1_logical_representation[core_id][hw_index_l1].m_default_entry = bucket->get_default_entry();
        m_l1_logical_representation[core_id][hw_index_l1].m_root = bucket->get_root();
    }
}

void
lpm_hw_writer_consistency_checker::update_l2_data_structure(const size_t core_id,
                                                            lpm_bucket_index_t hw_index,
                                                            const lpm_bucket* bucket)
{
    if (bucket == nullptr) {
        m_l2_logical_representation[core_id][hw_index].m_root = lpm_key_t();
        m_l2_logical_representation[core_id][hw_index].m_default_entry = lpm_key_payload();
        m_l2_logical_representation[core_id][hw_index].entries = lpm_key_payload_vec();
    } else {
        m_l2_logical_representation[core_id][hw_index].m_root = bucket->get_root();
        m_l2_logical_representation[core_id][hw_index].m_default_entry = bucket->get_default_entry();
        m_l2_logical_representation[core_id][hw_index].entries = bucket->get_entries();
    }
}

la_status
lpm_hw_writer_consistency_checker::verify_l2_bucket(const size_t core_id, lpm_bucket_index_t hw_index, const lpm_bucket* bucket)
{
    size_t ref_count = m_l2_logical_representation[core_id][hw_index].ref_count;
    if (ref_count == 0) {
        return LA_STATUS_SUCCESS;
    }

    lpm_key_t key = bucket->get_root();
    dassert_crit(key == m_l2_logical_representation[core_id][hw_index].m_root);

    size_t core;
    size_t hit_location;
    lookup_distributor(key, core, hit_location);
    if (core_id != core) {
        return LA_STATUS_SUCCESS;
    }

    const lpm_key_payload_vec& old_entries = m_l2_logical_representation[core_id][hw_index].entries;
    const lpm_key_payload_vec& new_entries = bucket->get_entries();
    for (const lpm_key_payload& old_entry : old_entries) {
        la_status status = verify_single_prefix(old_entry, new_entries);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
lpm_hw_writer_consistency_checker::verify_single_prefix(const lpm_key_payload& prefix, const lpm_key_payload_vec& new_entries)
{
    for (const lpm_key_payload& new_entry : new_entries) {
        if (prefix.key == new_entry.key) { /// Node exists in new bucket.
            if (prefix.payload == new_entry.payload) {
                return LA_STATUS_SUCCESS;
            } else {
                if (m_expected_payload_for_key[prefix.key].payload == new_entry.payload
                    || !m_expected_payload_for_key[prefix.key].is_valid) {
                    return LA_STATUS_SUCCESS;
                } else {
                    dassert_crit(false);
                    return LA_STATUS_EINVAL;
                }
            }
        }
    }
    /// Node doesn't exist in new bucket.
    lpm_payload_t lookup_result;
    lookup(prefix.key, lookup_result);

    if (prefix.payload != lookup_result) {
        dassert_crit(false);
        return LA_STATUS_EINVAL;
    }
    return LA_STATUS_SUCCESS;
}

void
lpm_hw_writer_consistency_checker::update_tcam_data_structure_insert(const size_t core_id,
                                                                     const tcam_cell_location& location,
                                                                     const lpm_key_t& key,
                                                                     lpm_payload_t payload)
{
    m_tcam_logical_representation[core_id][location.bankset][location.bank][location.cell].key = key;
    m_tcam_logical_representation[core_id][location.bankset][location.bank][location.cell].payload = payload;
    m_tcam_logical_representation[core_id][location.bankset][location.bank][location.cell].is_valid = true;
    lpm_bucket_index_t new_hw_index_l1 = payload;
    increase_l1_ref_count(core_id, new_hw_index_l1);
}

void
lpm_hw_writer_consistency_checker::update_tcam_data_structure_modify(const size_t core_id,
                                                                     const tcam_cell_location& location,
                                                                     const lpm_key_t& key,
                                                                     lpm_payload_t payload)
{
    lpm_bucket_index_t old_hw_index_l1
        = m_tcam_logical_representation[core_id][location.bankset][location.bank][location.cell].payload;
    decrease_l1_ref_count(core_id, old_hw_index_l1);
    m_tcam_logical_representation[core_id][location.bankset][location.bank][location.cell].payload = payload;
    m_tcam_logical_representation[core_id][location.bankset][location.bank][location.cell].is_valid = true;
    lpm_bucket_index_t new_hw_index_l1 = payload;
    increase_l1_ref_count(core_id, new_hw_index_l1);
}

void
lpm_hw_writer_consistency_checker::update_tcam_data_structure_remove(const size_t core_id, const tcam_cell_location& location)
{
    lpm_bucket_index_t hw_index_l1 = m_tcam_logical_representation[core_id][location.bankset][location.bank][location.cell].payload;
    m_tcam_logical_representation[core_id][location.bankset][location.bank][location.cell].is_valid = false;
    decrease_l1_ref_count(core_id, hw_index_l1);
}

la_status
lpm_hw_writer_consistency_checker::verify_insert_tcam_line(const size_t core_id,
                                                           const tcam_cell_location& location,
                                                           const lpm_key_t& key,
                                                           lpm_payload_t payload)
{
    if (m_tcam_logical_representation[core_id][location.bankset][location.bank][location.cell].is_valid) {
        dassert_crit(false);
        return LA_STATUS_EINVAL;
    }

    lpm_payload_t payload_parent_line;
    tcam_cell_location hit_location;
    la_status status = lookup_tcam(key, core_id, payload_parent_line, hit_location);
    return_on_error(status);

    lpm_core_tcam_allocator::tcam_cell_location_less_operator tcam_location_less_operator;
    if (tcam_location_less_operator(hit_location, location)) {
        return LA_STATUS_SUCCESS;
    }

    lpm_bucket_index_t hw_index_l1 = payload_parent_line;
    lpm_key_payload_vec old_prefixes;
    for (lpm_key_payload key_payload : m_l1_logical_representation[core_id][hw_index_l1].entries) {
        lpm_bucket_index_t hw_index_l2 = key_payload.payload;
        for (const lpm_key_payload& entry : m_l2_logical_representation[core_id][hw_index_l2].entries) {
            if (is_contained(entry.key, key)) {
                old_prefixes.push_back(entry);
            }
        }
    }

    lpm_bucket_index_t hw_index_l1_new = payload;
    lpm_key_payload_vec new_prefixes;
    for (lpm_key_payload key_payload : m_l1_logical_representation[core_id][hw_index_l1_new].entries) {
        lpm_bucket_index_t hw_index_l2 = key_payload.payload;
        for (const lpm_key_payload& entry : m_l2_logical_representation[core_id][hw_index_l2].entries) {
            new_prefixes.push_back(entry);
        }
    }

    for (const lpm_key_payload& old_entry : old_prefixes) {
        la_status status = verify_single_prefix(old_entry, new_prefixes);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
lpm_hw_writer_consistency_checker::verify_modify_tcam_line(const size_t core_id,
                                                           const tcam_cell_location& location,
                                                           const lpm_key_t& key,
                                                           lpm_payload_t payload)
{
    // If only_update_payload is true write is considered as MODIFY, else as INSERT.
    if (m_tcam_logical_representation[core_id][location.bankset][location.bank][location.cell].key != key) {
        dassert_crit(false);
        return LA_STATUS_EINVAL;
    }

    if (!m_tcam_logical_representation[core_id][location.bankset][location.bank][location.cell].is_valid) {
        dassert_crit(false);
        return LA_STATUS_EINVAL;
    }

    size_t core;
    size_t hit_location;
    lookup_distributor(key, core, hit_location);
    if (core_id != core) {
        return LA_STATUS_SUCCESS;
    }

    lpm_payload_t old_payload = m_tcam_logical_representation[core_id][location.bankset][location.bank][location.cell].payload;

    lpm_bucket_index_t hw_index_l1_old = old_payload;
    lpm_key_payload_vec old_prefixes;
    for (lpm_key_payload key_payload : m_l1_logical_representation[core_id][hw_index_l1_old].entries) {
        lpm_bucket_index_t hw_index_l2 = key_payload.payload;
        for (const lpm_key_payload& entry : m_l2_logical_representation[core_id][hw_index_l2].entries) {
            old_prefixes.push_back(entry);
        }
    }

    lpm_bucket_index_t hw_index_l1_new = payload;
    lpm_key_payload_vec new_prefixes;
    for (lpm_key_payload key_payload : m_l1_logical_representation[core_id][hw_index_l1_new].entries) {
        lpm_bucket_index_t hw_index_l2 = key_payload.payload;
        for (const lpm_key_payload& entry : m_l2_logical_representation[core_id][hw_index_l2].entries) {
            new_prefixes.push_back(entry);
        }
    }

    for (const lpm_key_payload& old_entry : old_prefixes) {
        la_status status = verify_single_prefix(old_entry, new_prefixes);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
lpm_hw_writer_consistency_checker::verify_remove_tcam_line(const size_t core_id,
                                                           const tcam_cell_location& location,
                                                           const lpm_key_t& key)
{
    if (m_tcam_logical_representation[core_id][location.bankset][location.bank][location.cell].key != key) {
        dassert_crit(false);
        return LA_STATUS_EINVAL;
    }

    size_t core;
    size_t hit_location;
    lookup_distributor(key, core, hit_location);
    if (core_id != core) {
        return LA_STATUS_SUCCESS;
    }

    lpm_payload_t old_payload = m_tcam_logical_representation[core_id][location.bankset][location.bank][location.cell].payload;

    lpm_bucket_index_t hw_index_l1_old = old_payload;
    lpm_key_payload_vec old_prefixes;
    for (lpm_key_payload key_payload : m_l1_logical_representation[core_id][hw_index_l1_old].entries) {
        lpm_bucket_index_t hw_index_l2 = key_payload.payload;
        for (const lpm_key_payload& entry : m_l2_logical_representation[core_id][hw_index_l2].entries) {
            old_prefixes.push_back(entry);
        }
    }

    lpm_payload_t payload_parent_line;
    tcam_cell_location hit_parent_location;
    la_status status = lookup_tcam_avoiding_specific_location(key, core_id, location, payload_parent_line, hit_parent_location);
    return_on_error(status);

    lpm_core_tcam_allocator::tcam_cell_location_less_operator tcam_location_less_operator;
    if (tcam_location_less_operator(location, hit_parent_location)) {
        return LA_STATUS_SUCCESS;
    }

    lpm_bucket_index_t hw_index_l1_new = payload_parent_line;
    lpm_key_payload_vec new_prefixes;
    for (lpm_key_payload key_payload : m_l1_logical_representation[core_id][hw_index_l1_new].entries) {
        lpm_bucket_index_t hw_index_l2 = key_payload.payload;
        for (const lpm_key_payload& entry : m_l2_logical_representation[core_id][hw_index_l2].entries) {
            new_prefixes.push_back(entry);
        }
    }

    for (const lpm_key_payload& old_entry : old_prefixes) {
        la_status status = verify_single_prefix(old_entry, new_prefixes);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

void
lpm_hw_writer_consistency_checker::update_distributor_insert(const lpm_distributor::distributor_hw_instruction& instruction)
{
    auto curr_data = boost::get<lpm_distributor::distributor_hw_instruction::insert_data>(instruction.instruction_data);
    size_t line = curr_data.location.cell;
    m_distributor_logical_representation[line].key = curr_data.key;
    m_distributor_logical_representation[line].group_id = curr_data.payload;
    m_distributor_logical_representation[line].is_valid = true;
}

void
lpm_hw_writer_consistency_checker::revert_distributor_insert(const lpm_distributor::distributor_hw_instruction& instruction)
{
    auto curr_data = boost::get<lpm_distributor::distributor_hw_instruction::insert_data>(instruction.instruction_data);
    size_t line = curr_data.location.cell;
    m_distributor_logical_representation[line].key = lpm_key_t();
    m_distributor_logical_representation[line].group_id = 0;
    m_distributor_logical_representation[line].is_valid = false;
}

la_status
lpm_hw_writer_consistency_checker::verify_insert_distributor_line(const lpm_distributor::distributor_hw_instruction& instruction)
{
    auto curr_data = boost::get<lpm_distributor::distributor_hw_instruction::insert_data>(instruction.instruction_data);
    size_t line = curr_data.location.cell;
    lpm_key_t key_to_insert = curr_data.key;

    if (!m_distributor_logical_representation[line].is_valid) {
        dassert_crit(false);
        return LA_STATUS_EINVAL;
    }

    size_t lookup_line_parent;
    size_t core_id;
    la_status status = lookup_distributor(key_to_insert, core_id, lookup_line_parent);
    return_on_error(status);

    if (lookup_line_parent < line) {
        return LA_STATUS_SUCCESS;
    }

    lpm_key_payload_vec old_prefixes;
    lpm_key_payload_vec new_prefixes;

    status = get_group_prefixes(core_id, key_to_insert, lookup_line_parent, old_prefixes);
    return_on_error(status);

    update_distributor_insert(instruction);
    for (const lpm_key_payload& old_entry : old_prefixes) {
        la_status status = verify_single_prefix(old_entry, new_prefixes);
        return_on_error(status);
    }
    revert_distributor_insert(instruction);

    return LA_STATUS_SUCCESS;
}

la_status
lpm_hw_writer_consistency_checker::get_group_prefixes(const size_t core_id,
                                                      const lpm_key_t& key,
                                                      size_t lookup_line_parent,
                                                      lpm_key_payload_vec& out_prefixes)
{
    for (uint8_t bankset = 0; bankset < NUM_OF_TCAM_BUNKSETS; ++bankset) {
        for (uint8_t bank = 0; bank < NUM_OF_TCAM_HW_BANKS; ++bank) {
            for (uint32_t cell = 0; cell < NUM_OF_TCAM_HW_LINES; ++cell) {
                if (!m_tcam_logical_representation[core_id][bankset][bank][cell].is_valid) {
                    continue;
                }

                if (!is_contained(m_tcam_logical_representation[core_id][bankset][bank][cell].key, key)) {
                    continue;
                }

                size_t lookup_line;

                size_t core;
                la_status status
                    = lookup_distributor(m_tcam_logical_representation[core_id][bankset][bank][cell].key, core, lookup_line);
                return_on_error(status);

                if (lookup_line != lookup_line_parent) {
                    continue;
                }

                lpm_bucket_index_t hw_index_l1 = m_tcam_logical_representation[core_id][bankset][bank][cell].payload;
                for (lpm_key_payload key_payload : m_l1_logical_representation[core_id][hw_index_l1].entries) {
                    lpm_bucket_index_t hw_index_l2 = key_payload.payload;
                    for (const lpm_key_payload& entry : m_l2_logical_representation[core_id][hw_index_l2].entries) {
                        if (is_contained(entry.key, key)) {
                            out_prefixes.push_back(entry);
                        }
                    }
                }
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

void
lpm_hw_writer_consistency_checker::update_distributor_remove(const lpm_distributor::distributor_hw_instruction& instruction)
{
    auto curr_data = boost::get<lpm_distributor::distributor_hw_instruction::remove_data>(instruction.instruction_data);
    size_t line = curr_data.location.cell;
    m_distributor_logical_representation[line].key = lpm_key_t();
    m_distributor_logical_representation[line].group_id = GROUP_ID_NONE;
    m_distributor_logical_representation[line].is_valid = false;
}

la_status
lpm_hw_writer_consistency_checker::verify_remove_distributor_line(const lpm_distributor::distributor_hw_instruction& instruction)
{
    auto curr_data = boost::get<lpm_distributor::distributor_hw_instruction::remove_data>(instruction.instruction_data);
    size_t line = curr_data.location.cell;
    lpm_key_t key_to_remove = curr_data.key;

    if (!m_distributor_logical_representation[line].is_valid) {
        dassert_crit(false);
        return LA_STATUS_EINVAL;
    }

    size_t lookup_line;
    size_t core_id;
    la_status status = lookup_distributor(key_to_remove, core_id, lookup_line);
    return_on_error(status);

    if (lookup_line > line) {
        return LA_STATUS_SUCCESS;
    }

    lpm_key_payload_vec old_prefixes;
    lpm_key_payload_vec new_prefixes;

    status = get_group_prefixes(core_id, key_to_remove, lookup_line, old_prefixes);
    return_on_error(status);

    m_distributor_logical_representation[line].is_valid = false;
    for (const lpm_key_payload& old_entry : old_prefixes) {
        la_status status = verify_single_prefix(old_entry, new_prefixes);
        return_on_error(status);
    }
    m_distributor_logical_representation[line].is_valid = true;

    return LA_STATUS_SUCCESS;
}

void
lpm_hw_writer_consistency_checker::update_distributor_modify_group_to_core(
    const lpm_distributor::distributor_hw_instruction& instruction)
{
    auto curr_data
        = boost::get<lpm_distributor::distributor_hw_instruction::update_group_to_core_data>(instruction.instruction_data);
    size_t group_id = curr_data.group_id;
    size_t core_id = curr_data.core_id;
    m_group_to_core_id[group_id] = core_id;
}

la_status
lpm_hw_writer_consistency_checker::verify_modify_group_to_core_distributor_line(
    const lpm_distributor::distributor_hw_instruction& instruction)
{
    auto curr_data
        = boost::get<lpm_distributor::distributor_hw_instruction::update_group_to_core_data>(instruction.instruction_data);
    size_t group_id = curr_data.group_id;

    // Collect prefixes for verification
    lpm_key_payload_vec old_prefixes;
    size_t current_line = 0;
    for (distributor_data& distributor_line : m_distributor_logical_representation) {
        if (m_group_to_core_id[distributor_line.group_id] != group_id) {
            ++current_line;
            continue;
        }
        la_status status = get_group_prefixes(m_group_to_core_id[group_id], distributor_line.key, current_line, old_prefixes);
        return_on_error(status);
        ++current_line;
    }
    // Update m_group_to_core_id
    size_t old_core_id = m_group_to_core_id[curr_data.group_id];
    m_group_to_core_id[curr_data.group_id] = curr_data.core_id;

    // Verify prefixes
    lpm_key_payload_vec new_prefixes;
    for (const lpm_key_payload& old_entry : old_prefixes) {
        la_status status = verify_single_prefix(old_entry, new_prefixes);
        return_on_error(status);
    }

    // Revert m_group_to_core_id
    m_group_to_core_id[curr_data.group_id] = old_core_id;

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
