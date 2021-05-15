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

#include "logical_lpm_impl.h"
#include "common/bit_utils.h"
#include "common/defines.h"
#include "common/file_utils.h"
#include "common/la_profile.h"
#include "common/logger.h"
#include "common/ranged_index_generator.h"
#include "common/resource_monitor.h"
#include "common/transaction.h"
#include "lld/ll_device.h"
#include "lpm_core.h"
#include "lpm_core_tcam.h"
#include "lpm_distributor_pacific_gb.h"
#include "lpm_dummy_distributor.h"
#include "lpm_top_hw_writer_gb.h"
#include "lpm_top_hw_writer_pacific.h"
#include <algorithm>
#include <cstdlib>
#include <limits>
#include <numeric>

using namespace std;

namespace silicon_one
{

static constexpr size_t DEFAULT_UPDATES_BETWEEN_REBALANCES = 1000;
static constexpr double DEFAULT_REBALANCE_START_FAIRNESS_THRESHOLD = 0.8;
static constexpr double DEFAULT_REBALANCE_END_FAIRNESS_THRESHOLD = 0.9;
static constexpr size_t DEFAULT_MAX_RETRIES_ON_FAIL = 1;
static constexpr size_t DEFAULT_NUM_GROUPS_TO_MERGE_WITH_PARENT = 2;
static constexpr size_t HBM_CORE_ID_WIDTH = 4;
static constexpr size_t LPM_MAX_FULLNESS = 100;
static constexpr size_t MAX_SIZE_T = std::numeric_limits<size_t>::max();

constexpr const char* JSON_ACTION_COUNTER = "actions_counter";
constexpr const char* JSON_DISTRIBUTER = "distributer";
constexpr const char* JSON_LPM_MEMBERS = "lpm_members";
constexpr const char* JSON_TREE = "tree";

logical_lpm_sptr
create_logical_lpm(const ll_device_sptr& ldevice, const lpm_settings& settings)
{
    log_debug(TABLES, "Creating logical_lpm");
    return std::make_shared<logical_lpm_impl>(ldevice, settings);
}

void
log_lpm_action(const ll_device_sptr& ll_device, const lpm_action_desc_internal action)
{
    logger& logger = logger::instance();
    la_device_id_t device_id = ll_device->get_device_id();

    if (!logger.is_logging(device_id, la_logger_component_e::TABLES, la_logger_level_e::DEBUG)) {
        return;
    }

    switch (action.m_action) {
    case lpm_implementation_action_e::INSERT:
        logger.log(device_id,
                   la_logger_component_e::TABLES,
                   la_logger_level_e::DEBUG,
                   "LPM ACTION: INSERT key 0x%s   key width %lu   payload = 0x%x",
                   action.m_key.to_string().c_str(),
                   action.m_key.get_width(),
                   action.m_payload);
        break;
    case lpm_implementation_action_e::MODIFY:
        logger.log(device_id,
                   la_logger_component_e::TABLES,
                   la_logger_level_e::DEBUG,
                   "LPM ACTION: MODIFY key 0x%s   key width %lu   payload = 0x%x",
                   action.m_key.to_string().c_str(),
                   action.m_key.get_width(),
                   action.m_payload);
        break;
    case lpm_implementation_action_e::REMOVE:
        logger.log(device_id,
                   la_logger_component_e::TABLES,
                   la_logger_level_e::DEBUG,
                   "LPM ACTION: REMOVE key 0x%s   key width %lu",
                   action.m_key.to_string().c_str(),
                   action.m_key.get_width());
        break;

    default:
        dassert_crit(false);
        break;
    }
}

logical_lpm_impl::logical_lpm_impl(const ll_device_sptr& ldevice, const lpm_settings& settings)
    : m_ll_device(ldevice),
      m_number_of_cores(settings.num_cores),
      m_number_of_groups(
          std::max(is_akpg_revision(ldevice) ? (size_t)(settings.num_distributor_lines * 1.5) : settings.num_distributor_lines,
                   (size_t)2)),
      m_has_hbm(settings.l2_max_number_of_hbm_buckets > 0),
      m_rebalance_start_fairness_threshold(DEFAULT_REBALANCE_START_FAIRNESS_THRESHOLD),
      m_rebalance_end_fairness_threshold(DEFAULT_REBALANCE_END_FAIRNESS_THRESHOLD),
      m_max_retries_on_fail(DEFAULT_MAX_RETRIES_ON_FAIL),
      m_tcam_single_width_key_weight(settings.tcam_single_width_key_weight),
      m_tcam_double_width_key_weight(settings.tcam_double_width_key_weight),
      m_tcam_quad_width_key_weight(settings.tcam_quad_width_key_weight),
      m_trap_destination(settings.trap_destination),
      m_core_tcam_utils(create_core_tcam_utils(m_ll_device)),
      m_tree(std::make_shared<bucketing_tree>(
          ldevice,
          m_number_of_cores,
          m_number_of_groups,
          settings.l2_double_bucket_size,
          (settings.l2_max_number_of_hbm_buckets > 0) ? std::min(settings.l2_max_bucket_size, settings.hbm_max_bucket_size)
                                                      : settings.l2_max_bucket_size,
          settings.l2_max_number_of_sram_buckets,
          settings.l2_max_number_of_hbm_buckets,
          settings.l2_buckets_per_sram_row,
          settings.l2_max_number_of_hbm_buckets == 0 /* double entries are not allowed if HBM is enabled*/,
          settings.l1_double_bucket_size,
          settings.l1_max_bucket_size,
          settings.l1_max_sram_buckets,
          settings.l1_buckets_per_sram_row,
          false /* l1_support_double_width_entries*/,
          settings.max_bucket_depth,
          settings.tcam_single_width_key_weight,
          settings.tcam_double_width_key_weight,
          settings.tcam_quad_width_key_weight,
          m_trap_destination,
          m_core_tcam_utils)),
      m_hw_writer(nullptr),
      m_actions_counter(0),
      m_distributor_row_width(settings.distributor_row_width),
      m_last_insert_oor_per_protocol({{false, false}}),
      m_resource_monitor(nullptr),
      m_num_tcam_cells_per_core(settings.tcam_num_banksets * 4 /* num of banks */ * settings.tcam_bank_size),
      m_num_l2_bucket_per_core((settings.l2_max_number_of_sram_buckets * settings.l2_buckets_per_sram_row / 2)
                               + settings.l2_max_number_of_hbm_buckets)
{
    std::string distributor_name = std::string("LPM Distributor");
    if (is_gibraltar_revision(ldevice)) {
        m_hw_writer.reset(new lpm_top_hw_writer_gb(ldevice));
        // because of the groups the number of entries must be even
        dassert_crit(settings.l2_double_bucket_size % 2 == 0);
        dassert_crit(settings.l2_max_bucket_size % 2 == 0);
        dassert_crit(settings.l2_double_bucket_size >= settings.l2_max_bucket_size);
        m_distributor.reset(
            new lpm_distributor_pacific_gb(distributor_name, settings.num_distributor_lines, m_distributor_row_width));
    } else if (is_pacific_revision(ldevice)) {
        m_hw_writer.reset(new lpm_top_hw_writer_pacific(ldevice));
        m_distributor.reset(
            new lpm_distributor_pacific_gb(distributor_name, settings.num_distributor_lines, m_distributor_row_width));
    } else {
        dassert_crit(false, "Unsupported device!");
    }

    // In case of one core, no need for rebalance.
    m_rebalance_interval = (m_number_of_cores == 1) ? MAX_SIZE_T : DEFAULT_UPDATES_BETWEEN_REBALANCES;
    m_load_per_core[0].assign(m_number_of_cores, 0); // IPv4
    m_load_per_core[1].assign(m_number_of_cores, 0); // IPv6
    m_load_per_group.load_per_group.resize(m_number_of_groups);

    size_t num_ipv6_indexes = (settings.num_distributor_lines == 0) ? 1 : (settings.num_distributor_lines / 2);
    m_distributor_logical_state[0 /*IPv4*/].free_indexes
        = ranged_index_generator(num_ipv6_indexes /*lower bound*/, m_number_of_groups /*upper bound*/);
    m_distributor_logical_state[1 /*IPv6*/].free_indexes
        = ranged_index_generator(0 /*lower bound*/, num_ipv6_indexes /*upper bound*/);

    for (size_t core_id = 0; core_id < m_number_of_cores; core_id++) {
        m_cores.emplace_back(std::make_shared<lpm_core>(ldevice,
                                                        core_id,
                                                        m_tree,
                                                        settings.l2_double_bucket_size,
                                                        settings.l2_max_number_of_sram_buckets,
                                                        settings.tcam_num_banksets,
                                                        settings.tcam_bank_size,
                                                        settings.tcam_max_quad_entries,
                                                        m_trap_destination,
                                                        m_core_tcam_utils));
    }

    constexpr size_t CORE_FOR_DEFAULT_GROUP = 0;

    for (size_t core_id = 0; core_id < m_number_of_cores; core_id++) {
        const lpm_core_hw_writer& core_writer = m_cores[core_id]->get_core_hw_writer();
        core_writer.write_tcam_default_row();
    }

    lpm_implementation_desc_vec actions;
    actions.reserve(2);
    // 0 - IPv4 and 1 - IPv6
    for (size_t idx : {0, 1}) {
        // Default group
        lpm_key_t default_key(idx /*prefix*/, 1);
        size_t group_idx;
        ranged_index_generator& free_indexes = m_distributor_logical_state[idx /*protocol*/].free_indexes;
        free_indexes.allocate(group_idx);
        key_to_group_core_unordered_map& key_to_group_core = m_distributor_logical_state[idx /*protocol*/].used_distributor_entries;
        key_to_group_core.insert(
            std::make_pair(default_key, lpm_core_group_data{.core_index = CORE_FOR_DEFAULT_GROUP, .group_index = group_idx}));

        if (m_hw_writer != nullptr) {
            lpm_action_desc_internal distributer_action = create_insert_modify_distributor_action_desc(
                lpm_implementation_action_e::INSERT, default_key, group_idx, CORE_FOR_DEFAULT_GROUP);
            lpm_implementation_desc_vec distributer_actions(1, distributer_action);
            lpm_distributor::hardware_instruction_vec distributor_instructions;
            la_status status = m_distributor->update(distributer_actions, distributor_instructions);
            dassert_crit(status == LA_STATUS_SUCCESS);
            m_distributor->commit();
            status = m_hw_writer->update_distributor(distributor_instructions);
            dassert_crit(status == LA_STATUS_SUCCESS);
        } else {
            // When having only 1 core there is no distributor. Therefore, no top_hw_writer.
            dassert_crit(m_number_of_cores == 1);
        }

        lpm_action_desc_internal add_group_action
            = lpm_action_desc_internal(lpm_implementation_action_e::ADD_GROUP_ROOT, default_key);
        add_group_action.m_group_id = group_idx;
        add_group_action.m_core_id = CORE_FOR_DEFAULT_GROUP;
        actions.push_back(add_group_action);
    }

    size_t failed_core;
    la_status status = update_cores(actions, failed_core);
    dassert_crit(status == LA_STATUS_SUCCESS);
}

logical_lpm_impl::~logical_lpm_impl()
{
}

logical_lpm_impl::logical_lpm_impl() : m_trap_destination(0)
{
}

const ll_device_sptr&
logical_lpm_impl::get_ll_device() const
{
    return m_ll_device;
}

la_status
logical_lpm_impl::insert(const lpm_key_t& key, lpm_payload_t payload)
{
    lpm_action_desc action(lpm_action_e::INSERT, key, payload);
    lpm_action_desc_vec_t actions(1 /* size */, action);

    size_t dummy_count_success;
    return update(actions, dummy_count_success);
}

la_status
logical_lpm_impl::remove(const lpm_key_t& key)
{
    lpm_action_desc action(lpm_action_e::REMOVE, key);
    lpm_action_desc_vec_t actions(1 /* size */, action);

    size_t dummy_count_success;
    return update(actions, dummy_count_success);
}

la_status
logical_lpm_impl::modify(const lpm_key_t& key, lpm_payload_t payload)
{
    lpm_action_desc action(lpm_action_e::MODIFY, key, payload);
    lpm_action_desc_vec_t actions(1 /* size */, action);

    size_t dummy_count_success;
    return update(actions, dummy_count_success);
}

la_status
logical_lpm_impl::update(const lpm_action_desc_vec_t& actions, size_t& out_count_success)
{
    start_profiling("LPM update");

    log_debug(TABLES, "LPM UPDATE  count = %zu", actions.size());

    out_count_success = 0;
    lpm_implementation_desc_vec internal_actions;
    internal_actions.reserve(actions.size());
    for (const lpm_action_desc& desc : actions) {
        const lpm_key_t& encoded_key = is_pacific_revision(m_ll_device) ? encode_lpm_key(desc.m_key) : desc.m_key;
        bool sram_only = desc.m_latency_sensitive && m_has_hbm;
        lpm_action_desc_internal internal_desc(desc.m_action, encoded_key, desc.m_payload, sram_only);
        log_lpm_action(m_ll_device, internal_desc);
        log_debug(
            TABLES, "LPM: encode_lpm_key(k=%s) -> k=%s", desc.m_key.to_string().c_str(), internal_desc.m_key.to_string().c_str());
        internal_actions.push_back(internal_desc);
    }

    if (m_last_insert_oor_per_protocol[0 /* IPv4 */] || m_last_insert_oor_per_protocol[1 /* IPv6 */]) {
        for (const auto& action : internal_actions) {
            if (action.m_action != lpm_implementation_action_e::INSERT) {
                continue;
            }

            const lpm_key_t& key = action.m_key;
            bool is_ipv6 = key.bit_from_msb(0);
            if (m_last_insert_oor_per_protocol[is_ipv6]) {
                return LA_STATUS_ERESOURCE;
            }
        }
    }

    size_t actions_counter_before_update = m_actions_counter;

    size_t start_index = 0;
    size_t failed_core;
    size_t count_success;
    la_status status = do_update(internal_actions, start_index, failed_core, count_success);
    if (count_success > 0) {
        out_count_success += count_success;
        if (m_resource_monitor != nullptr) {
            size_t current_size = size();
            m_resource_monitor->update_size(current_size);
        }
    }

    log_debug(TABLES, "LPM UPDATE count = %zu, out_count_success=%zu", actions.size(), out_count_success);

    dassert_slow(sanity());

    if (status == LA_STATUS_SUCCESS) {
        dassert_crit(internal_actions.size() == out_count_success);
        return LA_STATUS_SUCCESS;
    }

    if (status != LA_STATUS_ERESOURCE) {
        return status;
    }

    if (m_number_of_cores == 1) {
        // In case of OOR and one core and emergency rebalance, nothing we can do, no need of rebalance.
        return LA_STATUS_ERESOURCE;
    }

    dassert_crit(failed_core < m_number_of_cores);

    // Update has failed due to resource exhaustion, rebalance and retry.
    for (size_t try_num = 0; try_num < m_max_retries_on_fail; try_num++) {
        log_debug(TABLES, "LPM Rebalance triggered after failed update. try %zu/%zu", try_num, m_max_retries_on_fail);
        status = rebalance(failed_core);
        return_on_error(status);

        m_actions_counter = actions_counter_before_update + out_count_success;
        start_index = out_count_success;
        status = do_update(internal_actions, start_index, failed_core, count_success);
        if (count_success > 0) {
            out_count_success += count_success;
            if (m_resource_monitor != nullptr) {
                size_t current_size = size();
                m_resource_monitor->update_size(current_size);
            }
        }

        dassert_slow(sanity());

        if (status == LA_STATUS_SUCCESS) {
            log_debug(TABLES,
                      "LPM UPDATE after emergency rebalance count = %zu, out_count_success=%zu",
                      actions.size(),
                      out_count_success);
            dassert_crit(internal_actions.size() == out_count_success);
            return LA_STATUS_SUCCESS;
        }

        if (status != LA_STATUS_ERESOURCE) {
            break;
        }

        dassert_crit(failed_core < m_number_of_cores);
    }

    // If retry loop was completed, it means we still fail with resource error.
    dassert_crit(status != LA_STATUS_SUCCESS);

    log_debug(TABLES, "LPM UPDATE done count = %zu, out_count_success=%zu", actions.size(), out_count_success);
    return status;
}

la_status
logical_lpm_impl::do_update(const lpm_implementation_desc_vec& actions,
                            size_t start_index,
                            size_t& out_failed_core,
                            size_t& out_count_success)
{
    out_count_success = 0;
    size_t remaining_actions = actions.size() - start_index;

    while (remaining_actions > 0) {
        size_t next_rebalance = round_up(m_actions_counter + 1, m_rebalance_interval) - m_actions_counter;
        size_t current_num_actions = std::min(remaining_actions, next_rebalance);
        size_t end_index = start_index + current_num_actions;

        lpm_implementation_desc_vec current_iteration_actions;
        current_iteration_actions.insert(
            current_iteration_actions.begin(), actions.begin() + start_index, actions.begin() + end_index);
        la_status status = update_cores(current_iteration_actions, out_failed_core);
        return_on_error(status);

        start_index += current_num_actions;
        out_count_success += current_num_actions;
        m_actions_counter += current_num_actions;
        remaining_actions -= current_num_actions;

        if (m_actions_counter % m_rebalance_interval == 0) {
            log_debug(TABLES,
                      "LPM Rebalance triggered (periodic).  actions %zu  rebalance interval %zu",
                      m_actions_counter,
                      m_rebalance_interval);
            status = rebalance(CORE_ID_NONE);
            log_debug(TABLES, "Periodic load balance attempt ended with status = %d", status.value());

            if ((status != LA_STATUS_SUCCESS) && (status != LA_STATUS_ERESOURCE)) {
                return status;
            }
        }

        dassert_slow(sanity());
    }

    return LA_STATUS_SUCCESS;
}

la_status
logical_lpm_impl::update_cores(const lpm_implementation_desc_vec& actions, size_t& out_failed_core)
{
    start_profiling("LPM action update");

    log_debug(TABLES, "%s: Start running", __func__);

    out_failed_core = CORE_ID_NONE;

    transaction txn;
    txn.on_fail([&]() {
        if (txn.status == LA_STATUS_ERESOURCE) {
            update_last_insert_oor_per_protocol(actions);
        }
    });

    lpm_implementation_desc_vec_levels_cores cores_actions;
    txn.status = m_tree->update(actions, cores_actions, out_failed_core);
    return_on_error(txn.status);

    txn.on_fail([=]() { m_tree->withdraw(); });

    for (size_t core_id = 0; core_id < m_number_of_cores; core_id++) {
        lpm_implementation_desc_vec& l1_actions_for_core = cores_actions[core_id][LEVEL1];
        txn.status = m_cores[core_id]->update_tcam(l1_actions_for_core);
        if (txn.status != LA_STATUS_SUCCESS) {
            log_err(TABLES, "Core #%lu TCAM update failed", core_id);
            out_failed_core = core_id;
            return txn.status;
        }

        txn.on_fail([=]() { m_cores[core_id]->withdraw(); });
    }

    m_tree->commit();
    for (size_t core_id = 0; core_id < m_number_of_cores; core_id++) {
        txn.status = m_cores[core_id]->commit_hw_updates(cores_actions[core_id]);
        if (txn.status != LA_STATUS_SUCCESS) {
            log_err(TABLES, "Core #%lu HW commit failed", core_id);
            return txn.status;
        }
    }

    // We reset the last rebalance fail flag since after update rebalance might succeed again.
    m_last_insert_oor_per_protocol.fill(false);
    log_debug(TABLES, "%s: m_last_insert_oor_per_protocol is cleared", __func__);
    log_debug(TABLES, "%s: Ended successfully", __func__);

    return LA_STATUS_SUCCESS;
}

void
logical_lpm_impl::update_last_insert_oor_per_protocol(const lpm_implementation_desc_vec& actions)
{
    bool is_v6_failure = false;
    for (const auto& action : actions) {
        const lpm_key_t& key = action.m_key;
        if (action.m_action != lpm_implementation_action_e::INSERT) {
            continue;
        }

        bool is_ipv6 = key.bit_from_msb(0);
        if (is_ipv6) {
            // Assuming V6 use more resources than V4 so if we have both - V6 is the reason for OOR.
            is_v6_failure = true;
            break;
        }
    }

    m_last_insert_oor_per_protocol[is_v6_failure] = true;
}

la_status
logical_lpm_impl::lookup(const lpm_key_t& key, lpm_key_t& out_hit_key, lpm_payload_t& out_hit_payload) const
{
    const lpm_key_t& encoded_key = is_pacific_revision(m_ll_device) ? encode_lpm_key(key) : key;
    lpm_core_group_data core_group_idx;
    get_containing_group_and_core(encoded_key, core_group_idx);
    size_t core_id = core_group_idx.core_index;
    if (core_id == CORE_ID_NONE) {
        return LA_STATUS_EUNKNOWN;
    }

    la_status status = m_cores[core_id]->lookup(encoded_key, out_hit_key, out_hit_payload);
    return_on_error(status);

    if (is_pacific_revision(m_ll_device)) {
        out_hit_key = decode_lpm_key(out_hit_key);
    }

    return LA_STATUS_SUCCESS;
}

void
logical_lpm_impl::get_containing_group_and_core(const lpm_key_t& key, lpm_core_group_data& out_core_group) const
{
    out_core_group.group_index = GROUP_ID_NONE;
    out_core_group.core_index = CORE_ID_NONE;
    if (key.get_width() == 0) {
        // key of width == 0 is illegal, we return failing value
        return;
    }

    lpm_key_t hit_key;
    lpm_payload_t hit_payload;
    distributor_cell_location unused_hit_location;

    la_status status = m_distributor->lookup_tcam_tree(key, hit_key, hit_payload, unused_hit_location);
    if (status != LA_STATUS_SUCCESS) {
        log_err(TABLES, "Requested key 0x%s not found in distributor TCAM", key.to_string().c_str());
        return;
    }

    size_t protocol_idx = key.bit_from_msb(0);
    const key_to_group_core_unordered_map& key_to_group_core = m_distributor_logical_state[protocol_idx].used_distributor_entries;
    const auto& it = key_to_group_core.find(hit_key);
    dassert_crit(it != key_to_group_core.end());

    out_core_group.group_index = it->second.group_index;
    out_core_group.core_index = it->second.core_index;
    dassert_crit(out_core_group.group_index != GROUP_ID_NONE);
    dassert_crit(out_core_group.core_index != CORE_ID_NONE);

    log_xdebug(TABLES,
               "%s(key = 0x%s, width = %zu) = %zu",
               __func__,
               key.to_string().c_str(),
               key.get_width(),
               out_core_group.group_index);
}

size_t
logical_lpm_impl::get_core_index_by_group(size_t group_index) const
{
    if (group_index == GROUP_ID_NONE) {
        return CORE_ID_NONE;
    }

    const auto& group_to_core = m_tree->get_group_to_core();
    return group_to_core[group_index];
}

const lpm_distributor&
logical_lpm_impl::get_distributer() const
{
    return *(m_distributor);
}

lpm_core_scptr
logical_lpm_impl::get_core(size_t idx) const
{
    if (idx == CORE_ID_NONE) {
        return nullptr;
    }

    return m_cores[idx];
}

bucketing_tree_scptr
logical_lpm_impl::get_tree() const
{
    return m_tree;
}

size_t
logical_lpm_impl::get_num_cores() const
{
    return m_number_of_cores;
}

// Calculate number of entries in each core
vector_alloc<size_t>
logical_lpm_impl::get_cores_utilization() const
{
    vector_alloc<size_t> utilization(m_number_of_cores, 0);
    for (lpm_ip_protocol_e protocol : {lpm_ip_protocol_e::IPV4, lpm_ip_protocol_e::IPV6}) {
        vector_alloc<size_t> protocol_utilization;
        m_tree->calculate_prefixes_load_per_core(protocol, protocol_utilization);
        for (size_t core = 0; core < m_number_of_cores; core++) {
            utilization[core] += protocol_utilization[core];
        }
    }

    return utilization;
}

void
logical_lpm_impl::set_rebalance_interval(size_t num_of_updates)
{
    if (m_number_of_cores == 1) {
        log_err(TABLES, "LPM: set rebalance interval unsupported for one core.");
        return;
    }

    log_debug(TABLES, "LPM: set rebalance interval: %zu", num_of_updates);
    m_rebalance_interval = num_of_updates;
}

size_t
logical_lpm_impl::get_rebalance_interval() const
{
    return m_rebalance_interval;
}

void
logical_lpm_impl::set_max_retries_on_fail(size_t max_retries)
{
    m_max_retries_on_fail = max_retries;
}

void
logical_lpm_impl::set_rebalance_start_fairness_threshold(double threshold)
{
    log_debug(TABLES, "LPM: set rebalance start ratio: %f", threshold);
    m_rebalance_start_fairness_threshold = threshold;
}

double
logical_lpm_impl::get_rebalance_start_fairness_threshold() const
{
    return m_rebalance_start_fairness_threshold;
}

void
logical_lpm_impl::set_rebalance_end_fairness_threshold(double threshold)
{
    log_debug(TABLES, "LPM: set rebalance end ratio: %f", threshold);
    m_rebalance_end_fairness_threshold = threshold;
}

double
logical_lpm_impl::get_rebalance_end_fairness_threshold() const
{
    return m_rebalance_end_fairness_threshold;
}

size_t
logical_lpm_impl::get_max_retries_on_fail()
{
    return m_max_retries_on_fail;
}

la_status
logical_lpm_impl::rebalance()
{
    if (m_number_of_cores == 1) {
        log_debug(TABLES, "Rebalance skipped due to one core.");
        return LA_STATUS_SUCCESS;
    }

    return rebalance(CORE_ID_NONE);
}

void
logical_lpm_impl::log_distibutor() const
{
    if (logger::instance().is_logging(m_ll_device->get_device_id(), la_logger_component_e::TABLES, la_logger_level_e::DEBUG)) {
        return;
    }

    vector_alloc<lpm_key_t> group_to_key(m_number_of_groups, lpm_key_t());
    vector_alloc<size_t> group_to_core(m_number_of_groups, CORE_ID_NONE);
    for (const auto& distributr_logical_state : m_distributor_logical_state) {
        const key_to_group_core_unordered_map& key_to_group_core = distributr_logical_state.used_distributor_entries;
        for (const auto& it : key_to_group_core) {
            size_t group_idx = it.second.group_index;
            const lpm_key_t& key = it.first;
            group_to_key[group_idx] = key;
            group_to_core[group_idx] = it.second.core_index;
        }
    }

    log_debug(TABLES, "Distributor State");
    for (size_t group_idx = 0; group_idx < m_number_of_groups; group_idx++) {
        const lpm_key_t& key = group_to_key[group_idx];
        size_t core_idx = group_to_core[group_idx];
        if (core_idx != CORE_ID_NONE) {
            log_debug(
                TABLES, "group %-4zu  core %-4zu: Key %-40s/%zu", group_idx, core_idx, key.to_string().c_str(), key.get_width());
        }
    }
}

la_status
logical_lpm_impl::rebalance(size_t src_core)
{
    start_profiling("Rebalance");

    // In case of one core, we should never get to rebalance.
    dassert_crit(m_number_of_cores != 1);

    log_distibutor();

    calculate_cores_utilization();

    // Init all groups to invalid.
    m_load_per_group.is_valid = vector_alloc<bool>(m_number_of_groups, false);

    la_status status_v4 = rebalance(lpm_ip_protocol_e::IPV4, src_core);
    if ((status_v4 != LA_STATUS_SUCCESS) && (status_v4 != LA_STATUS_ERESOURCE)) {
        return status_v4;
    }

    la_status status_v6 = rebalance(lpm_ip_protocol_e::IPV6, src_core);
    if ((status_v6 != LA_STATUS_SUCCESS) && (status_v6 != LA_STATUS_ERESOURCE)) {
        return status_v6;
    }

    dassert_slow(sanity());

    if ((status_v4 == LA_STATUS_ERESOURCE) && (status_v6 == LA_STATUS_ERESOURCE)) {
        return LA_STATUS_ERESOURCE;
    }

    return LA_STATUS_SUCCESS;
}

// Rebalance is the main function that performs load balancing.
// Rebalance pseudocode:
//      -while (no group move between cores can lower max core utilization)
//          -create new group instead of an existing one,
//           in a way that will lower the maximum group utilization as possible.
//          -if no change, break loop.
//      -move group between cores in a way that will lower the maximum core utilization as possible.
la_status
logical_lpm_impl::rebalance(lpm_ip_protocol_e protocol, size_t src_core)
{
    log_debug(TABLES, "Rebalance starting (IPv%d)  src_core = %zu", (protocol == lpm_ip_protocol_e::IPV4) ? 4 : 6, src_core);

    bool force_rebalance = (src_core != CORE_ID_NONE); // if src_core is specified, we're in emergency.
    bool start_rebalance = force_rebalance || !are_cores_balanced(protocol, m_rebalance_start_fairness_threshold);

    if (!start_rebalance) {
        log_debug(TABLES, "Skipping rebalance this time. Already balanced");
        return LA_STATUS_SUCCESS;
    }

    size_t max_rebalance_iterations = force_rebalance ? 1 : m_number_of_cores;

    for (size_t i = 0; i < max_rebalance_iterations; i++) {
        bool did_improve;
        la_status status = move_a_subtree_to_least_utilized_core(protocol, src_core, did_improve);
        return_on_error(status, TABLES, DEBUG, "Rebalance failed");

        if (!did_improve) {
            log_debug(TABLES, "LPM Rebalance ending because it is not improving balance anymore.");
            break;
        }

        bool balanced = are_cores_balanced(protocol, m_rebalance_end_fairness_threshold);
        if (balanced) {
            log_debug(TABLES, "LPM Rebalance ended at iteration=%lu because cores are now sufficiently balanced", i);
            break;
        }
    }

    log_debug(TABLES, "Rebalance done");
    return LA_STATUS_SUCCESS;
}

double
logical_lpm_impl::compute_cores_fairness(lpm_ip_protocol_e protocol) const
{
    size_t most_utilized_core;
    size_t least_utilized_core;
    size_t max_core_utilization;
    size_t min_core_utilization;
    get_most_and_least_utilized_cores(
        protocol, most_utilized_core, least_utilized_core, max_core_utilization, min_core_utilization);

    dassert_crit(min_core_utilization <= max_core_utilization);

    double fairness = (double)(min_core_utilization + 1) / (max_core_utilization + 1);
    return fairness;
}

bool
logical_lpm_impl::are_cores_balanced(lpm_ip_protocol_e protocol, double fairness_threshold) const
{

    double fairness = compute_cores_fairness(protocol);
    return fairness >= fairness_threshold;
}

// Move a single group between cores, to minimize the maximum core utilization
la_status
logical_lpm_impl::move_group_to_core(lpm_ip_protocol_e protocol, const lpm_key_t& key_to_move, size_t to_core)
{
    size_t protocol_idx = static_cast<size_t>(protocol);
    key_to_group_core_unordered_map& key_to_group_core = m_distributor_logical_state[protocol_idx].used_distributor_entries;
    const auto& group_to_core_it = key_to_group_core.find(key_to_move);
    dassert_crit(group_to_core_it != key_to_group_core.end());

    size_t group_to_move = group_to_core_it->second.group_index;
    dassert_crit(group_to_move != GROUP_ID_NONE);
    size_t from_core = group_to_core_it->second.core_index;
    dassert_crit(from_core != to_core);

    log_debug(TABLES,
              "%s: (key_to_move = %s/%zu, from_core %zu, to_core = %zu, group_to_move %zu)",
              __func__,
              key_to_move.to_string().c_str(),
              key_to_move.get_width(),
              from_core,
              to_core,
              group_to_move);

    lpm_action_desc_internal move_group_action(lpm_implementation_action_e::MODIFY_GROUP_TO_CORE, key_to_move);
    move_group_action.m_group_id = group_to_move;
    move_group_action.m_core_id = to_core;

    resource_type resource = m_resource_type_to_use_for_rebalance[protocol_idx];
    bool load_is_prefixes = (resource == resource_type::PREFIXES);

    lpm_action_desc_internal distributer_action = create_insert_modify_distributor_action_desc(
        lpm_implementation_action_e::MODIFY_GROUP_TO_CORE, key_to_move, group_to_move, to_core);
    lpm_implementation_desc_vec distributer_actions(1, distributer_action);

    // After moving entries between cores we want to recalculate to_core and from_core utilization for the next iteration.
    // If load_is_tcam we don't need to do it because we can get it from the core's TCAM using O(1) query. In that case we don't
    // need to know the group's size.
    // If load_is_prefixes we don't maintain entries-per-group so we must calculate the group's size in order to update the cores'
    // utilization.
    size_t group_load = (load_is_prefixes) ? m_tree->get_load_of_group(group_to_move, key_to_move, resource) : 0;

    la_status status = move_entries_between_cores(move_group_action, from_core, to_core, distributer_actions);
    return_on_error(status,
                    TABLES,
                    DEBUG,
                    "%s: Failed to move group=%zu from_core=%zu to_core=%zu",
                    __func__,
                    group_to_move,
                    from_core,
                    to_core);

    // Move group to target core
    group_to_core_it->second.core_index = to_core;

    // update state
    if (load_is_prefixes) {
        dassert_crit(m_load_per_core[protocol_idx][from_core] >= group_load);
        m_load_per_core[protocol_idx][from_core] -= group_load;
        m_load_per_core[protocol_idx][to_core] += group_load;
    } else {
        m_load_per_core[protocol_idx][from_core] = get_core_tcam_load(protocol, from_core);
        m_load_per_core[protocol_idx][to_core] = get_core_tcam_load(protocol, to_core);
    }

    dassert_slow(sanity());

    return LA_STATUS_SUCCESS;
}

// Delete a single group and break another group to two groups.
// The intention is to even out the src_core and least_utilized_core.
la_status
logical_lpm_impl::move_a_subtree_to_least_utilized_core(lpm_ip_protocol_e protocol, size_t src_core, bool& did_improve)
{
    double fairness_before = compute_cores_fairness(protocol);

    size_t protocol_idx = static_cast<size_t>(protocol);
    const ranged_index_generator& free_indexes = m_distributor_logical_state[protocol_idx].free_indexes;
    bool have_free_group = (free_indexes.available() != 0);
    if (!have_free_group) {
        la_status status = free_a_group_by_merging_two_groups(protocol);
        if (status == LA_STATUS_SUCCESS) {
            have_free_group = true;
        } else if (status != LA_STATUS_ERESOURCE) {
            return status;
        }
    }

    if (have_free_group) {
        log_debug(TABLES, "%s: will move a subtree from core src_core using free group", __func__);
        la_status status = move_a_subtree_to_least_utilized_core_using_new_group(protocol, src_core);
        return_on_error(status);
    } else {
        log_debug(TABLES, "%s: no free group, trying to move whole group from src_core", __func__);
        la_status status = move_a_whole_group_to_least_utilized_core(protocol, src_core);
        return_on_error(status);
    }

    did_improve = false;
    double fairness_after = compute_cores_fairness(protocol);

    if (fairness_after > fairness_before) {
        did_improve = true;
    }

    return LA_STATUS_SUCCESS;
}

la_status
logical_lpm_impl::move_a_whole_group_to_least_utilized_core(lpm_ip_protocol_e protocol, size_t src_core)
{
    size_t most_utilized_core;
    size_t least_utilized_core;
    size_t unused_max_core_utilization;
    size_t unused_min_core_utilization;
    get_most_and_least_utilized_cores(
        protocol, most_utilized_core, least_utilized_core, unused_max_core_utilization, unused_min_core_utilization);

    size_t from_core = (src_core == CORE_ID_NONE) ? most_utilized_core : src_core;

    size_t protocol_idx = static_cast<size_t>(protocol);
    for (const auto& group_core_it : m_distributor_logical_state[protocol_idx].used_distributor_entries) {
        size_t group_index = group_core_it.second.group_index;
        size_t group_core = group_core_it.second.core_index;
        if (group_core != from_core) {
            continue;
        }

        if (group_core == least_utilized_core) { // nothing to move
            continue;
        }

        const lpm_key_t& group_key = group_core_it.first;
        la_status status = move_group_to_core(protocol, group_key, least_utilized_core);
        if (status != LA_STATUS_ERESOURCE) {
            log_debug(TABLES, "%s: failed to move group %zu to core %zu", __func__, group_index, least_utilized_core);
            return status;
        }
    }

    log_debug(TABLES, "%s: failed to find a group to move from core %zu to core %zu", __func__, from_core, least_utilized_core);
    return LA_STATUS_ERESOURCE;
}

la_status
logical_lpm_impl::free_a_group_by_merging_two_groups(lpm_ip_protocol_e protocol)
{
    vector_alloc<bool> group_exclude_list(m_number_of_groups, false);

    for (size_t i = 0; i < DEFAULT_NUM_GROUPS_TO_MERGE_WITH_PARENT; i++) {
        lpm_key_t group_key;
        lpm_core_group_data from_group_core;
        lpm_core_group_data to_group_core;
        find_optimal_group_root_to_be_merged_with_parent(protocol, group_exclude_list, group_key, from_group_core, to_group_core);

        size_t from_group = from_group_core.group_index;
        // no remaining groups to try
        if (from_group == GROUP_ID_NONE) {
            log_debug(TABLES, "%s: No remaining groups to try to free. Sorry", __func__);
            break;
        }

        la_status status = merge_group_with_parent(protocol, group_key, from_group_core, to_group_core);
        if (status == LA_STATUS_SUCCESS) {
            return LA_STATUS_SUCCESS;
        }

        if (status == LA_STATUS_ERESOURCE) {
            // this group failed. let's try another one
            log_debug(TABLES, "%s: blacklisting group %zu because we failed to move it", __func__, from_group);
            group_exclude_list[from_group] = true;
        } else {
            return status;
        }
    }

    log_debug(TABLES, "%s: giving up. really tried hard. sorry", __func__);
    return LA_STATUS_ERESOURCE;
}

la_status
logical_lpm_impl::merge_group_with_parent(lpm_ip_protocol_e protocol,
                                          const lpm_key_t& group_root_key,
                                          const lpm_core_group_data& from_group_core,
                                          const lpm_core_group_data& to_group_core)
{
    log_debug(TABLES, "%s(protocol = %s)", __func__, protocol == lpm_ip_protocol_e::IPV6 ? "IPV6" : "IPV4");

    size_t group_to_merge = from_group_core.group_index;
    size_t group_to_move_entries_to = to_group_core.group_index;
    size_t from_core = from_group_core.core_index;
    size_t to_core = to_group_core.core_index;
    dassert_crit(group_to_merge != group_to_move_entries_to);
    dassert_crit(group_to_merge != GROUP_ID_NONE);
    dassert_crit(from_core != CORE_ID_NONE);
    dassert_crit(to_core != CORE_ID_NONE);

    size_t protocol_idx = static_cast<size_t>(protocol);

    lpm_action_desc_internal distributer_action(lpm_implementation_action_e::REMOVE, group_root_key);
    lpm_implementation_desc_vec distributer_actions(1, distributer_action);

    lpm_action_desc_internal remove_group_root_action(lpm_implementation_action_e::REMOVE_GROUP_ROOT, group_root_key);

    resource_type resource = m_resource_type_to_use_for_rebalance[protocol_idx];
    bool load_is_prefixes = (resource == resource_type::PREFIXES);

    // After moving entries between cores we want to recalculate to_core and from_core utilization for the next iteration.
    // If load_is_tcam we don't need to do it because we can get it from the core's TCAM using O(1) query. In that case we don't
    // need to know the group's size.
    // If load_is_prefixes we don't maintain entries-per-group so we must calculate the group's size in order to update the cores'
    // utilization.
    size_t group_load = (load_is_prefixes) ? m_tree->get_load_of_group(group_to_merge, group_root_key, resource) : 0;

    la_status status = move_entries_between_cores(remove_group_root_action, from_core, to_core, distributer_actions);
    return_on_error(status, TABLES, DEBUG, "%s: Failed to move group from core %zu to core %zu", __func__, from_core, to_core);

    // Update state
    ranged_index_generator& group_indexes = m_distributor_logical_state[protocol_idx].free_indexes;
    dassert_crit(!group_indexes.is_available(group_to_merge));
    group_indexes.release(group_to_merge);

    key_to_group_core_unordered_map& group_core_map = m_distributor_logical_state[protocol_idx].used_distributor_entries;
    const auto& it = group_core_map.find(group_root_key);
    dassert_crit(it != group_core_map.end());
    group_core_map.erase(it);

    if (load_is_prefixes) {
        dassert_crit(m_load_per_core[protocol_idx][from_core] >= group_load);
        m_load_per_core[protocol_idx][from_core] -= group_load;
        m_load_per_core[protocol_idx][to_core] += group_load;
    } else {
        m_load_per_core[protocol_idx][from_core] = get_core_tcam_load(protocol, from_core);
        m_load_per_core[protocol_idx][to_core] = get_core_tcam_load(protocol, to_core);
    }

    m_load_per_group.is_valid[group_to_move_entries_to] = false;

    dassert_slow(sanity());

    return LA_STATUS_SUCCESS;
}

void
logical_lpm_impl::find_optimal_group_root_to_be_merged_with_parent(lpm_ip_protocol_e protocol,
                                                                   const vector_alloc<bool> group_exclude_list,
                                                                   lpm_key_t& group_key,
                                                                   lpm_core_group_data& out_from_group_core,
                                                                   lpm_core_group_data& out_to_group_core) const
{
    dassert_crit(group_exclude_list.size() == m_number_of_groups);

    size_t min_core_load_after_merge = MAX_SIZE_T;
    out_from_group_core.core_index = CORE_ID_NONE;
    out_from_group_core.group_index = GROUP_ID_NONE;

    size_t protocol_idx = static_cast<size_t>(protocol);

    for (const auto& it : m_distributor_logical_state[protocol_idx].used_distributor_entries) {
        size_t group_index = it.second.group_index;
        if (group_exclude_list[group_index]) {
            continue;
        }

        const lpm_key_t& key = it.first;
        lpm_core_group_data core_group_to_merge_to;
        get_covering_core_group(key, core_group_to_merge_to);
        if (core_group_to_merge_to.group_index == GROUP_ID_NONE) {
            continue;
        }

        size_t from_core = it.second.core_index;
        size_t core_to_merge_to = core_group_to_merge_to.core_index;
        if (from_core
            == core_to_merge_to) { // Best thing ever. Free a group without moving anything between cores. Guaranteed to succeed.
            group_key = key;
            out_from_group_core.group_index = group_index;
            out_from_group_core.core_index = from_core;
            out_to_group_core = core_group_to_merge_to;

            break;
        }

        if (!m_load_per_group.is_valid[group_index]) {
            m_load_per_group.load_per_group[group_index]
                = m_tree->get_load_of_group(group_index, key, m_resource_type_to_use_for_rebalance[protocol_idx]);
            m_load_per_group.is_valid[group_index] = true;
        }

        size_t group_load = m_load_per_group.load_per_group[group_index];
        size_t dst_core_load = m_load_per_core[protocol_idx][core_to_merge_to];

        size_t dst_core_load_after_merge = dst_core_load + group_load;

        log_xdebug(TABLES,
                   "%s: group %zu  load %zu   core %zu  core load %zu  covering group %zu  covering group core %zu  "
                   "covering group core load %zu   covering group core load after merge %zu",
                   __func__,
                   group_index,
                   group_load,
                   from_core,
                   m_load_per_core[protocol_idx][from_core],
                   core_group_to_merge_to.group_index,
                   core_to_merge_to,
                   dst_core_load,
                   dst_core_load_after_merge);

        if (dst_core_load_after_merge <= min_core_load_after_merge) {
            min_core_load_after_merge = dst_core_load_after_merge;
            out_from_group_core.group_index = group_index;
            out_from_group_core.core_index = from_core;
            out_to_group_core = core_group_to_merge_to;
            group_key = key;
        }
    }

    if (out_from_group_core.group_index == GROUP_ID_NONE) {
        log_debug(TABLES, "%s: could not find a group to merge with parent", __func__);
    } else {
        log_debug(TABLES,
                  "%s: proposing to merge group %zu (core %zu) with its parent %zu (core %zu)",
                  __func__,
                  out_from_group_core.group_index,
                  out_from_group_core.core_index,
                  out_to_group_core.group_index,
                  out_to_group_core.core_index);
    }
}

void
logical_lpm_impl::get_covering_core_group(const lpm_key_t& group_root, lpm_core_group_data& out_core_group) const
{
    dassert_crit(!group_root.is_null());
    // The containing group of a given group,
    // is the group that its key is the longest key that is contained in the given group key.
    // This group is found by looking up the longest containing key possible, which is the given key bits except the last.
    // This is correct because the distributor TCAM finds the key with the longest prefix match.
    lpm_key_t parent_key = group_root >> 1;
    get_containing_group_and_core(parent_key, out_core_group);
}

la_status
logical_lpm_impl::move_entries_between_cores(const lpm_action_desc_internal& action,
                                             size_t from_core,
                                             size_t to_core,
                                             const lpm_implementation_desc_vec& distributor_actions)
{
    dassert_crit(from_core != CORE_ID_NONE);
    dassert_crit(to_core != CORE_ID_NONE);

    lpm_implementation_action_e action_type = action.m_action;
    dassert_crit((action_type == lpm_implementation_action_e::ADD_GROUP_ROOT)
                 || (action_type == lpm_implementation_action_e::REMOVE_GROUP_ROOT)
                 || (action_type == lpm_implementation_action_e::MODIFY_GROUP_TO_CORE));
    lpm_implementation_desc_vec tree_actions(1, action);
    size_t failed_core;
    lpm_implementation_desc_vec_levels_cores cores_actions;
    transaction txn;
    txn.status = m_tree->update(tree_actions, cores_actions, failed_core);
    if (txn.status != LA_STATUS_SUCCESS) {
        dassert_crit(failed_core == to_core);
        return txn.status;
    }

    txn.on_fail([=]() { m_tree->withdraw(); });

    vector_alloc<size_t> cores_to_update{to_core};
    // (from_core == to_core) can be true if we remove group root and its covering group is on the same core.
    if (to_core != from_core) {
        cores_to_update.push_back(from_core);
    }

    for (size_t core_id : cores_to_update) {
        if (core_id == CORE_ID_NONE) {
            continue;
        }

        lpm_implementation_desc_vec& l1_actions_for_core = cores_actions[core_id][LEVEL1];

        txn.status = m_cores[core_id]->update_tcam(l1_actions_for_core);
        if (txn.status != LA_STATUS_SUCCESS) {
            dassert_crit(core_id == to_core);
            log_err(TABLES, "Rebalance: core #%lu update failed", core_id);
            return txn.status;
        }

        txn.on_fail([=]() { m_cores[core_id]->withdraw(); });
    }

    lpm_distributor::hardware_instruction_vec distributor_updates;
    dassert_crit(distributor_actions.size() <= 1);
    dassert_crit((distributor_actions.size() == 0) || (distributor_actions[0].m_action != lpm_implementation_action_e::REMOVE)
                     || (distributor_actions[0].m_key.get_width() >= 2),
                 "trying to remove distributor node with width (%zu) < 2",
                 distributor_actions[0].m_key.get_width());

    txn.status = m_distributor->update(distributor_actions, distributor_updates);
    if (txn.status != LA_STATUS_SUCCESS) {
        dassert_crit(false);
        log_err(TABLES, "Moving entries between cores: Distributer update failed");
        return txn.status;
    }

    m_tree->commit();

    // Commit HW changes
    if (to_core != CORE_ID_NONE) {
        log_debug(TABLES, "committing HW update to target core");
        txn.status = m_cores[to_core]->commit_hw_updates(cores_actions[to_core]);
        dassert_crit(txn.status == LA_STATUS_SUCCESS);
        return_on_error(txn.status);
    }

    if (!distributor_actions.empty()) {
        log_debug(TABLES, "comitting HW update to distributor");
        m_distributor->commit();
        txn.status = m_hw_writer->update_distributor(distributor_updates);
        dassert_crit(txn.status == LA_STATUS_SUCCESS);
        return_on_error(txn.status);
    }

    if (from_core != CORE_ID_NONE) {
        log_debug(TABLES, "committing HW update to target core");
        txn.status = m_cores[from_core]->commit_hw_updates(cores_actions[from_core]);
        dassert_crit(txn.status == LA_STATUS_SUCCESS);
        return_on_error(txn.status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
logical_lpm_impl::move_a_subtree_to_least_utilized_core_using_new_group(lpm_ip_protocol_e protocol, size_t src_core)
{
    log_debug(TABLES, "logical_lpm_impl::%s", __func__);

    size_t most_utilized_core;
    size_t least_utilized_core;
    size_t max_core_utilization;
    size_t min_core_utilization;
    get_most_and_least_utilized_cores(
        protocol, most_utilized_core, least_utilized_core, max_core_utilization, min_core_utilization);

    size_t protocol_idx = static_cast<size_t>(protocol);

    size_t from_core = (src_core == CORE_ID_NONE) ? most_utilized_core : src_core;
    size_t to_core = least_utilized_core;

    if (from_core == to_core) {
        log_debug(
            TABLES, "%s: Source core %zu is the least utilized core! Nothing I can do here to help. Sorry!", __func__, from_core);
        return LA_STATUS_ERESOURCE;
    }

    size_t from_core_utilization = m_load_per_core[protocol_idx][from_core];
    size_t delta_between_cores = from_core_utilization - min_core_utilization;
    size_t requested_group_weighted_size = (delta_between_cores * 2) / 5; // a little less than half

    log_debug(TABLES,
              "%s: rebalance. from_core_utilization %zu  min_core_utilization %zu  requested_group_weighted_size %zu",
              __func__,
              from_core_utilization,
              min_core_utilization,
              requested_group_weighted_size);

    if (requested_group_weighted_size == 0) {
        log_debug(TABLES,
                  "%s: No need to move anything, cores (%zu and %zu) loads are (%zu vs. %zu)",
                  __func__,
                  from_core,
                  to_core,
                  from_core_utilization,
                  min_core_utilization);
        return LA_STATUS_SUCCESS;
    }

    while (requested_group_weighted_size > 0) {
        log_debug(TABLES,
                  "%s: Trying to move a subtree of size %zu from core %zu (load: %zu) to core %zu (load: %zu)",
                  __func__,
                  requested_group_weighted_size,
                  from_core,
                  from_core_utilization,
                  to_core,
                  min_core_utilization);
        la_status status = break_a_group_subtree_with_given_size(protocol, from_core, to_core, requested_group_weighted_size);
        if (status == LA_STATUS_SUCCESS) {
            dassert_slow(sanity());
            return status;
        }

        log_debug(TABLES,
                  "%s: failed to move %zu entries. Will try %zu",
                  __func__,
                  requested_group_weighted_size,
                  requested_group_weighted_size / 2);
        requested_group_weighted_size /= 2;
    }

    return LA_STATUS_ERESOURCE;
}

la_status
logical_lpm_impl::break_a_group_subtree_with_given_size(lpm_ip_protocol_e protocol,
                                                        size_t src_core,
                                                        size_t dst_core,
                                                        size_t requested_size)
{
    dassert_crit(dst_core != CORE_ID_NONE);
    dassert_crit(src_core != dst_core);

    lpm_key_t new_key;
    size_t from_group;
    size_t new_group_size;
    find_a_group_subtree_with_given_size(src_core, protocol, requested_size, from_group, new_key, new_group_size);

    log_debug(TABLES,
              "%s: src_core %zu  requested_size %zu   from_group %zu  new_key %s/%zu  new_group_size %zu",
              __func__,
              src_core,
              requested_size,
              from_group,
              new_key.to_string().c_str(),
              new_key.get_width(),
              new_group_size);

    if (from_group == GROUP_ID_NONE) {
        log_debug(TABLES, "%s: failed to find a subtree in core %zu with size around %zu", __func__, src_core, requested_size);
        return LA_STATUS_ERESOURCE;
    }

    if (new_group_size == 0) {
        log_debug(TABLES, "%s: New group size is zero. Nothing to do. Bye", __func__);
        return LA_STATUS_SUCCESS;
    }

    size_t protocol_idx = static_cast<size_t>(protocol);
    key_to_group_core_unordered_map& group_core_map = m_distributor_logical_state[protocol_idx].used_distributor_entries;
    const auto& it = group_core_map.find(new_key);
    bool is_whole_group = (it != group_core_map.end());
    if (is_whole_group) {
        la_status status = move_group_to_core(protocol, new_key, dst_core);
        if (status == LA_STATUS_SUCCESS) {
            log_debug(TABLES, "%s: moved whole group %zu from core %zu to core %zu", __func__, from_group, src_core, dst_core);
        } else {
            log_debug(
                TABLES, "%s: failed to move whole group %zu from core %zu to core %zu", __func__, from_group, src_core, dst_core);
        }
        return status;
    }

    size_t free_group_id;
    la_status status = allocate_free_group(protocol, free_group_id);
    return_on_error(status, TABLES, DEBUG, "%s: Failed to allocate free group index", __func__);
    transaction txn;
    txn.on_fail([=]() { m_distributor_logical_state[protocol_idx].free_indexes.release(free_group_id); });

    log_debug(TABLES,
              "%s: will move entries from group %zu (key %s/%zu  core %zu) to new group (%zu) on core %zu",
              __func__,
              from_group,
              new_key.to_string().c_str(),
              new_key.get_width(),
              src_core,
              free_group_id,
              dst_core);

    lpm_action_desc_internal add_group_root_action(lpm_implementation_action_e::ADD_GROUP_ROOT, new_key);
    add_group_root_action.m_group_id = free_group_id;
    add_group_root_action.m_core_id = dst_core;

    lpm_action_desc_internal distributer_action
        = create_insert_modify_distributor_action_desc(lpm_implementation_action_e::INSERT, new_key, free_group_id, dst_core);
    lpm_implementation_desc_vec distributer_actions(1, distributer_action);

    txn.status = move_entries_between_cores(add_group_root_action, src_core, dst_core, distributer_actions);
    return_on_error(txn.status, TABLES, DEBUG, "%s: move_entries_between_cores failed", __func__);

    group_core_map[new_key] = lpm_core_group_data{.core_index = dst_core, .group_index = free_group_id};

    resource_type resource = m_resource_type_to_use_for_rebalance[protocol_idx];
    bool load_is_prefixes = (resource == resource_type::PREFIXES);
    dassert_crit(m_load_per_core[protocol_idx][src_core] >= new_group_size);

    // update state
    if (load_is_prefixes) {
        m_load_per_core[protocol_idx][src_core] -= new_group_size;
        m_load_per_core[protocol_idx][dst_core] += new_group_size;
    } else {
        m_load_per_core[protocol_idx][src_core] = get_core_tcam_load(protocol, src_core);
        m_load_per_core[protocol_idx][dst_core] = get_core_tcam_load(protocol, dst_core);
    }

    m_load_per_group.is_valid[from_group] = false;
    m_load_per_group.is_valid[free_group_id] = false;

    dassert_slow(sanity());

    return LA_STATUS_SUCCESS;
}

void
logical_lpm_impl::find_a_group_subtree_with_given_size(size_t from_core,
                                                       lpm_ip_protocol_e protocol,
                                                       size_t requested_weighted_size,
                                                       size_t& out_from_group,
                                                       lpm_key_t& out_new_group_key,
                                                       size_t& out_achieved_weighted_size) const
{
    lpm_key_vec group_roots_in_from_core;
    size_t protocol_idx = static_cast<size_t>(protocol);

    for (const auto& it : m_distributor_logical_state[protocol_idx].used_distributor_entries) {
        size_t core_id = it.second.core_index;
        if (core_id != from_core) {
            continue;
        }

        const lpm_key_t& group_root = it.first;
        group_roots_in_from_core.push_back(group_root);
    }

    resource_descriptor tree_requested_weighted_size
        = {m_resource_type_to_use_for_rebalance[protocol_idx], requested_weighted_size};
    bool is_ipv6 = (protocol == lpm_ip_protocol_e::IPV6);
    size_t max_key_width = is_ipv6 ? m_distributor_row_width - 1 : lpm_core_tcam::CELL_WIDTH;
    m_tree->find_subtree_with_given_weighted_size(tree_requested_weighted_size,
                                                  group_roots_in_from_core,
                                                  max_key_width,
                                                  out_from_group,
                                                  out_new_group_key,
                                                  out_achieved_weighted_size);
}

la_status
logical_lpm_impl::allocate_free_group(lpm_ip_protocol_e protocol, size_t& free_group_id)
{
    log_debug(TABLES, "Allocating a free group for protocol: %s", (protocol == lpm_ip_protocol_e::IPV6) ? "IPv6" : "IPv4");

    free_group_id = GROUP_ID_NONE;
    ranged_index_generator& group_indexes = m_distributor_logical_state[static_cast<size_t>(protocol)].free_indexes;
    if (group_indexes.available() == 0) {
        log_debug(TABLES, "%s: Failed to allocate new group", __func__);
        return LA_STATUS_ERESOURCE;
    }

    bool allocated = group_indexes.allocate(free_group_id);
    dassert_crit(allocated);

    log_debug(TABLES, "%s free group %zu allocated", __func__, free_group_id);

    return LA_STATUS_SUCCESS;
}

void
logical_lpm_impl::get_most_and_least_utilized_cores(lpm_ip_protocol_e protocol,
                                                    size_t& out_most_utilized_core,
                                                    size_t& out_least_utilized_core,
                                                    size_t& out_max_core_utilization,
                                                    size_t& out_min_core_utilization) const
{
    size_t protocol_idx = static_cast<size_t>(protocol);

    auto minmax = std::minmax_element(m_load_per_core[protocol_idx].begin(), m_load_per_core[protocol_idx].end());
    out_least_utilized_core = (minmax.first - m_load_per_core[protocol_idx].begin());
    out_most_utilized_core = (minmax.second - m_load_per_core[protocol_idx].begin());
    out_min_core_utilization = *minmax.first;
    out_max_core_utilization = *minmax.second;
}

void
logical_lpm_impl::calculate_cores_utilization()
{
    constexpr std::array<size_t, 2> TCAM_IS_LOADED_THRESHOLD{{512, 110}};
    for (lpm_ip_protocol_e protocol : {lpm_ip_protocol_e::IPV4, lpm_ip_protocol_e::IPV6}) {
        size_t protocol_idx = static_cast<size_t>(protocol);
        for (size_t core = 0; core < m_number_of_cores; core++) {
            m_load_per_core[protocol_idx][core] = get_core_tcam_load(protocol, core);
        }

        auto result = std::max_element(m_load_per_core[protocol_idx].begin(), m_load_per_core[protocol_idx].end());
        if (*result < TCAM_IS_LOADED_THRESHOLD[protocol_idx]) {
            m_resource_type_to_use_for_rebalance[protocol_idx] = resource_type::PREFIXES;
            m_tree->calculate_prefixes_load_per_core(protocol, m_load_per_core[protocol_idx]);
        } else {
            m_resource_type_to_use_for_rebalance[protocol_idx] = resource_type::TCAM_LINES;
        }
    }
}

size_t
logical_lpm_impl::get_core_tcam_load(lpm_ip_protocol_e protocol, size_t core) const
{
    const lpm_core_tcam& tcam = m_cores[core]->get_tcam();
    auto stats = tcam.get_occupancy();
    if (protocol == lpm_ip_protocol_e::IPV6) {
        return stats.num_double_entries * m_tcam_double_width_key_weight + stats.num_quad_entries * m_tcam_quad_width_key_weight;
    }

    return stats.num_single_entries * m_tcam_single_width_key_weight;
}

void
logical_lpm_impl::lpm_hbm_collect_stats()
{
    constexpr size_t HBM_HW_INDEX_WIDTH = 15;
    vector_alloc<size_t> hbm_hw_indices;
    la_status status = m_hw_writer->read_indices_of_last_accessed_hbm_buckets(hbm_hw_indices);
    if (status != LA_STATUS_SUCCESS) {
        return;
    }

    for (const auto& hbm_hw_index : hbm_hw_indices) {
        size_t core = bit_utils::get_bits(hbm_hw_index, HBM_CORE_ID_WIDTH - 1, 0);
        size_t hw_index = bit_utils::get_bits(hbm_hw_index, HBM_CORE_ID_WIDTH + HBM_HW_INDEX_WIDTH - 1, HBM_CORE_ID_WIDTH);
        if (hw_index != 0) {
            m_cores[core]->notify_l2_bucket_accessed(hw_index);
        }
    }

    for (size_t i = 0; i < m_number_of_cores; i++) {
        m_cores[i]->collect_bucket_hotness_stats();
    }
}

void
logical_lpm_impl::lpm_hbm_do_caching()
{
    for (size_t i = 0; i < m_number_of_cores; i++) {
        m_cores[i]->perform_caching();
    }
}

void
logical_lpm_impl::unmask_and_clear_l2_ecc_interrupt_registers() const
{
    for (size_t i = 0; i < m_number_of_cores; i++) {
        m_cores[i]->unmask_and_clear_l2_ecc_interrupt_registers();
    }
}

size_t
logical_lpm_impl::max_size() const
{
    return LPM_MAX_FULLNESS;
}

bool
logical_lpm_impl::sanity() const
{
    bool res = true;
    dassert_slow(res = res && check_groups_roots_keys());
    return res;
}

bool
logical_lpm_impl::check_groups_roots_keys() const
{
    // Check that tree's group_to_core is consistent with logical_lpm group_to_core.
    const auto& tree_group_to_core(m_tree->get_group_to_core());

    // check that all tree nodes which are marked as group roots are consistent with logical_lpm's records about who are the group
    // roots
    const lpm_node* root_node = m_tree->get_root_node();
    vector_alloc<bool> found_groups(m_number_of_groups, false);
    std::array<key_to_group_core_unordered_map, 2> tree_group_core_map;

    vector_alloc<const lpm_node*> wave;
    wave.push_back(root_node);
    while (!wave.empty()) {
        const lpm_node* current_node = wave.back();
        wave.pop_back();
        if (current_node == nullptr) {
            continue;
        }

        const lpm_bucketing_data& current_data = current_node->data();
        size_t group = current_data.group;
        if (group != GROUP_ID_NONE) {
            if (found_groups[group]) {
                log_err(TABLES, "logical_lpm_impl::%s group_id=%lu appears more than once in the tree", __func__, group);
                dassert_crit(false);
                return false;
            } else {
                found_groups[group] = true;
            }

            const lpm_key_t& key = current_node->get_key();
            size_t protocol_idx = key.bit_from_msb(0);
            size_t core = tree_group_to_core[group];
            if (core == CORE_ID_NONE) {
                log_err(TABLES, "logical_lpm_impl::%s core index %zu not valid", __func__, core);
                dassert_crit(false);
                return false;
            }

            tree_group_core_map[protocol_idx][key] = lpm_core_group_data{.core_index = core, .group_index = group};
        }

        wave.push_back(current_node->get_left_child());
        wave.push_back(current_node->get_right_child());
    }

    for (lpm_ip_protocol_e protocol : {lpm_ip_protocol_e::IPV4, lpm_ip_protocol_e::IPV6}) {
        size_t protocol_idx = static_cast<size_t>(protocol);
        const key_to_group_core_unordered_map& key_to_group_core
            = m_distributor_logical_state[protocol_idx].used_distributor_entries;
        if (tree_group_core_map[protocol_idx] != key_to_group_core) {
            log_err(TABLES,
                    "logical_lpm_impl::%s key to group/core map not consistent with one from the tree for protocol %s",
                    __func__,
                    (protocol == lpm_ip_protocol_e::IPV4) ? "IPv4" : "IPv6");
            dassert_crit(false);
            return false;
        }

        ranged_index_generator group_indexes = m_distributor_logical_state[protocol_idx].free_indexes;
        for (const auto& it : key_to_group_core) {
            size_t group_index = it.second.group_index;
            if (group_index == GROUP_ID_NONE) {
                log_err(TABLES, "logical_lpm_impl::%s group index %zu not valid", __func__, group_index);
                dassert_crit(false);
                return false;
            }

            if (group_indexes.is_available(group_index)) {
                log_err(TABLES, "logical_lpm_impl::%s group=%lu exists as available group", __func__, group_index);
                dassert_crit(false);
                return false;
            }
        }

        size_t num_allocated_groups = group_indexes.size();
        if (num_allocated_groups != key_to_group_core.size()) {
            log_err(TABLES, "logical_lpm_impl::%s Number of allocated groups %zu not aligned", __func__, num_allocated_groups);
            dassert_crit(false);
            return false;
        }
    }

    return true;
}

size_t
logical_lpm_impl::size() const
{

    size_t min_empty_cells = MAX_SIZE_T;
    size_t min_number_of_free_l2_buckets = MAX_SIZE_T;
    size_t max_quad_entries_in_use = 0;

    for (const auto& core : m_cores) {
        auto& tcam = core->get_tcam();
        auto tcam_occupancy = tcam.get_occupancy();

        min_empty_cells = std::min(min_empty_cells, tcam_occupancy.empty_cells);
        max_quad_entries_in_use = std::max(max_quad_entries_in_use, tcam_occupancy.num_quad_entries);

        const auto& l2_hw_index_allocator = m_tree->get_hw_index_allocator(core->get_id(), lpm_level_e::L2);
        size_t number_of_free_l2_buckets = l2_hw_index_allocator->get_number_of_free_indices();
        min_number_of_free_l2_buckets = std::min(min_number_of_free_l2_buckets, number_of_free_l2_buckets);
    }

    // All cores should have the same parameters.
    double max_tcam_quad_v6_utilization = 0;
    if (is_pacific_revision(m_ll_device) || is_gibraltar_revision(m_ll_device)) {
        const lpm_core_tcam& tcam = m_cores[0]->get_tcam();
        const size_t max_quad_tcam_lines = tcam.get_max_quad_entries();
        max_tcam_quad_v6_utilization = ((double)max_quad_entries_in_use / max_quad_tcam_lines) * LPM_MAX_FULLNESS;
    }

    const double max_tcam_v4_utilization
        = LPM_MAX_FULLNESS - ((double)min_empty_cells / m_num_tcam_cells_per_core) * LPM_MAX_FULLNESS;
    const double max_l2_buckets_utilization
        = LPM_MAX_FULLNESS - ((double)min_number_of_free_l2_buckets / m_num_l2_bucket_per_core) * LPM_MAX_FULLNESS;

    return std::max({max_tcam_v4_utilization, max_tcam_quad_v6_utilization, max_l2_buckets_utilization});
}

la_status
logical_lpm_impl::set_resource_monitor(const resource_monitor_sptr& monitor)
{
    m_resource_monitor = monitor;

    return LA_STATUS_SUCCESS;
}

la_status
logical_lpm_impl::get_resource_monitor(resource_monitor_sptr& out_monitor) const
{
    out_monitor = m_resource_monitor;

    return LA_STATUS_SUCCESS;
}

la_status
logical_lpm_impl::save_state(std::string file_name) const
{
    json_t* json_repr = json_object();

    save_flat_members(json_repr);

    json_t* json_distributer = m_distributor->save_state();
    json_object_set_new(json_repr, JSON_DISTRIBUTER, json_distributer);

    json_t* json_tree = m_tree->tree_to_json();
    json_object_set_new(json_repr, JSON_TREE, json_tree);

    la_status status = file_utils::write_json_to_file(json_repr, file_name);
    json_decref(json_repr);

    return status;
}

la_status
logical_lpm_impl::get_prefixes_statistics(std::string file_name) const
{
    json_t* json_repr = json_array();

    json_t* json_prefixes_statistics = m_tree->prefixes_statistics_to_json();
    json_array_append_new(json_repr, json_prefixes_statistics);

    la_status status = file_utils::write_json_to_file(json_repr, file_name);
    json_decref(json_repr);

    return status;
}

la_status
logical_lpm_impl::load_state(const std::string& file_name)
{
    lpm_action_statistics tree_stats = m_tree->get_total_action_distribution_stats();
    if (tree_stats.insertions != tree_stats.removals) {
        log_err(TABLES, "Failed loading the state! Lpm not empty!");
        return LA_STATUS_EINVAL;
    }

    json_error_t error;
    json_t* root = json_load_file(file_name.c_str(), 0, &error);
    if (!root) {
        log_err(TABLES, "Failed to open the file %s for loading the state.", file_name.c_str());
        return LA_STATUS_EINVAL;
    }

    json_t* json_distributor = json_object_get(root, JSON_DISTRIBUTER);
    if (!json_distributor) {
        log_err(TABLES, "Could not read distributor from JSON.");
        return LA_STATUS_EINVAL;
    }

    lpm_distributor::hardware_instruction_vec instructions;
    m_distributor->load_state(json_distributor, instructions);
    m_distributor->commit();
    la_status status = m_hw_writer->update_distributor(instructions);
    dassert_crit(status == LA_STATUS_SUCCESS);
    json_t* json_members = json_object_get(root, JSON_LPM_MEMBERS);
    load_flat_members(json_members);

    json_decref(root);
    return status;
}

void
logical_lpm_impl::save_flat_members(json_t* json_repr) const
{
    json_t* json_members = json_object();
    json_object_set_new(json_members, JSON_ACTION_COUNTER, json_integer(m_actions_counter));
    for (const auto& distributor_logical_state : m_distributor_logical_state) {
        const key_to_group_core_unordered_map& key_to_group_core = distributor_logical_state.used_distributor_entries;
        for (const auto& group_core_it : key_to_group_core) {
            json_t* json_group = json_object();
            size_t group_id = group_core_it.second.group_index;
            size_t core_id = group_core_it.second.core_index;
            json_object_set_new(json_group, JSON_GROUP_ID, json_integer(group_id));
            json_object_set_new(json_group, JSON_CORE_ID, json_integer(core_id));

            const lpm_key_t& key = group_core_it.first;
            json_object_set_new(json_group, JSON_KEY_VALUE, json_string(key.to_string().c_str()));
            json_object_set_new(json_group, JSON_KEY_WIDTH, json_integer(key.get_width()));
            json_object_set_new(json_members, std::to_string(group_id).c_str(), json_group);
        }
    }

    json_object_set_new(json_repr, JSON_LPM_MEMBERS, json_members);
}

void
logical_lpm_impl::load_flat_members(json_t* json_repr)
{
    reset_members();
    const char* member;
    json_t* member_data;
    json_object_foreach(json_repr, member, member_data)
    {
        if (std::strcmp(JSON_ACTION_COUNTER, member) == 0) {
            m_actions_counter = json_integer_value(member_data);
            continue;
        }

        size_t group_id = json_integer_value(json_object_get(member_data, JSON_GROUP_ID));
        size_t core_id = json_integer_value(json_object_get(member_data, JSON_CORE_ID));
        std::string key_value = json_string_value(json_object_get(member_data, JSON_KEY_VALUE));
        size_t key_width_value = json_integer_value(json_object_get(member_data, JSON_KEY_WIDTH));
        lpm_key_t key = lpm_key_t(key_value, key_width_value);
        size_t protocol_idx = key.bit_from_msb(0);
        key_to_group_core_unordered_map& key_to_group_core = m_distributor_logical_state[protocol_idx].used_distributor_entries;
        key_to_group_core.insert(std::make_pair(key, lpm_core_group_data{.core_index = core_id, .group_index = group_id}));

        ranged_index_generator& group_indexes = m_distributor_logical_state[protocol_idx].free_indexes;
        size_t dummy_out_index;
        group_indexes.allocate(group_id, dummy_out_index);
        dassert_crit(!group_indexes.is_available(group_id));

        lpm_action_desc_internal group_root_action = lpm_action_desc_internal(lpm_implementation_action_e::ADD_GROUP_ROOT, key);
        group_root_action.m_group_id = group_id;
        group_root_action.m_core_id = core_id;
        if (is_default_group(key)) {
            group_root_action.m_action = lpm_implementation_action_e::MODIFY_GROUP_TO_CORE;
        }

        lpm_implementation_desc_vec actions{group_root_action};
        size_t failed_core;
        la_status status = update_cores(actions, failed_core);
        dassert_crit(status == LA_STATUS_SUCCESS);
    }

    dassert_crit(sanity());
}

void
logical_lpm_impl::reset_members()
{
    for (auto& distributor_logical_state : m_distributor_logical_state) {
        ranged_index_generator& group_indexes = distributor_logical_state.free_indexes;
        key_to_group_core_unordered_map& key_to_group_core = distributor_logical_state.used_distributor_entries;
        for (const auto& group_core_it : key_to_group_core) {
            size_t group_id = group_core_it.second.group_index;
            size_t core_id = group_core_it.second.core_index;

            dassert_crit(core_id != CORE_ID_NONE && group_id != GROUP_ID_NONE);

            const lpm_key_t& group_root_key = group_core_it.first;
            group_indexes.release(group_id);
            if (is_default_group(group_root_key)) {
                continue;
            }

            lpm_action_desc_internal remove_group_action(lpm_implementation_action_e::REMOVE_GROUP_ROOT, group_root_key);
            lpm_implementation_desc_vec actions{remove_group_action};
            size_t failed_core;
            la_status status = update_cores(actions, failed_core);
            dassert_crit(status == LA_STATUS_SUCCESS);
        }

        key_to_group_core.clear();
    }
}

bool
logical_lpm_impl::is_default_group(const lpm_key_t& group_root) const
{
    return (group_root.get_width() == 1);
}

lpm_action_desc_internal
logical_lpm_impl::create_insert_modify_distributor_action_desc(lpm_implementation_action_e action,
                                                               const lpm_key_t& key,
                                                               size_t group,
                                                               size_t core)
{
    lpm_action_desc_internal instruction;
    bool pacific_gb = is_pacific_or_gibraltar_revision(m_ll_device);
    dassert_crit((group != GROUP_ID_NONE) && (core != CORE_ID_NONE));

    switch (action) {
    case lpm_implementation_action_e::INSERT:
        instruction.m_key = key;
        break;
    case lpm_implementation_action_e::MODIFY_GROUP_TO_CORE: {
        if (!pacific_gb) {
            instruction.m_key = key;
        }

        break;
    }

    default:
        dassert_crit(false);
        break;
    }

    if (pacific_gb) {
        instruction.m_payload = group;
        instruction.m_core_id = core;
    } else {
        // For AKPG payload of distributor is actually core id, not a group.
        instruction.m_payload = core;
    }

    instruction.m_action = action;
    return instruction;
}

size_t
logical_lpm_impl::get_physical_usage(lpm_ip_protocol_e table_type, size_t num_of_table_logical_entries) const
{
    size_t default_ret_val = 0;
    log_warning(TABLES, "%s is not implememnted. returned %zu.", __FUNCTION__, default_ret_val);
    return default_ret_val;
}

size_t
logical_lpm_impl::get_available_entries(lpm_ip_protocol_e table_type) const
{
    size_t total_free_l2_buckets = 0;
    for (size_t core_idx = 0; core_idx < m_number_of_cores; core_idx++) {
        const auto& l2_hw_index_allocator = m_tree->get_hw_index_allocator(core_idx, lpm_level_e::L2);
        size_t core_free_l2_buckets = l2_hw_index_allocator->get_number_of_free_indices();
        total_free_l2_buckets += core_free_l2_buckets;
    }

    const auto& l2_tree_parameters = m_tree->get_parameters(lpm_level_e::L2);
    size_t num_shared_entries_estimation = l2_tree_parameters.bucket_num_shared_entries / l2_tree_parameters.buckets_per_sram_line;
    size_t entries_per_bucket = num_shared_entries_estimation + l2_tree_parameters.bucket_num_fixed_entries;
    size_t total_available_entries = total_free_l2_buckets * entries_per_bucket;

    return total_available_entries;
}

} // namespace silicon_one
