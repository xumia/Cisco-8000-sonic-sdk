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

#include "hw_tables/em_core.h"
#include "common/bit_utils.h"
#include "common/defines.h"
#include "common/logger.h"
#include "crc_divisors.h"
#include "hw_tables/em_hasher.h"

#include "lld/ll_device.h"

const double HIGHEST_UTILIZATION_FOR_MOVINGS = 0.95;

namespace silicon_one
{

em_core::em_core() : m_orig_max_moving_depth()
{
}

em_core::em_core(const ll_device_sptr& ldevice, const physical_em& em, size_t max_moving_depth, bool flex_entry_enabled)
    : m_is_cam_evacuation_disabled(false),
      m_ll_device(ldevice),
      m_num_of_banks(em.banks.size()),
      m_num_of_bank_entries(em.bank_size),
      m_num_of_cam_entries(em.cam_size),
      m_entry_width(em.data_width),
      m_max_moving_depth(max_moving_depth),
      m_orig_max_moving_depth(max_moving_depth),
      m_em(em),
      m_flexible_entry(flex_entry_enabled),
      m_banks(em.banks.size()),
      m_cam(em.cam_size),
      m_resource_monitor(nullptr),
      m_num_entries(0)
{
    // Initialize banks.
    em_bank_entry empty_bank_entry = {false, EM_NULL_INDEX, em::key_t(), em_verifier_t(), em::payload_t()};

    for (size_t bank_index = 0; bank_index < m_num_of_banks; bank_index++) {
        if (!m_em.banks[bank_index].is_active) {
            continue;
        }
        m_banks[bank_index].resize(em.bank_size, empty_bank_entry);
    }

    // Initialize CAM.
    em_cam_entry empty_cam_entry = {false, em::key_t(), em::payload_t()};
    m_cam.resize(em.cam_size, empty_cam_entry);

    // Setup hashers.
    init_hashers();
}

la_status
em_core::insert(const bit_vector& key_bv, const bit_vector& payload_bv)
{
    em::payload_t payload(payload_bv);
    em::key_t key(key_bv);

    // Check inputs correctness.
    if (!check_key_payload_inputs(key, payload)) {
        return LA_STATUS_EINVAL;
    }

    size_t key_width = key.get_width();
    size_t payload_width = payload.get_width();
    size_t line_cfg_option = get_line_config_option_index(key_width, payload_width);

    size_t free_bank_index;
    size_t free_entry_index;
    em_verifier_t verifier;

    // Check if the entry exists in EM core, get free entry if not.
    if (find_entry(key, line_cfg_option, free_bank_index, free_entry_index, verifier)) {
        return LA_STATUS_EEXIST;
    }

    hw_entries_vec_t entries_to_write;
    la_status status;
    if (insert_entry_to_banks(key, payload, free_bank_index, free_entry_index, line_cfg_option, verifier, entries_to_write)) {
        status = write_to_physical_em(entries_to_write);
        return_on_error(status);
    } else if (insert_entry_to_cam(key, payload, free_entry_index, entries_to_write)) {
        status = write_to_physical_em(entries_to_write);
        return_on_error(status);
    } else {
        return LA_STATUS_ERESOURCE;
    }

    ++m_num_entries;
    if (m_resource_monitor != nullptr) {
        size_t current_size = size();
        m_resource_monitor->update_size(current_size);
    }

    if (get_utilization_percentage() > HIGHEST_UTILIZATION_FOR_MOVINGS) {
        log_debug(TABLES, "%s, util: %f, size():%ld, max_size():%ld", __func__, get_utilization_percentage(), size(), max_size());
        m_max_moving_depth = 0;
    }

    return status;
}

la_status
em_core::erase(const bit_vector& key_bv)
{
    em::key_t key(key_bv);
    la_status status = LA_STATUS_SUCCESS;

    // Check input correctness.
    if (!check_key_input(key)) {
        return LA_STATUS_EINVAL;
    }

    size_t key_width = key.get_width();
    size_t line_cfg_option = get_key_option_index(key_width);

    size_t bank_index;
    size_t entry_index;
    em_verifier_t dummy_verifier;

    // Find entry.
    if (!find_entry(key, line_cfg_option, bank_index, entry_index, dummy_verifier)) {
        return LA_STATUS_ENOTFOUND;
    }

    // Remove entry.
    if (bank_index == m_num_of_banks) {
        // CAM entry.
        em_cam_entry& entry(get_cam_entry(entry_index));
        entry.m_valid = false;

        log_debug(TABLES, "em_core::remove(cam, entry: %zd, key: %s)", entry_index, key.to_string().c_str());
        status = erase_from_physical_cam(entry_index);
        return_on_error(status);
    } else {
        // Bank entry.
        em_bank_entry& entry(get_bank_entry(bank_index, entry_index));
        entry.m_valid = false;

        log_debug(TABLES, "em_core::remove(bank: %zd, entry: %zd, key: %s)", bank_index, entry_index, key.to_string().c_str());
        status = erase_from_physical_bank(bank_index, entry_index);
        return_on_error(status);
    }

    --m_num_entries;
    if (m_resource_monitor != nullptr) {
        size_t current_size = size();
        m_resource_monitor->update_size(current_size);
    }

    if (get_utilization_percentage() <= HIGHEST_UTILIZATION_FOR_MOVINGS) {
        m_max_moving_depth = m_orig_max_moving_depth;
    }

    return status;
}

la_status
em_core::erase(const bit_vector& key_bv, size_t payload_width)
{
    em::key_t key(key_bv);
    la_status status = LA_STATUS_SUCCESS;

    // Check input correctness.
    if (!check_key_input(key)) {
        return LA_STATUS_EINVAL;
    }

    size_t key_width = key.get_width();
    size_t line_cfg_option = get_line_config_option_index(key_width, payload_width);

    size_t bank_index;
    size_t entry_index;
    em_verifier_t dummy_verifier;

    // Find entry.
    if (!find_entry(key, line_cfg_option, bank_index, entry_index, dummy_verifier)) {
        return LA_STATUS_ENOTFOUND;
    }

    // Remove entry.
    if (bank_index == m_num_of_banks) {
        // CAM entry.
        em_cam_entry& entry(get_cam_entry(entry_index));
        entry.m_valid = false;

        log_debug(TABLES, "em_core::remove(cam, entry: %zd, key: %s)", entry_index, key.to_string().c_str());
        status = erase_from_physical_cam(entry_index);
        return_on_error(status);
    } else {
        // Bank entry.
        em_bank_entry& entry(get_bank_entry(bank_index, entry_index));
        entry.m_valid = false;

        log_debug(TABLES, "em_core::remove(bank: %zd, entry: %zd, key: %s)", bank_index, entry_index, key.to_string().c_str());
        status = erase_from_physical_bank(bank_index, entry_index);
        return_on_error(status);
    }

    --m_num_entries;
    if (m_resource_monitor != nullptr) {
        size_t current_size = size();
        m_resource_monitor->update_size(current_size);
    }

    if (get_utilization_percentage() <= HIGHEST_UTILIZATION_FOR_MOVINGS) {
        m_max_moving_depth = m_orig_max_moving_depth;
    }

    return status;
}

bool
em_core::is_flexible_entry_supported() const
{
    return m_flexible_entry;
}

la_status
em_core::update(const bit_vector& key_bv, const bit_vector& payload_bv)
{
    em::payload_t payload(payload_bv);
    em::key_t key(key_bv);

    // Check inputs correctness.
    if (!check_key_payload_inputs(key, payload)) {
        return LA_STATUS_EINVAL;
    }

    size_t key_width = key.get_width();
    size_t payload_width = payload.get_width();
    size_t line_cfg_option = get_line_config_option_index(key_width, payload_width);

    size_t bank_index;
    size_t entry_index;
    em_verifier_t verifier;

    // Find entry.
    if (!find_entry(key, line_cfg_option, bank_index, entry_index, verifier)) {
        return LA_STATUS_ENOTFOUND;
    }

    // Update entry.
    if (bank_index == m_num_of_banks) {
        // CAM entry.
        em_cam_entry& entry(get_cam_entry(entry_index));
        entry.m_payload = payload;

        log_debug(TABLES,
                  "em_core::update(cam, entry: %zd, key: %s, payload: %s)",
                  entry_index,
                  key.to_string().c_str(),
                  payload.to_string().c_str());
        return write_to_physical_cam(entry_index, key, payload);
    }

    // Bank entry.
    em_bank_entry& entry(get_bank_entry(bank_index, entry_index));
    entry.m_payload = payload;

    log_debug(TABLES,
              "em_core::update(bank: %zd, entry: %zd, key: %s, payload: %s)",
              bank_index,
              entry_index,
              key.to_string().c_str(),
              payload.to_string().c_str());

    return write_to_physical_bank(bank_index, entry_index, key, line_cfg_option, verifier, payload);
}

la_status
em_core::lookup(const bit_vector& key_bv, bit_vector& out_payload) const
{
    em::key_t key(key_bv);

    // Check input correctness.
    if (!check_key_input(key)) {
        return LA_STATUS_EINVAL;
    }

    size_t key_width = key.get_width();
    size_t payload_width = out_payload.get_width();
    size_t line_cfg_option = get_line_config_option_index(key_width, payload_width);

    size_t bank_index;
    size_t entry_index;
    em_verifier_t dummy_verifier;

    // Find entry.
    if (!find_entry(key, line_cfg_option, bank_index, entry_index, dummy_verifier)) {
        return LA_STATUS_ENOTFOUND;
    }

    // Return payload.
    if (bank_index == m_num_of_banks) {
        // CAM entry.
        const em_cam_entry& entry(get_cam_entry(entry_index));
        out_payload = entry.m_payload;
    } else {
        // Bank entry.
        const em_bank_entry& entry(get_bank_entry(bank_index, entry_index));
        out_payload = entry.m_payload;
    }

    return LA_STATUS_SUCCESS;
}

const physical_em*
em_core::get_physical_em() const
{
    return &m_em;
}

bool
em_core::check_key_payload_inputs(const em::key_t& key, const em::payload_t& payload) const
{
    // Check key input.
    if (!check_key_input(key)) {
        return false;
    }

    // The sum of payload width and key width should be a constant width.
    size_t key_width = key.get_width();
    size_t payload_width = payload.get_width();
    if (is_flexible_entry_supported()) {
        if (key_width + payload_width > m_entry_width) {
            return false;
        }
    } else {
        if (key_width + payload_width != m_entry_width) {
            return false;
        }
    }
    return true;
}

bool
em_core::check_key_input(const em::key_t& key) const
{
    // Only specific key widths are allowed.
    size_t key_width = key.get_width();
    size_t key_idx = get_key_option_index(key_width);
    if (key_idx == EM_NULL_INDEX) {
        return false;
    }

    return true;
}

bool
em_core::find_entry(const em::key_t& key,
                    size_t& line_cfg_option,
                    size_t& out_bank_index,
                    size_t& out_entry_index,
                    em_verifier_t& out_verifier) const
{
    out_bank_index = EM_NULL_INDEX;
    out_entry_index = EM_NULL_INDEX;

    bool has_flexible_entry_support = is_flexible_entry_supported();

    // Look in banks
    for (size_t bank_index = 0; bank_index < m_num_of_banks; bank_index++) {

        if (!m_em.banks[bank_index].is_active) {
            continue;
        }

        em_hashed_value hashed_key(calc_hash(bank_index, key));
        size_t entry_index = hashed_key.m_entry_index;
        const em_verifier_t& verifier = hashed_key.m_verifier;

        const em_bank_entry& entry(get_bank_entry(bank_index, entry_index));

        if (!entry.m_valid) {
            // Found free entry, save first free entry in case given entry not found.
            if (out_bank_index == EM_NULL_INDEX && out_entry_index == EM_NULL_INDEX) {
                out_bank_index = bank_index;
                out_entry_index = entry_index;
                out_verifier = verifier;
            }
        } else if (verifier == entry.m_verifier) {
            if (!has_flexible_entry_support || (has_flexible_entry_support && line_cfg_option == entry.line_cfg_index)) {
                // Found if entry is valid and matches given key's verifier (optional: matches line config).
                out_bank_index = bank_index;
                out_entry_index = entry_index;
                out_verifier = verifier;

                return true;
            }
        }
    }

    // Look in CAM
    for (size_t cam_index = 0; cam_index < m_num_of_cam_entries; cam_index++) {
        const em_cam_entry& entry(get_cam_entry(cam_index));

        if (!entry.m_valid) {
            // Found free entry, save first free entry in case given entry not found.
            if (out_bank_index == EM_NULL_INDEX && out_entry_index == EM_NULL_INDEX) {
                out_bank_index = m_num_of_banks;
                out_entry_index = cam_index;
            }
        } else if (key == entry.m_key) {
            // Found if entry is valid and matches given key.
            out_bank_index = m_num_of_banks;
            out_entry_index = cam_index;

            return true;
        }
    }

    return false;
}

const em_core::em_bank_entry&
em_core::get_bank_entry(size_t bank_index, size_t entry_index) const
{
    const em_bank_t& bank(m_banks[bank_index]);

    return bank[entry_index];
}

em_core::em_bank_entry&
em_core::get_bank_entry(size_t bank_index, size_t entry_index)
{
    em_bank_t& bank(m_banks[bank_index]);

    return bank[entry_index];
}

const em_core::em_cam_entry&
em_core::get_cam_entry(size_t entry_index) const
{
    return m_cam[entry_index];
}

em_core::em_cam_entry&
em_core::get_cam_entry(size_t entry_index)
{
    return m_cam[entry_index];
}

bool
em_core::insert_entry_to_banks(const em::key_t& key,
                               const em::payload_t& payload,
                               size_t free_bank_index,
                               size_t free_entry_index,
                               size_t line_cfg_option_index,
                               em_verifier_t& verifier,
                               hw_entries_vec_t& entries_to_write)
{
    // If no free entry in bank, try to handle collisions.
    if (free_bank_index >= m_num_of_banks || free_entry_index == EM_NULL_INDEX) {

        // Handle collision: move entries to make room for given entry.
        // If entry is found, bank, index and verifier are got updated to the new free location.
        if (!handle_collision_banks(key, free_bank_index, free_entry_index, verifier, entries_to_write)) {
            return false;
        }
    }

    em_bank_entry& free_entry(get_bank_entry(free_bank_index, free_entry_index));
    free_entry = {true /* valid */, line_cfg_option_index, key, verifier, payload};

    // HW write
    log_debug(TABLES,
              "em_core::insert_entry_to_banks(bank: %zd, entry: %zd, key: %s, payload: %s)",
              free_bank_index,
              free_entry_index,
              key.to_string().c_str(),
              payload.to_string().c_str());
    entries_to_write.push_back({free_bank_index, free_entry_index, key, line_cfg_option_index, verifier, payload});

    return true;
}

bool
em_core::insert_entry_to_cam(const em::key_t& key,
                             const em::payload_t& payload,
                             size_t free_entry_index,
                             hw_entries_vec_t& entries_to_write)
{
    // If no free entry in CAM, try to handle collisions.
    if (free_entry_index == EM_NULL_INDEX) {

        // Handle collision CAM: move entries from CAM to make room for given entry.
        if (!handle_collision_cam(key, free_entry_index, entries_to_write)) {
            return false;
        }
    }

    em_cam_entry& free_entry(get_cam_entry(free_entry_index));
    free_entry = {true /* valid */, key, payload};

    log_debug(TABLES,
              "em_core::insert_entry_to_cam(entry: %zd, key: %s, payload: %s)",
              free_entry_index,
              key.to_string().c_str(),
              payload.to_string().c_str());
    entries_to_write.push_back({m_num_of_banks, free_entry_index, key, EM_NULL_INDEX, em::key_t(), payload});

    return true;
}

em_core::em_hashed_value
em_core::calc_hash(size_t bank_index, const em::key_t& key) const
{
    size_t key_width = key.get_width();
    em_hasher_scptr hasher = get_hasher(key_width, bank_index);
    dassert_crit(hasher);

    em::key_t hashed_key(hasher->encrypt(key));

    size_t num_of_address_bits = bit_utils::bits_to_represent(m_num_of_bank_entries - 1);
    size_t entry_index = hashed_key.bits_from_msb(0, num_of_address_bits).get_value();

    size_t verifier_width = key_width - num_of_address_bits;
    em_verifier_t verifier(0, verifier_width);
    verifier.set_bits(verifier_width - 1, 0, hashed_key);

    return {entry_index, verifier};
}

bool
em_core::handle_collision_banks(const em::key_t& key,
                                size_t& out_bank_index,
                                size_t& out_entry_index,
                                em_verifier_t& out_verifier,
                                hw_entries_vec_t& entries_to_write)
{
    if (m_max_moving_depth == 0) {
        return false;
    }

    em_moving_candidates_vec_t moving_candidates;
    std::vector<em_verifier_t> verifiers(m_num_of_banks);

    // The entries that congesting with key are the first candidates.
    for (size_t bank_index = 0; bank_index < m_num_of_banks; bank_index++) {
        if (!m_em.banks[bank_index].is_active) {
            continue;
        }

        const auto& hashed_value(calc_hash(bank_index, key));
        size_t entry_index = hashed_value.m_entry_index;
        verifiers[bank_index] = hashed_value.m_verifier;

        const em::key_t& candidate_key = get_bank_entry(bank_index, entry_index).m_key;
        candidate_entry_indices candidate
            = {bank_index, entry_index, 1 /* one move */, EM_NULL_INDEX /* no parent */, candidate_key};

        moving_candidates.push_back(candidate);
    }

    bool success = check_and_move_candidates(moving_candidates, out_bank_index, out_entry_index, entries_to_write);
    if (success) {
        out_verifier = verifiers[out_bank_index];
    }

    return success;
}

bool
em_core::handle_collision_cam(const em::key_t& key, size_t& out_entry_index, hw_entries_vec_t& entries_to_write)
{
    if (m_max_moving_depth == 0 || m_is_cam_evacuation_disabled) {
        return false;
    }

    em_moving_candidates_vec_t moving_candidates;

    // CAM entries can be moved to bank then free slot will be available.
    for (size_t entry_index = 0; entry_index < m_num_of_cam_entries; entry_index++) {
        em::key_t candidate_key(m_cam[entry_index].m_key);
        candidate_entry_indices candidate
            = {m_num_of_banks, entry_index, 1 /* one move */, EM_NULL_INDEX /* no parent */, candidate_key};

        moving_candidates.push_back(candidate);
    }

    size_t dummy_bank_index;
    bool cam_have_been_evacuated
        = check_and_move_candidates(moving_candidates, dummy_bank_index, out_entry_index, entries_to_write);
    if (!cam_have_been_evacuated) {
        m_is_cam_evacuation_disabled = true;
    }
    return cam_have_been_evacuated;
}

bool
em_core::check_and_move_candidates(em_moving_candidates_vec_t& moving_candidates,
                                   size_t& out_bank_index,
                                   size_t& out_entry_index,
                                   hw_entries_vec_t& entries_to_write)
{
    // Iterating one by one, vector size increases inside loop.
    size_t vec_index = 0;
    while (moving_candidates.size() > vec_index) {
        const auto& candidate(moving_candidates[vec_index]);
        em::key_t candidate_key(candidate.m_key);
        size_t candidate_bank_index = candidate.m_bank_index;

        // Look for free entry to move candidate to. Insert congestions to candidates vector.
        size_t moving_depth = candidate.m_moving_depth + 1;
        for (size_t bank_index = 0; bank_index < m_num_of_banks; bank_index++) {
            // Skip candidate checking itself.
            if (bank_index == candidate_bank_index || !m_em.banks[bank_index].is_active) {
                continue;
            }

            em_hashed_value hashed_key(calc_hash(bank_index, candidate_key));
            size_t entry_index = hashed_key.m_entry_index;
            const em_bank_entry& entry(get_bank_entry(bank_index, entry_index));

            // Free entry is invalid one. Move entries and return.
            // bank and entry indices are updated to the new empty location.
            if (!entry.m_valid) {
                move_entries(moving_candidates, vec_index, bank_index, entry_index, entries_to_write);
                out_bank_index = bank_index;
                out_entry_index = entry_index;

                return true;
            }

            // If moving depth exceeds maximum, don't add more candidates.
            if (moving_depth <= m_max_moving_depth) {
                const em::key_t& next_candidate_key(entry.m_key);
                moving_candidates.push_back({bank_index, entry_index, moving_depth, vec_index, next_candidate_key});
            }
        }

        vec_index++;
    }

    return false;
}

void
em_core::move_entries(const em_moving_candidates_vec_t& moving_candidates,
                      size_t from_index,
                      size_t& free_bank_index,
                      size_t& free_entry_index,
                      hw_entries_vec_t& entries_to_write)
{
    // EM_NULL_INDEX as an origin means we reached the entry we started with.
    while (from_index != EM_NULL_INDEX) {
        em::key_t from_key;
        em::payload_t from_payload;
        size_t from_line_cfg;

        // Get entry to move.
        const auto& candidate(moving_candidates[from_index]);
        if (candidate.m_bank_index == m_num_of_banks) {
            // CAM entry.
            const em_cam_entry& from_entry(get_cam_entry(candidate.m_entry_index));
            from_key = from_entry.m_key;
            from_payload = from_entry.m_payload;
            size_t key_width = from_key.get_width();
            size_t payload_width = from_payload.get_width();
            from_line_cfg = get_line_config_option_index(key_width, payload_width);
        } else {
            // Bank entry.
            const em_bank_entry& from_entry(get_bank_entry(candidate.m_bank_index, candidate.m_entry_index));
            from_key = from_entry.m_key;
            from_payload = from_entry.m_payload;
            from_line_cfg = from_entry.line_cfg_index;
        }

        // Get free entry and overwrite it. Could only be a bank free entry.
        em_verifier_t verifier(calc_hash(free_bank_index, candidate.m_key).m_verifier);
        em_bank_entry& to_entry(get_bank_entry(free_bank_index, free_entry_index));
        to_entry = {true /* valid */, from_line_cfg, from_key, verifier, from_payload};

        log_debug(TABLES,
                  "em_core::move_entries(bank: %zd, entry: %zd, key: %s, payload: %s)",
                  free_bank_index,
                  free_entry_index,
                  from_key.to_string().c_str(),
                  from_payload.to_string().c_str());
        entries_to_write.push_back({free_bank_index, free_entry_index, from_key, from_line_cfg, verifier, from_payload});

        // Update indices to point to next entry to move and new free entry.
        from_index = candidate.m_parent_candidate_index;
        free_bank_index = candidate.m_bank_index;
        free_entry_index = candidate.m_entry_index;
    }

    // Invalidate last moved entry.
    // No need to update HW since this entry will be filled with the new addition.
    if (free_bank_index == m_num_of_banks) {
        // CAM entry.
        em_cam_entry& moved_entry(get_cam_entry(free_entry_index));
        moved_entry.m_valid = false;
    } else {
        // Bank entry.
        em_bank_entry& moved_entry(get_bank_entry(free_bank_index, free_entry_index));
        moved_entry.m_valid = false;
    }
}

em_hasher_scptr
em_core::get_hasher(size_t key_width, size_t bank_index) const
{
    for (const auto& width_hashers_pair : m_hashers) {
        if (width_hashers_pair.first == key_width && bank_index < m_num_of_banks) {
            return width_hashers_pair.second[bank_index];
        }
    }

    return nullptr;
}

size_t
em_core::get_line_config_option_index(size_t key_width, size_t payload_width) const
{
    if (!is_flexible_entry_supported()) {
        /*
         * Tables that don't support flex ems and pac/gb could use this option.
         * Eventually they could move to line_cfg model
         */
        return get_key_option_index(key_width);
    }

    for (size_t idx = 0; idx < m_em.line_cfg.size(); ++idx) {
        if ((m_em.line_cfg[idx].first == key_width) && (m_em.line_cfg[idx].second == payload_width)) {
            return idx;
        }
    }
    return EM_NULL_INDEX;
}

size_t
em_core::get_key_option_index(size_t key_width) const
{
    for (size_t idx = 0; idx < m_hashers.size(); ++idx) {
        if (m_hashers[idx].first == key_width) {
            return idx;
        }
    }

    return EM_NULL_INDEX;
}

la_status
em_core::write_to_physical_em(const hw_entries_vec_t& entires_to_write)
{
    la_status status = LA_STATUS_SUCCESS;

    for (const hw_entry& entry : entires_to_write) {
        if (entry.bank_index == m_num_of_banks) {
            // cam entry
            status = write_to_physical_cam(entry.entry_index, entry.key, entry.payload);
        } else {
            status = write_to_physical_bank(
                entry.bank_index, entry.entry_index, entry.key, entry.line_cfg_index, entry.verifier, entry.payload);
        }

        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
em_core::write_to_physical_bank(size_t bank_idx,
                                size_t entry_idx,
                                const em::key_t& key,
                                size_t line_cfg_index,
                                const em::key_t& verifier,
                                const em::payload_t& payload)
{

    const physical_em::bank& bank = m_em.banks[bank_idx];
    if (!bank.is_active) {
        return LA_STATUS_EACCES;
    }

    dassert_crit(line_cfg_index != EM_NULL_INDEX);
    // If Low Level device was not initialized, just return.
    if (!m_ll_device) {
        return LA_STATUS_SUCCESS;
    }

    bool has_flexible_entry_support = is_flexible_entry_supported();
    size_t key_width_index = line_cfg_index;

    size_t key_size_field_width;
    size_t valid_bit_field_size = 0;
    if (has_flexible_entry_support) {
        key_size_field_width = bit_utils::bits_to_represent(m_em.line_cfg.size() - 1);
        valid_bit_field_size = 1;
    } else {
        key_size_field_width = bit_utils::bits_to_represent(m_em.key_widths.size());
    }

    size_t calculated_width
        = verifier.get_width() + payload.get_width() + key_size_field_width + valid_bit_field_size + m_em.ecc_width;
    if (has_flexible_entry_support) {
        if (calculated_width > m_em.bank_width) {
            dassert_crit(false);
            return LA_STATUS_EINVAL;
        }
    } else {
        if (calculated_width != m_em.bank_width) {
            dassert_crit(false);
            return LA_STATUS_EINVAL;
        }
    }

    // Preparing value to be written.
    //
    // The structure is (starting from LSB)
    // Regular EM
    // 1. Payload
    // 2. Key verifier - LSB from encrypted key.
    // 3. Key width option/valid bit. 1 or 2 bits according to number of EM keys.
    // 4. ECC
    // Flexible EM
    // 1. Dontcare
    // 2. Payload
    // 3. Key verifier - LSB from encrypted key.
    // 4. Valid bit
    // 5. Line config
    // 6. ECC

    size_t dontcare_size = m_em.bank_width - calculated_width;

    bit_vector384_t value(0);
    value.resize(m_em.bank_width);

    size_t payload_lsb = dontcare_size;
    size_t payload_msb = payload_lsb + payload.get_width() - 1;
    value.set_bits(payload_msb, payload_lsb, payload);

    size_t verifier_lsb = payload_msb + 1;
    size_t verifier_msb = verifier_lsb + verifier.get_width() - 1;
    value.set_bits(verifier_msb, verifier_lsb, verifier);

    // add a valid bit if this is a flexible entry
    size_t key_width_enc_msb;
    size_t key_width_enc_lsb;
    if (has_flexible_entry_support) {
        // valid bit set
        // Key size encoding as following:
        // 0 - largest key
        // 1 - 2'nd key option
        // 2 - 3'rd key option
        // and so on
        size_t valid_bit_pos = verifier_msb + 1;
        value.set_bit(valid_bit_pos, 1);
        key_width_enc_lsb = valid_bit_pos + 1;
        key_width_enc_msb = valid_bit_pos + key_size_field_width;
    } else {
        // Key size encoding as following:
        // 0 - invalid line
        // 1 - largest key
        // 2 - 2'nd key option
        // 3 - 3'rd key option
        key_width_index += 1;
        key_width_enc_lsb = verifier_msb + 1;
        key_width_enc_msb = verifier_msb + key_size_field_width;
    }
    bit_vector key_width_enc(key_width_index, key_size_field_width);
    value.set_bits(key_width_enc_msb, key_width_enc_lsb, key_width_enc);

    // Ecc
    if (!m_em.skip_ecc_calc) {
        add_ecc_to_em_entry(value, key_width_enc_msb + 1 /*ecc lsb*/);
    }

    log_debug(TABLES,
              "em_core::write_to_physical_bank(ecc: %s, key_size: %zd, key_width_encoding:%s, verifier: %s, full entry: %s)",
              value.bits_from_msb(0, value.get_width() - key_width_enc_msb - 1).to_string().c_str(),
              key_width_index + 1,
              key_width_enc.to_string().c_str(),
              verifier.to_string().c_str(),
              value.to_string().c_str());

    // Write value
    la_status status = m_ll_device->write_memory(*bank.memory, entry_idx, value);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
em_core::erase_from_physical_bank(size_t bank_idx, size_t entry_idx)
{
    // If Low Level device was not initialized, just return.
    if (!m_ll_device) {
        return LA_STATUS_SUCCESS;
    }

    const physical_em::bank& bank = m_em.banks[bank_idx];
    if (!bank.is_active) {
        return LA_STATUS_EACCES;
    }

    // Invalid bit is 0. Nothing more is need to be done.
    bit_vector value;
    value.resize(m_em.bank_width);

    // Write value
    la_status status = m_ll_device->write_memory(*bank.memory, entry_idx, value);
    return_on_error(status);

    m_is_cam_evacuation_disabled = false;

    return LA_STATUS_SUCCESS;
}

la_status
em_core::write_to_physical_cam(size_t entry_idx, const em::key_t& key, const em::payload_t& payload)
{
    // If Low Level device was not initialized, just return.
    if (!m_ll_device) {
        return LA_STATUS_SUCCESS;
    }
    // CAM key field width is always the widest key.
    size_t primary_key_width = m_em.key_widths[0];
    // CAM payload field width is always the widest payload (which is deducted from the smallest key).
    size_t payload_width = m_em.data_width - m_em.key_widths.back();

    size_t key_lsb = payload_width;
    size_t valid_bit = key_lsb + primary_key_width;

    bit_vector cam_value(0, valid_bit + 1 /*width*/);
    cam_value.set_bits(key_lsb - 1, 0, payload);
    cam_value.set_bits(valid_bit - 1, key_lsb, key);
    cam_value.set_bit(valid_bit, true);

    // Find the CAM to write to
    size_t cam_line = entry_idx;
    lld_memory_scptr cam_to_write;
    for (const lld_memory_scptr& cam : m_em.cams) {
        const lld_memory_desc_t* desc = cam->get_desc();
        if (cam_line < desc->entries) {
            cam_to_write = cam;
            break;
        }
        cam_line -= desc->entries;
    }

    // Write value
    dassert_crit(cam_to_write);
    la_status status = m_ll_device->write_memory(*cam_to_write, cam_line, cam_value);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
em_core::erase_from_physical_cam(size_t entry_idx)
{
    // If Low Level device was not initialized, just return.
    if (!m_ll_device) {
        return LA_STATUS_SUCCESS;
    }

    // CAM key field width is always the widest key.
    size_t primary_key_width = m_em.key_widths[0];
    // CAM payload field widht is always the widest payload (which is deducted from the smallest key.
    size_t payload_width = m_em.data_width - m_em.key_widths.back();

    size_t valid_bit = primary_key_width + payload_width;

    bit_vector cam_value(0, valid_bit + 1 /*width*/);
    cam_value.set_bit(valid_bit, false);

    // Find the CAM to write to
    size_t cam_line = entry_idx;
    lld_memory_scptr cam_to_write;
    for (const lld_memory_scptr& cam : m_em.cams) {
        const lld_memory_desc_t* desc = cam->get_desc();
        if (cam_line < desc->entries) {
            cam_to_write = cam;
            break;
        }
        cam_line -= desc->entries;
    }

    // Write value
    dassert_crit(cam_to_write);
    la_status status = m_ll_device->write_memory(*cam_to_write, cam_line, cam_value);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

void
em_core::add_ecc_to_em_entry(bit_vector384_t& entry, size_t ecc_lsb)
{
    size_t data_width = ecc_lsb;
    size_t ecc_msb = entry.get_width() - 1;
    size_t ecc_width = entry.get_width() - ecc_lsb;

    entry.set_bits(ecc_msb, ecc_lsb, 0 /*initial value*/);

    // Create mixed data and zeros vector, according to what we see in HW
    bit_vector384_t mixed_data(0, 2);
    size_t seg_len = 2;
    size_t data_pos = 0;
    size_t mixed_data_pos = 2;
    while (data_pos < data_width) {
        mixed_data.set_bit(mixed_data_pos, 0);
        mixed_data_pos++;
        for (size_t i = 0; i < seg_len - 1 && data_pos < data_width; ++i) {
            bool data_bit = entry.bit(data_pos);
            mixed_data.set_bit(mixed_data_pos, data_bit);
            data_pos++;
            mixed_data_pos++;
        }
        seg_len *= 2;
    }

    // Run parity
    size_t mixed_data_width = mixed_data.get_width();
    for (size_t ecc_idx = 0, ecc_pos = ecc_lsb; ecc_idx < ecc_width - 1; ++ecc_idx, ++ecc_pos) {
        size_t addr_pos = (1 << ecc_idx);
        bool ecc_val = entry.bit(ecc_pos);
        bool ecc_calc_val = ecc_val;
        for (size_t data_idx = 1; data_idx < mixed_data_width; ++data_idx) {
            if (data_idx & addr_pos) {
                bool data_val = mixed_data.bit(data_idx);
                ecc_calc_val = ecc_calc_val ^ data_val;
            }
        }
        entry.set_bit(ecc_pos, ecc_calc_val);
    }

    // Run parity for MSB
    bool ecc_msb_val = (entry.count_ones() % 2) == 1;
    entry.set_bit(ecc_msb, ecc_msb_val);
}

void
em_core::init_hashers()
{
    for (size_t key_width : m_em.key_widths) {

        // Prepare crc divisors
        em::hasher_params hasher_params;
        generate_default_hasher_params(key_width, 0, hasher_params);

        std::vector<em_hasher_scptr> per_bank_hashers;
        for (size_t bank_index = 0; bank_index < m_num_of_banks; bank_index++) {
            // modify rc5 - the rest is the same for all banks
            hasher_params.rc5_parameter = m_em.banks[bank_index].rc5;

            per_bank_hashers.push_back(std::make_shared<em_hasher>(key_width, hasher_params));
        }

        m_hashers.push_back(make_pair(key_width, per_bank_hashers));
    }
}

size_t
em_core::max_size() const
{
    return m_num_of_banks * m_num_of_bank_entries + m_num_of_cam_entries;
}

la_status
em_core::get_physical_usage(size_t num_of_table_logical_entries, size_t& out_physical_usage) const
{
    out_physical_usage = 0;
    return LA_STATUS_ENOTIMPLEMENTED;
};

la_status
em_core::get_available_entries(size_t& out_available_entries) const
{
    out_available_entries = 0;
    return LA_STATUS_ENOTIMPLEMENTED;
};

la_status
em_core::set_resource_monitor(const resource_monitor_sptr& monitor)
{
    m_resource_monitor = monitor;

    return LA_STATUS_SUCCESS;
}

la_status
em_core::get_resource_monitor(resource_monitor_sptr& out_monitor) const
{
    out_monitor = m_resource_monitor;

    return LA_STATUS_SUCCESS;
}

size_t
em_core::size() const
{
    return m_num_entries;
}

double
em_core::get_utilization_percentage()
{
    return static_cast<double>(size()) / static_cast<double>(max_size() + m_num_of_cam_entries);
}

} // namespace silicon_one
