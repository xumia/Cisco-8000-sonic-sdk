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

#ifndef __CEM_H__
#define __CEM_H__

#include <bitset>
#include <unordered_map>
#include <vector>

#include "api/types/la_common_types.h"
#include "arc_cpu_common.h"
#include "common/bit_vector.h"
#include "common/la_status.h"
#include "common/resource_monitor.h"
#include "em_common.h"
#include "em_hasher.h"
#include <chrono>

#include "lld/lld_fwd.h"

namespace silicon_one
{

class ll_device;

/// @brief Entry location in Central Exact Match.
struct cem_location {
    bool valid;         ///< Whether found location is valid (out).
    size_t em_core_idx; ///< CDB core of found location (in/out).
    size_t em_bank_idx; ///< Bank within CDB core or ARC_CAM_BANK_IDX if it's CAM (in/out)
    size_t em_index;    ///< Index within the bank or CAM line (in/out)
    size_t key_size;    ///< EM key size option of the found location (0, 1 or 2, while 0 is the primary key size) (out).
};

constexpr std::chrono::seconds LA_ARC_RESPONSE_INTERVAL{1};
constexpr size_t STATUS_REGISTER_READ_ATTEMPTS = 3;

/// @brief Central exact match object.
///
/// Implements the CEM ARC protocol.
class cem
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    enum class entry_type_e {
        SINGLE_ENTRY,
        DOUBLE_ENTRY,
    };

    enum {
        EM_NEW_MAX_AGE = 7,                   ///< Max age for new record from owner device
        EM_NO_AGING_AGE = EM_NEW_MAX_AGE - 1, ///< No-aging value static records coming from CPU
        EM_REFRESH_AGE = EM_NEW_MAX_AGE - 2   ///< Refresh age - next value after MAX_AGE
    };

    struct cem_parameters {
        size_t num_banks;                       ///< Number of banks per EM core.
        size_t num_even_banks;                  ///< Number of even banks.
        bit_vector banks_configuration;         ///< on-bits - bank belongs to CEM
                                                ///< off-bits - bank belongs to LPM
        size_t cem_arc_cpu_register_start_addr; ///< Address of the first command register to the CEM ARC.

        static const cem_parameters get_params(la_device_revision_e device_revision);
    };

    struct cem_age_info {
        uint8_t age_owner : 1; ///< Age owner bit
        uint8_t age_value : 3; ///< Age value of a MAC entry
    };

    struct cdb_top_storage {
        lld_register_scptr arc_control_registers;
        lld_register_scptr arc_interrupt_masks;
        lld_register_scptr arc_mem_ccm_data;
        lld_register_scptr arc_mem_regs;
        lld_register_scptr arc_mem_start;

        lld_register_array_sptr access_reg;
        lld_register_scptr em_key_width;

        lld_memory_scptr cem_iccm;
        lld_memory_scptr cem_dccm;
        lld_memory_scptr counters;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(cdb_top_storage)
    /// @brief Construct a cem object.
    ///
    explicit cem(const ll_device_sptr& device);

    /// @brief Destroy a cem object.
    ///
    ~cem();

    /// @brief Initialize or reset CEM ARC.
    ///
    /// The following sequence is performed:
    /// 0. Stop ARC
    /// 1. Load microcode
    /// 2. Reset counters
    /// 3. Run ARC
    ///
    /// @param[in]  iccm_file           Full path to iccm firmware binary file.
    /// @param[in]  dccm_file           Full path to dccm firmware binary file.
    ///
    /// @retval return status code
    la_status init_arc(const std::string& iccm_file, const std::string& dccm_file);

    /// @brief Change Switch maximum MAC's connected to it.
    ///
    /// @param[in]  switch_id           switch_id to be limited.
    /// @param[in]  current_max_mac     Previous limit of MAC entries for the switch.
    /// @param[in]  new_max_mac         New limit to populate to the switch.
    ///
    /// @retval     status code.
    la_status set_switch_mac_limit(la_uint32_t switch_id, la_uint64_t current_max_mac, la_uint64_t new_max_mac);

    /// @brief Lookup given key in CEM.
    ///
    /// Command assumes, logical key is already concatenated with HW prefix in translation phase.
    ///
    /// @param[in]  key                 Key to look in CEM.
    /// @param[out] out_value_bv        Value of the found entry.
    /// @param[out] out_location        Location of the found entry.
    ///
    /// @retval     status code.
    la_status lookup(const bit_vector& key, bit_vector& out_payload_bv, cem_location& out_location);

    /// @brief Read and entry from the given location in CEM.
    /// In case, location contains wide entry, even bank index should be provided. Otherwise, the read is partial.
    ///
    /// @param[in]  location            Location to read.
    /// @param[in]  out_key_bv          Entry key in CEM.
    /// @param[out] out_value_bv        Entry value in CEM.
    ///
    /// @retval     status code.
    la_status read(const cem_location& location, bit_vector& out_key_bv, bit_vector& out_value_bv);

    /// @brief Read and entry's age info from the given entry in CEM.
    ///
    /// @param[in]  key                 The key of the entry
    /// @param[in]  value               The value
    /// @param[out] out_age_info        Entry age value in CEM.
    ///
    /// @retval     status code.
    la_status read_age(const bit_vector& key, const bit_vector& value, cem_age_info& out_age_info);

    /// @brief Set a new single bank entry to the EM table.
    ///
    /// Set table assumes logical key is already concatenated with HW prefix in translation phase.
    ///
    /// @param[in]  key                 The key of the entry
    /// @param[in]  value               The value
    ///
    /// @retval     status code.
    la_status set_table_single_entry(const bit_vector& key, const bit_vector& value);

    /// @brief Add a new single bank entry to the EM table.
    ///
    /// Insert table assumes logical key is already concatenated with HW prefix in translation phase.
    ///
    /// @param[in]  key                 The key of the entry
    /// @param[in]  value               The value
    ///
    /// @retval     status code.
    la_status insert_table_single_entry(const bit_vector& key, const bit_vector& value);

    /// @brief Update an existing single bank entry in the EM table.
    ///
    /// Update table assumes logical key is already concatenated with HW prefix in translation phase.
    ///
    /// @param[in]  key                 The key of the entry
    /// @param[in]  value               The value
    ///
    /// @retval     status code.
    la_status update_table_single_entry(const bit_vector& key, const bit_vector& value);

    /// @brief Remove a specific single bank entry from EM table.
    ///
    /// Erase table assumes logical key is already concatenated with HW prefix in translation phase
    ///
    /// @param[in]  key                 The key of the removed entry
    ///
    /// @retval     status code.
    la_status erase_table_single_entry(const bit_vector& key);

    /// @brief Set a new double bank entry to the EM table.
    ///
    /// Set table assumes logical key is already concatenated with HW prefix in translation phase.
    ///
    /// @param[in]  key                 The key of the entry
    /// @param[in]  value               The value
    ///
    /// @retval     status code.
    la_status set_table_double_entry(const bit_vector& key, const bit_vector& value);

    /// @brief Add a new double bank entry to the EM table.
    ///
    /// Insert table assumes logical key is already concatenated with HW prefix in translation phase.
    ///
    /// @param[in]  key                 The key of the entry
    /// @param[in]  value               The value
    ///
    /// @retval     status code.
    la_status insert_table_double_entry(const bit_vector& key, const bit_vector& value);

    /// @brief Update an existing double bank entry in the EM table.
    ///
    /// Update table assumes logical key is already concatenated with HW prefix in translation phase.
    ///
    /// @param[in]  key                 The key of the entry
    /// @param[in]  value               The value
    ///
    /// @retval     status code.
    la_status update_table_double_entry(const bit_vector& key, const bit_vector& value);

    /// @brief Remove a specific double bank entry from EM table.
    ///
    /// Erase table assumes logical key is already concatenated with HW prefix in translation phase
    ///
    /// @param[in]  key                 The key of the removed entry
    ///
    /// @retval     status code.
    la_status erase_table_double_entry(const bit_vector& key);

    /// @brief Confgure ARC MAC aging interval in unit of 100ms
    ///
    /// ARC aging uses cem_age_table.age_value and valid range is 0 to 5
    /// By controlling how often we do aging scrub, we can have 6 checks before
    /// age_value reach 0 and age out the MAC entry.
    ///
    /// @param[in]  interval            interval in 100ms ticks
    ///
    /// @retval     status code.
    la_status set_mac_aging_interval(uint32_t interval);

    /// @brief Set ARC's soft-reset mode.
    ///
    /// Soft reset will bring ARC to waiting state, no EM access.
    ///
    /// @param[in]  enabled             true for entering soft-reset mode, false otherwise.
    ///
    /// @retval     status code.
    la_status set_soft_reset_mode(bool enabled);

    /// @brief Get max size of CEM.
    ///
    /// @retval     size_t    max size of CEM.
    size_t max_size() const;

    /// @brief Retrieve percentage of the physical usage out of the total physical resource based on the table's type and it's
    /// number of logical entries.
    ///
    /// @param[in]  table_type                      Single/wide table type.
    /// @param[in]  num_of_table_logical_entries    Number of the logical entries that inserted to the CEM through this table.
    /// @param[out] out_physical_usage                    Physical entries occupied by the table.
    ///
    /// @retval     la_status
    la_status get_physical_usage(entry_type_e table_type, size_t num_of_table_logical_entries, size_t& out_physical_usage) const;

    /// @brief Retrieve estimation of the available entries left for table based on it's type.
    ///
    /// @param[in]  table_type                      Single/wide table type..
    /// @param[out]  out_available_entries                  Available entries left for table.
    ///
    /// @retval     la_status
    la_status get_available_entries(entry_type_e table_type, size_t& out_available_entries);

    /// @brief Set resource monitor.
    ///
    /// @param[in]  resource_monitor           Resource monitor.
    ///
    /// @retval     LA_STATUS_SUCCESS           Success.
    /// @retval     LA_STATUS_EUNKONWN          Internal error.
    la_status set_resource_monitor(const resource_monitor_sptr& monitor);

    /// @brief Get resource monitor.
    ///
    /// @param[out] out_resource_monitor        Resource monitor to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Success.
    /// @retval     LA_STATUS_EUNKONWN          Internal error.
    la_status get_resource_monitor(resource_monitor_sptr& out_monitor) const;

    /// @brief Get utilization data from ARC
    ///
    /// @retval     status code.
    la_status update_size();

    /// @brief If an entry was deleted then there is a possibility to evacuate CAM entry to SRAM.
    /// Each call check the next relevant CAM entry and try to evacuate it
    /// Relevant only for Pacific, since HW bug prevent doing it on ARC
    ///
    /// @retval     status code.
    la_status evacuate();

    /// @brief Retrieve the number of entries in the table.
    ///
    /// @retval Number of entries.
    size_t size() const;

    /// @brief Configure Local MAC learning related CEM ARC features
    ///
    /// @retval     LA_STATUS_SUCCESS           Success.
    /// @retval     LA_STATUS_EUNKONWN          Failed to set one of the features
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   Unknown/incorrect TLV
    la_status set_arc_local_mac_learning_features();

    /// @brief Configure System MAC learning related CEM ARC features
    ///
    /// @retval     LA_STATUS_SUCCESS           Success.
    /// @retval     LA_STATUS_EUNKONWN          Failed to set one of the features
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   Unknown/incorrect TLV
    la_status set_arc_system_mac_learning_features();

    /// @brief Retrieve currently configured CEM ARC features
    ///
    /// @retval     LA_STATUS_SUCCESS           Success.
    la_status get_arc_features();

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    cem() : m_cem_parameters()
    {
    }

    la_status init_arc(const std::string& iccm_file, const std::string& dccm_file, cdb_top_storage& cdb);
    template <class _Lambda>
    la_status for_each_cdb(_Lambda lambda);

    /// @brief Send command for arc to execute.
    ///
    /// @param[in]  command             Command for arc.
    /// @param[in]  cdb            cdb to operate on
    ///
    /// @retval     status code.
    la_status dispatch_arc_command(arc_cpu_command* command, cdb_top_storage& cdb) const;

    /// @brief Send command for arc to execute.
    ///
    /// @param[in]  command             Command for arc.
    ///
    /// @retval     status code.
    la_status dispatch_arc_command(arc_cpu_command* command);

    /// @brief Reads arc response
    ///
    /// @param[in]  resp                Data structure to fill.
    /// @param[in]  cdb            cdb to operate on
    ///
    /// @retval     status code.
    la_status read_arc_response(arc_cpu_command& resp, cdb_top_storage& cdb) const;

    /// @brief Notify ARC a command is waiting for execution.
    ///
    /// @param[out]  out_arc_command      The arc command to write the location of the inserted entry if succeeded.
    /// @param[in]  cdb            cdb to operate on
    ///
    /// Sets the CPU request bit in the ARC, and waits for execution to complete.
    la_status wait_response(arc_cpu_command* out_arc_command, cdb_top_storage& cdb) const;

    /// @brief Helper to table commands, preparing table command arguments.
    ///
    /// @param[in]  key                  The key of the entry
    /// @param[in]  value                The value
    ///
    /// @retval     command to be sent to ARC, with initialized arguments.
    arc_cpu_command init_table_command_params(const bit_vector& key, const bit_vector& value);

    /// @brief Reset ARC limit and occupacy counters to their initial values.
    /// @param[in]  cdb            cdb to operate on
    la_status reset_arc_counters(cdb_top_storage& cdb);

    /// @brief Load ARC firmware binary
    ///
    /// @param[in]  is_iccm              Whether ICCM or DCCM microcode.
    /// @param[in]  mem_entries          Maximal number of entries available.
    /// @param[in]  filename             Full path to binary file.
    /// @param[in]  cdb            cdb to operate on
    la_status load_arc_microcode(bool is_iccm, size_t mem_entries, const std::string& filename, cdb_top_storage& cdb);

private:
    using hashed_key = em::key_t;
    using cores_bitmap = std::bitset<NUM_EM_CORES>;

    enum {
        INVALID_CORE_OR_CAM = (size_t)-1,
    };

    struct wide_key_storage_data {
        std::vector<hashed_key> hashed_values;
        size_t core = INVALID_CORE_OR_CAM;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(wide_key_storage_data)

    void add_wide_key_to_shadow(const bit_vector& key, const arc_cpu_command arc_command, wide_key_storage_data& storage_data);
    bool erase_wide_key_from_shadow(const bit_vector& key, uint32_t core);

    // This function transfer to ARC em_key_width, which is a register used to map logical key to key-size.
    // Since HW alaways return double size for CAM's keys, em_key_width is needed for HW workaround.
    la_status set_key_size_map_value();
    // try to evacuate one current entry
    la_status evacuation_routine();
    void populate_wide_key_hashed_values(const bit_vector& key, wide_key_storage_data& storage_data) const;
    bit_vector generate_key_for_hasher(const bit_vector& key) const;
    uint32_t get_allowed_cores_bitmap_of_key(const wide_key_storage_data& storage_data) const;

    void poll_arc_done(arc_cpu_fsm_state_e expected_state, cdb_top_storage& cdb) const;

    la_status read_status_register_loop(bit_vector& out_message, cdb_top_storage& cdb) const;

    template <class _CDB_TOP>
    void initialize_cdb_top_references(_CDB_TOP& cdb_top, size_t idx)
    {
        m_cdb_top_storage[idx].arc_control_registers = cdb_top->arc_control_registers;
        m_cdb_top_storage[idx].arc_interrupt_masks = cdb_top->arc_interrupt_masks;
        m_cdb_top_storage[idx].arc_mem_ccm_data = cdb_top->arc_mem_ccm_data;
        m_cdb_top_storage[idx].arc_mem_regs = cdb_top->arc_mem_regs;
        m_cdb_top_storage[idx].arc_mem_start = cdb_top->arc_mem_start;

        m_cdb_top_storage[idx].access_reg = cdb_top->access_reg;

        m_cdb_top_storage[idx].cem_iccm = cdb_top->cem_iccm;
        m_cdb_top_storage[idx].cem_dccm = cdb_top->cem_dccm;
        m_cdb_top_storage[idx].counters = cdb_top->counters;
    }

    /// Low level device.
    ll_device_sptr m_ll_device;

    std::vector<em_hasher> m_hashers;

    // This map maps the wide keys to their storage data.
    std::unordered_map<bit_vector, wide_key_storage_data> m_wide_keys_to_storage_data;
    // This map maps the MSB half of the hashed keys to the cores they are stored in.
    std::unordered_map<hashed_key, cores_bitmap> m_hashed_keys_msb_to_cores_bitmap;

    // Each index of the external vector contains all the double keys in the CAM of core #index.
    std::vector<std::vector<bit_vector> > m_core_to_cam_keys;

    // bitset to mark cores which have erased entry since last evacuation
    uint32_t m_erase_bitset = 0;

    // currently evacuated core
    size_t m_curr_evacuation_core = 0;

    // index for next evacuation
    uint32_t m_evacuation_index = 0;

    // Resource monitor
    resource_monitor_sptr m_resource_monitor;
    size_t m_usage;

    const cem_parameters m_cem_parameters;

    std::vector<cdb_top_storage> m_cdb_top_storage;
};

} // namespace silicon_one

#endif // __CEM_H__
