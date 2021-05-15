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

#ifndef __COUNTER_LOGICAL_BANK_H__
#define __COUNTER_LOGICAL_BANK_H__

#include <cstddef>
#include <cstdint>
#include <vector>

#include "api/qos/la_meter_set.h"
#include "api/types/la_common_types.h"
#include "common/la_status.h"
#include "counter_allocation.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "system/counter_bank_utils.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

// Number of rows in banks
enum {
    MAX_LOGICAL_ROWS_IN_COUNTER_BANK = 8 * 1024,
    MAX_LOGICAL_ROWS_IN_METER_BANK = 2 * 1024,
    ROWS_IN_HARDWARE_COUNTERS_BANK = 4 * 1024,
};

enum {
    COUNTER_BANK_BASE = 0,
    METER_BANK_BASE = 96, // Banks 96-108 has both meter entries and counter entries
    NUM_OF_BANKS = 108,   // Total number of banks
};

// A single physical bank_entry
class physical_bank_entry
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

private:
    friend class counter_logical_bank;
    // Address field in the counter_cpu_read register

    union counter_read_address_field {
        struct _c {
            uint32_t offset_in_bank : 14;
            uint32_t bank_id : 7;
        } c;
        uint32_t flat;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(counter_read_address_field);
    CEREAL_SUPPORT_PRIVATE_CLASS(counter_read_address_field::_c);

    physical_bank_entry(const la_device_impl_wptr& device, size_t phys_bank_index, size_t offset_in_bank);
    la_device_impl_wptr m_device;
    bool is_enabled;
    size_t bytes_count;
    size_t packet_count;
    size_t m_token_size; // for meter banks - token distributer attribiute
    counter_read_address_field m_counter_address;

    void disable();
    void enable();

    // Clears physical-counter values
    void clear();

    // Meter banks are configured at initialization
    // with maximum tokens rate for the shaper to distribute to the meters
    void read_token_size_from_device();

    size_t get_token_size();

    // Add the given values to the count data-members. This function is called
    // asynchronously by the counter-manager
    void add(size_t bytes, size_t packets);

    // Read counter values from the device
    void read(bool force_update, bool clear_on_read, size_t& out_bytes, size_t& out_packets);

    // Read the physical-counter values from the device and update the count data-members
    void update_counter_values_from_device();

    // dispatching reading physical-counter values from the device.
    void dispatch_read_counter_command(enum counter_read_command_e cmd);

    // Read the physical-counter values from the device.
    void read_counter_values_from_device(size_t& out_bytes, size_t& out_packets);

    enum {
        METER_TOKEN_DISTRIBUTER_MAX_SIZE = 12, // Hardware defined
    };

public:
    physical_bank_entry() = default; // For cereal. Need to be public because the class is used in a vector
    ~physical_bank_entry() = default;

    const la_device* get_device() const;
};

// Manage a logical bank, which consist of 1, 2 or 4 consecutive physical banks
class counter_logical_bank
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    counter_logical_bank() = default;
    //////////////////////////////
    friend class counter_manager;

    counter_logical_bank(const la_device_impl_wptr& device,
                         size_t first_index,
                         size_t first_slice,
                         bool is_slice_pair,
                         counter_direction_e direction,
                         const counter_user_group_vec& allowed_user_types);

    // Object life-cycle API-s
    la_status initialize();
    la_status destroy();

    // Get HW representation of user type.
    size_t get_user_type_encoding();

    // Return the compensation needed for the bytes count
    size_t get_npl_byte_count_compensation(counter_direction_e direction) const;

    // Find and allocate physical entries
    bool allocate(const counter_allocation& allocation, counter_user_type_e user_type, size_t& out_base_row_index);

    // Release an allocation
    void release(counter_user_type_e user_type, const counter_allocation& allocation);

    // Retrieve the counters of the given allocation
    void read_counter(const counter_allocation& allocation,
                      size_t sub_counter_index,
                      bool force_update,
                      bool clear_on_read,
                      size_t& out_bytes,
                      size_t& out_packets);
    void read_counter_ifg(const counter_allocation& allocation,
                          la_slice_ifg ifg,
                          size_t sub_counter_index,
                          bool force_update,
                          bool clear_on_read,
                          size_t& out_bytes,
                          size_t& out_packets);
    void read_meter(const counter_allocation& allocation,
                    size_t sub_counter_index,
                    la_qos_color_e color,
                    bool force_update,
                    bool clear_on_read,
                    uint64_t& out_bytes,
                    uint64_t& out_packets);
    void read_meter_ifg(const counter_allocation& allocation,
                        la_slice_ifg ifg,
                        size_t sub_counter_index,
                        la_qos_color_e color,
                        uint64_t& out_bytes,
                        uint64_t& out_packets);
    size_t get_phys_row(const counter_allocation& allocation, size_t sub_counter_index) const;
    size_t get_phys_row(const counter_allocation& allocation, size_t sub_counter_index, la_qos_color_e color) const;
    void do_read(const counter_allocation& allocation,
                 size_t row,
                 bool force_update,
                 bool clear_on_read,
                 uint64_t& out_bytes,
                 uint64_t& out_packets);
    void do_read_ifg(const counter_allocation& allocation,
                     la_slice_ifg ifg,
                     size_t sub_counter_index,
                     size_t phys_row,
                     bool force_update,
                     bool clear_on_read,
                     size_t& out_bytes,
                     size_t& out_packets);

    // Add values to a specific physical-counter
    void add(size_t slice, la_ifg_id_t ifg, size_t row_index, size_t bytes, size_t packets);

    // Check if the bank is empty
    bool is_empty() const;

    // Check whether the given row can accomodate the given allocation
    bool is_free_entries_in_row(size_t logical_row_index, const counter_allocation& allocation);

    // Mark the phys-counters needed by the given allocation as busy
    void enable_phys_counters(size_t logical_row_index, counter_user_type_e user_type, const counter_allocation& allocation);

    // Get the first IFG index in a row for the given allocation
    size_t get_first_ifg(const counter_allocation& allocation);

    // Return the number of physical counter rows per each counting object(counter or meter).
    size_t phys_per_logical() const;

    // Read and update shadow from the HW
    la_status update_shadow(size_t physical_bank_index, size_t physical_bank_id);

    // Calculate MSBs and LSBs of counter index in the shadow memory
    void get_shadow_indexes(size_t offset_in_bank,
                            size_t& bytes_counter_msb,
                            size_t& bytes_counter_lsb,
                            size_t& packets_counter_msb,
                            size_t& packets_counter_lsb) const;

    // Set shadow entry to zero
    void clear_counter_shadow_entry(size_t ifg, size_t bank_id, size_t offset_in_bank);

    // Save shadow value of cleared counter
    void update_clear_bank_entry(size_t ifg, size_t bank_id, size_t offset_in_bank);

    // String representation of the bank
    std::string to_string() const;

    // List of rows in the bank
    typedef std::vector<physical_bank_entry> phys_entry_row_t;
    std::vector<phys_entry_row_t> m_phys_entries;

    // Owning device
    la_device_impl_wptr m_device;

    // Index of the base physical bank
    size_t m_first_index;

    // Index of the base slice
    la_slice_id_t m_first_slice;

    // Types of objects associated with the counter bank
    counter_user_group_bitset m_allowed_user_types;

    // Either egress or ingress
    counter_direction_e m_direction;

    // Number of slices in the bank
    size_t m_num_of_slices;

    // Number of busy physical counters in the bank
    size_t m_num_of_busy_phys_entries;

    // Number of rows in the bank
    size_t m_num_logical_rows_in_bank;

    // Number of physical meter rows
    size_t m_num_physical_rows_in_bank;

    // Current utilization of the bank
    vector_alloc<std::array<size_t, COUNTER_USER_TYPE_NUM> > m_num_allocated_entries;

    std::chrono::time_point<std::chrono::steady_clock> m_last_shadow_update;
    std::vector<bit_vector> m_physical_bank_shadow;

    // virtual banks to save shadow value of the counter before clear
    std::vector<bit_vector> m_last_clear_bank;

public:
    // Need to be public because the class is used in a vector
    ~counter_logical_bank() = default;

public:
    // Return the index of the first physical bank
    size_t get_first_index() const;

    // Return the first slice in the bank
    size_t get_first_slice() const;

    // Check how many slices are in the bank
    size_t get_num_of_slices() const;

    // Return the type of object that is using the bank
    const counter_user_group_bitset& get_allowed_user_types() const;

    // Check if user type is meter.
    bool is_user_type_meter() const;

    // Check if user type is global.
    bool is_user_type_global() const;

    // Check if user type is allowed on the bank.
    bool is_user_type_allowed(counter_user_type_e user_type) const;

    // Get the direction of the counters in the bank
    counter_direction_e get_direction() const;

    // Helper functions
    la_status configure_counters_block_config_table(size_t first_slice, size_t num_of_slices, size_t first_index);
    la_status configure_rx_counter_table(size_t first_slice, size_t num_of_slices, size_t first_index, bool is_meter);
    la_status configure_tx_counter_table(size_t first_slice, size_t num_of_slices, size_t first_index);

    la_status erase_counters_block_config_table(size_t first_slice, size_t num_of_slices, size_t first_index);
    la_status erase_rx_counter_table(size_t first_slice, size_t num_of_slices, size_t first_index);
    la_status erase_tx_counter_table(size_t first_slice, size_t num_of_slices, size_t first_index);

    const la_device* get_device() const;

    /// @brief Retrieve the number of used banks.
    ///
    /// @retval Current number of used banks.
    const vector_alloc<std::array<size_t, COUNTER_USER_TYPE_NUM> >& size() const;

    /// @brief Retrieve the number of banks.
    ///
    /// @retval Number of banks.
    size_t max_size() const;

    /// @brief Retrive the number of counters allocated for a given user.
    ///
    /// @retval Number of counters.
    size_t num_of_allocated_counters_for_user(counter_user_type_e user_type) const;
};

} // namespace silicon_one

#endif // __COUNTER_LOGICAL_BANK_H_
