// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __NSIM_CONFIG_INTERFACE_H__
#define __NSIM_CONFIG_INTERFACE_H__

#include <string>
#include <stdint.h>
#include <stdio.h>

#include "utils/nsim_bv.h"

struct udk_table_id_and_components;
namespace nsim
{
enum npu_host_slice_e { NPU_HOST_SLICE = 6 };

class nsim_table_listener;
class nsim_timer_listener;

class nsim_config_interface
{
public:
    virtual ~nsim_config_interface()
    {
    }

    /// @brief Inserts entry to exact table.
    ///
    /// @param[in]  table_name      Name of the NPL table.
    /// @param[in]  index           Instance index of the table.
    /// @param[in]  key             The key used for lookup the table.
    /// @param[in]  payload         Payload to return from the table if key was hit.
    ///
    /// @return true if entry was inserted successfuly, false otherwise.
    virtual bool insert_entry(std::string table_name, size_t index, const nsim::bit_vector& key, const nsim::bit_vector& payload)
        = 0;

    /// @brief Inserts entry to ternary table.
    ///
    /// @param[in]  table_name      Name of the NPL table.
    /// @param[in]  index           Instance index of the table.
    /// @param[in]  line            Line to use in the table.
    /// @param[in]  key             The key used for lookup the table.
    /// @param[in]  mask            The mask used for lookup the table.
    /// @param[in]  payload         Payload to return from the table if key was hit.
    ///
    /// @return true if entry was inserted successfuly, false otherwise.
    virtual bool insert_ternary_entry(std::string table_name,
                                      size_t index,
                                      size_t line,
                                      const nsim::bit_vector& key,
                                      const nsim::bit_vector& mask,
                                      const nsim::bit_vector& payload)
        = 0;

    /// @brief Inserts entry to lpm table.
    ///
    /// @param[in]  table_name      Name of the NPL table.
    /// @param[in]  index           Instance index of the table.
    /// @param[in]  key             The key used for lookup the table.
    /// @param[in]  length          Length of the prefix to use for matching the entry.
    /// @param[in]  payload         Payload to return from the table if key was hit.
    ///
    /// @return true if entry was inserted successfuly, false otherwise.
    virtual bool insert_lpm_entry(std::string table_name,
                                  size_t index,
                                  const nsim::bit_vector& key,
                                  size_t length,
                                  const nsim::bit_vector& payload)
        = 0;

    /// @brief Erases entry from exact table.
    ///
    /// @param[in]  table_name      Name of the NPL table.
    /// @param[in]  index           Instance index of the table.
    /// @param[in]  key             The key of the entry to delete.
    ///
    /// @return true if entry was erased successfuly, false otherwise.
    virtual bool erase_entry(std::string table_name, size_t index, const nsim::bit_vector& key) = 0;

    /// @brief Erases entry from ternary table.
    ///
    /// @param[in]  table_name      Name of the NPL table.
    /// @param[in]  index           Instance index of the table.
    /// @param[in]  line            Entry line to erase.
    ///
    /// @return true if entry was erased successfuly, false otherwise.
    virtual bool erase_ternary_entry(std::string table_name, size_t index, size_t line) = 0;

    /// @brief Erases entry from lpm table.
    ///
    /// @param[in]  table_name      Name of the NPL table.
    /// @param[in]  index           Instance index of the table.
    /// @param[in]  key             The key of the entry to erase.
    /// @param[in]  length          Length of the entry to erase.
    ///
    /// @return true if entry was erased successfuly, false otherwise.
    virtual bool erase_lpm_entry(std::string table_name, size_t index, const nsim::bit_vector& key, size_t length) = 0;

    /// @brief Gets entry to exact table.
    ///
    /// @param[in]  table_name      Name of the NPL table.
    /// @param[in]  index           Instance index of the table.
    /// @param[in]  key             The key used for lookup the table.
    /// @param[out] out_payload     Payload at key entry.
    ///
    /// @return true if entry was found successfuly, false otherwise.
    virtual bool get_entry(std::string table_name, size_t index, const nsim::bit_vector& key, nsim::bit_vector& out_payload) = 0;

    /// @brief Gets entry to ternary table.
    ///
    /// @param[in]  table_name      Name of the NPL table.
    /// @param[in]  index           Instance index of the table.
    /// @param[in]  line            Line to use in the table.
    /// @param[out] out_mask        The mask used for lookup the table - at line.
    /// @param[out] out_key         The key used for lookup the table - at line.
    /// @param[out] out_payload     Payload at line entry.
    ///
    /// @return true if entry was found successfuly, false otherwise.
    virtual bool get_ternary_entry(std::string table_name,
                                   size_t index,
                                   size_t line,
                                   nsim::bit_vector& out_key,
                                   nsim::bit_vector& out_mask,
                                   nsim::bit_vector& out_payload)
        = 0;

    /// @brief Gets entry from lpm table.
    ///
    /// @param[in]  table_name      Name of the NPL table.
    /// @param[in]  index           Instance index of the table.
    /// @param[in]  key             The key used for lookup the table.
    /// @param[in]  length          Length of the prefix to use for matching the entry.
    /// @param[out] out_payload     Payload at key entry with length.
    ///
    /// @return true if entry was found successfuly, false otherwise.
    virtual bool get_lpm_entry(std::string table_name,
                               size_t index,
                               const nsim::bit_vector& key,
                               size_t length,
                               nsim::bit_vector& out_payload)
        = 0;

    /// @brief Updates entry in exact table.
    ///
    /// @param[in]  table_name      Name of the NPL table.
    /// @param[in]  index           Instance index of the table.
    /// @param[in]  key             The key used for lookup the table.
    /// @param[in]  new_payload     Updated payload to return from the table if key was hit.
    ///
    /// @return true if entry was updated successfuly, false otherwise.
    virtual bool update_entry(std::string table_name,
                              size_t index,
                              const nsim::bit_vector& key,
                              const nsim::bit_vector& new_payload)
        = 0;

    /// @brief Updates entry in ternary table.
    ///
    /// @param[in]  table_name      Name of the NPL table.
    /// @param[in]  index           Instance index of the table.
    /// @param[in]  line            Line to use in the table.
    /// @param[in]  new_payload     Updated payload to return from the table if key was hit.
    ///
    /// @return true if entry was updated successfuly, false otherwise.
    virtual bool update_ternary_entry(std::string table_name, size_t index, size_t line, const nsim::bit_vector& new_payload) = 0;

    /// @brief Updates entry in lpm table.
    ///
    /// @param[in]  table_name      Name of the NPL table.
    /// @param[in]  index           Instance index of the table.
    /// @param[in]  key             The key used for lookup the table.
    /// @param[in]  length          Length of the prefix to use for matching the entry.
    /// @param[in]  new_payload     Updated payload to return from the table if key was hit.
    ///
    /// @return true if entry was updated successfuly, false otherwise.
    virtual bool update_lpm_entry(std::string table_name,
                                  size_t index,
                                  const nsim::bit_vector& key,
                                  size_t length,
                                  const nsim::bit_vector& new_payload)
        = 0;

    /// @brief place user defined key.
    ///
    /// @param[in]  macro_id        macro id.
    /// @param[in]  udk_components  Vector of udk components.
    /// @param[in]  key_size             The key used for lookup the table.
    ///
    /// @return PLACE_UDK_RES_OK if done successfuly, other values otherwise.
    virtual uint8_t place_udk(uint16_t macro_id, std::vector<udk_table_id_and_components>& table_components) = 0;

    /// @brief Set counter value.
    ///
    /// @param[in]  block_id        Counter block id.
    /// @param[in]  counter_index   Instance index of the unit.
    /// @param[in]  value           Value to set the specific counter to.
    ///
    /// @return true if counter was read successfuly, false otherwise.
    virtual bool set_counter(uint64_t block_id, uint64_t counter_index, const nsim::bit_vector& value) = 0;

    /// @brief Get counter value.
    ///
    /// @param[in]  block_id        Counter block id.
    /// @param[in]  counter_index   Instance index of the unit.
    /// @param[in]  clear_counter   Determine if need to set the counter to 0 after read.
    /// @param[out] out_value       Value of the specific counter.
    ///
    /// @return true if counter was read successfuly, false otherwise.
    virtual bool get_counter(uint64_t block_id, uint64_t counter_index, bool clear_counter, nsim::bit_vector& out_value) = 0;

    /// @brief returns a vector of table names which is mapping from table id to table name
    ///
    /// @param[in]  file            File to read the state from.
    ///
    /// @return vector of sorted table names
    virtual std::vector<std::string>& get_sorted_table_names() = 0;
    /// @brief mapping from table id to table name
    ///
    /// @param[in]  table_name     table name
    ///
    /// @return table_id>=0        valid table_id
    /// @return UINT32_MAX         table_id not found
    virtual uint32_t get_table_id_by_name(std::string table_name) = 0;
    /// @brief subscribe listener to table
    ///
    /// @param[in]  table_listener  listner
    /// @param[in]  table_name      table name
    /// @param[in]  registration_id
    /// @param[in]  type            notification type
    ///
    /// @return true if subscription was successfull, false otherwise.
    virtual bool subscribe_listener_to_table(nsim_table_listener* table_listener,
                                             std::string table_name,
                                             size_t registration_id,
                                             uint16_t type)
        = 0;
    /// @brief unsubscribe listener from table
    ///
    /// @param[in]  table_name      table name
    /// @param[in]  table_listener  listner
    /// @param[in]  type            notification type
    ///
    /// class which implements the listener is responsible for unsubscribing from the tables
    virtual void unsubscribe_table_listener_from_table(std::string table_name, nsim_table_listener* table_listener, uint16_t type)
        = 0;
    /// @brief unsubscribe listener from all tables
    ///
    /// @param[in]  table_listener  listner
    /// @param[in]  type            notification type
    ///
    /// class which implements the listener is responsible for unsubscribing from the tables
    virtual void unsubscribe_table_listener_from_all_tables(nsim_table_listener* table_listener, uint16_t type) = 0;
    /// @brief unsubscribe listener from all tables
    ///
    /// @param[in]  table_listener  listner
    ///
    /// class which implements the listener is responsible for unsubscribing from the tables
    virtual void unsubscribe_table_listener_from_all_tables(nsim_table_listener* table_listener) = 0;
    /// @brief subscribe listener to nsim timer
    ///
    /// @param[in]   timer_listener  listner
    /// @param[out]  out_nsim_timer_resolution_ms
    /// @param[out]  out_num_sim_sec_per_hw_sec
    ///
    /// @return true if subscription was successfull, false otherwise.
    virtual bool subscribe_timer_listener(nsim_timer_listener* timer_listener,
                                          int32_t& out_nsim_timer_resolution_ms,
                                          double& out_num_sim_sec_per_hw_sec)
        = 0;
    /// @brief unsubscribe listener from nsim timer
    ///
    /// @param[in]  timer_listener  listner
    ///
    virtual void unsubscribe_timer_listener(nsim_timer_listener* timer_listener) = 0;
};
} // namespace nsim

#endif
