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

#ifndef __LEABA_LPM_DISTRIBUTOR_PACIFIC_GB_H__
#define __LEABA_LPM_DISTRIBUTOR_PACIFIC_GB_H__

#include "lpm_distributor.h"

namespace silicon_one
{

class lpm_distributor_pacific_gb : public lpm_distributor
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Construct a LPM distributor object.
    ///
    /// @param[in]     name                 Name of distibutor.
    /// @param[in]     num_hw_lines         Number of HW lines in distributor TCAM.
    /// @param[in]     max_key_width        Max supported key width.
    lpm_distributor_pacific_gb(std::string name, size_t num_hw_lines, size_t max_key_width);

    // lpm_distributor API-s
    la_status update(const lpm_implementation_desc_vec& updates, hardware_instruction_vec& out_instructions) override;
    la_status get_entry(distributor_cell_location cell, lpm_key_payload& out_key_payload) const override;
    void commit() override;
    void withdraw() override;
    json_t* save_state() const override;
    void load_state(json_t* json_distributor, hardware_instruction_vec& out_instructions) override;

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lpm_distributor_pacific_gb() = default;

    /// @brief Struct describing a withdraw stack entry.
    struct withdraw_action {
        /// @brief type of withdraw action.
        enum class withdraw_action_type_e {
            WITHDRAW_UPDATE_NUM_IPV4_ROWS, ///< Withdraw an "update number of IPv4 rows" operation.
        };

        struct withdraw_update_num_ipv4_rows {
            size_t num_ipv4_rows;
        };

        withdraw_action_type_e action_type;
        boost::variant<boost::blank, withdraw_update_num_ipv4_rows> action_data;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action)
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::withdraw_update_num_ipv4_rows)

    // lpm_distributor virtual functions
    la_status make_space_for_logical_tcam(bool is_ipv6, lpm_logical_tcam::logical_instruction_vec& out_instructions) override;
    distributor_cell_location translate_logical_row_to_cell_location(size_t logical_row, bool is_ipv6) const override;

    /// @name Atoms: only operations which are allowed to directly modify the Distributors's data structures.
    /// @{

    /// @brief Update number of IPv4 rows.
    ///
    /// @param[in]     new_value      New value to write.
    void atom_update_num_ipv4_rows(size_t new_value);

    /// @}

    /// @brief Is row currently allocated to IPv6.
    ///
    /// @param[in]       row                  Row number.
    ///
    /// @return Whether row is allocated to IPv6 (vs. IPv4).
    bool is_row_ipv6(size_t row) const;

    /// @brief Withdraw a single action.
    ///
    /// @param[in] waction        Action to withdraw.
    void withdraw_one_action(const withdraw_action& waction);

    // Core data structures
    size_t m_num_ipv4_rows; ///< Number of rows currently allocated to IPv4 entries.

    // Withdraw
    vector_alloc<withdraw_action> m_withdraw_stack; ///< Withdraw stack.
};

} // namespace silicon_one

#endif
