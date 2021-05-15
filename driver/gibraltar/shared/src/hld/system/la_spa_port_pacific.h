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

#ifndef __LA_SPA_PORT_PACIFIC_H__
#define __LA_SPA_PORT_PACIFIC_H__

#include "la_spa_port_pacgb.h"

namespace silicon_one
{

class la_device_impl;
class la_system_port_base;

class la_spa_port_pacific : public la_spa_port_pacgb
{
    ////////// Cereal ////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_spa_port_pacific() = default;
    //////////////////////////////
public:
    explicit la_spa_port_pacific(const la_device_impl_wptr& device);
    ~la_spa_port_pacific() override;

    la_status destroy() override;
    la_status set_lb_mode(la_lb_mode_e lb_mode) override;
    la_status get_lb_mode(la_lb_mode_e& out_lb_mode) const override;
    la_status get_lb_resolution(const la_lb_pak_fields_vec& lb_vector, size_t& member, const la_object*& out_object) const override;

private:
    // Address of size table entry
    npl_port_dspa_group_size_table_entry_wptr_t m_size_table_entry;

    la_status add_system_port_to_dspa_table(std::shared_ptr<system_port_base_data>& sp_data_to_update,
                                            size_t num_of_entries_to_add,
                                            transaction& txn) override;
    la_status clear_table_tail(size_t start_index, transaction& txn) override;
    la_status init_port_dspa_group_size_table_entry() override;
    la_status erase_port_dspa_group_size_table_entry() override;

    /// @brief Sets the given value in the port-DSPA-group-size resolution table.
    ///
    /// Sets the given group-size value in the port-DSPA-group-size resolution table.
    ///
    /// @param[in]  lbg_group_size      Group size to write.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    la_status set_port_dspa_group_size_table_entry(size_t lbg_group_size) override;

    /// @brief Sets the given system port as a member of this SPA in the port-DSPA resolution table.
    ///
    /// Sets the given system port's GID as lbg_member_id-th member in the port-DSPA resolution table.
    ///
    /// @param[in]  system_port         System port to set as member.
    /// @param[in]  lbg_member_id       Member ID of the system port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    la_status set_port_dspa_table_entry(const la_system_port_wcptr& system_port, size_t lbg_member_id) override;

    /// @brief Erases a system port residing as the given member ID from being a member of this SPA in the port-DSPA resolution
    /// table.
    ///
    /// Erases the entry of the lbg_member_id-th member of this SPA in the port-DSPA resolution table.
    ///
    /// @param[in]  lbg_member_id       Member ID to erase.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    la_status erase_port_dspa_table_entry(size_t lbg_member_id);
};
}

/// @}

#endif
