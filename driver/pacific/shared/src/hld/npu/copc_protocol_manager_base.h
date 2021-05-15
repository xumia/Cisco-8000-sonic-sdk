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

#ifndef __COPC_PROTOCOL_MANAGER_BASE_H__
#define __COPC_PROTOCOL_MANAGER_BASE_H__

#include <stdint.h>
#include <vector>

#include "api/npu/la_copc.h"
#include "hld_types_fwd.h"
#include "nplapi/nplapi_tables.h"

// This table is used for only L3

namespace silicon_one
{

class copc_protocol_manager_base
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit copc_protocol_manager_base(const la_device_impl_wptr& device);
    ~copc_protocol_manager_base();

    /// @brief Initialize the copc_protocol_manager, and program static entries in controlled tables.
    ///
    /// @retval     LA_STATUS_SUCCESS    Initialization completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN   An unknown error occurred.
    la_status initialize();

    /// @brief Add all dynamic entries received into copc protocol table
    ///
    /// @param[in]  copc_protocol_vec       List of protocol entries
    ///
    /// @retval     LA_STATUS_SUCCESS       Success
    /// @retval     LA_STATUS_EINVAL        Invalid argument.
    /// @retval     LA_STATUS_ENOTFOUND     No free entries in the table.
    /// @retval     LA_STATUS_EEXIST        Entry already exists in the table.
    /// @retval     LA_STATUS_EOUTOFRANGE   Given location is out of bound.
    /// @retval     LA_STATUS_EUNKNOWN      Internal error.
    la_status add(const la_control_plane_classifier::protocol_table_data& copc_protocol_data);

    /// @brief remove all dynamic entries received from copc protocol table
    ///
    /// @param[in]  copc_protocol_vec       List of protocol entries
    ///
    /// @retval     LA_STATUS_SUCCESS       Success
    /// @retval     LA_STATUS_EOUTOFRANGE   Given location is out of bound
    /// @retval     LA_STATUS_ENOTFOUND     Entry not in the table
    /// @retval     LA_STATUS_EUNKNOWN      Internal error
    la_status remove(const la_control_plane_classifier::protocol_table_data& copc_protocol_data);

    /// @brief clear all dynamic entries from copc protocol table
    ///
    /// @retval    LA_STATUS_SUCCESS        Success
    /// @retval    LA_STATUS_EOUTOFRANGE    Given location is out of bound
    /// @retval    LA_STATUS_ENOTFOUND      Entry not in the table
    /// @retval    LA_STATUS_EUNKNOWN       Internal error
    la_status clear(void);

    /// @brief Get all copc protocol table table entries
    ///
    /// @param[out]  out_copc_protocol_vec    Buffer to fetch all entries
    ///
    /// @retval      LA_STATUS_SUCCESS        Operation completed successfully
    /// @retval      LA_STATUS_EINVAL         Internal error.
    la_status get(la_control_plane_classifier::protocol_table_data_vec& out_copc_protocol_vec);

    struct copc_protocol_entry {
        npl_protocol_type_e l3_protocol;
        npl_protocol_type_e l4_protocol;
        uint64_t dst_port;
        uint64_t mac_da_use_copc;
    };

    using copc_protocol_entry_vec = std::vector<copc_protocol_entry>;

protected:
    copc_protocol_manager_base() = default; // For serialization only.

private:
    /// The creating device
    la_device_impl_wptr m_device;

    la_status update_entry(const copc_protocol_entry& sdk_entry,
                           npl_l2_lpts_protocol_table_t::key_type& key,
                           npl_l2_lpts_protocol_table_t::key_type& mask,
                           npl_l2_lpts_protocol_table_t::value_type& value);

    la_status insert_entry(npl_l2_lpts_protocol_table_t::key_type& key,
                           npl_l2_lpts_protocol_table_t::key_type& mask,
                           npl_l2_lpts_protocol_table_t::value_type& value);

    la_status clear_entry(npl_l2_lpts_protocol_table_t::key_type& key, npl_l2_lpts_protocol_table_t::key_type& mask);
    la_status populate_copc_entry(const la_control_plane_classifier::protocol_table_data& copc_protocol_data,
                                  copc_protocol_entry& copc_entry);
    la_status convert_copc_entry(const copc_protocol_entry& copc_entry,
                                 la_control_plane_classifier::protocol_table_data& copc_protocol_data);
};

} // namespace silicon_one

#endif // __COPC_PROTOCOL_MANAGER_BASE_H__
