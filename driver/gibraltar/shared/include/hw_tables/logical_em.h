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

#ifndef __LOGICAL_EM_H__
#define __LOGICAL_EM_H__

#include "common/resource_monitor.h"
#include "hw_tables/physical_locations.h"

#include <memory>

namespace silicon_one
{

class ll_device;
class logical_em;

/// @brief Logical Exact Match interface.
class logical_em
{
public:
    virtual ~logical_em()
    {
    }

    /// @brief Insert to Exact Match.
    ///
    /// Fuctions fails if the key already exists.
    /// User's responsibility to make sure the inserted entry does not exist in any of EM banks.
    ///
    /// @param[in]  key                     Exact Match key.
    /// @param[in]  payload                 Exact Match payload.
    ///
    /// @retval     status code.
    virtual la_status insert(const bit_vector& key, const bit_vector& payload) = 0;

    /// @brief Updates the payload of existing entry.
    ///
    /// Finds an entry that matches the provided key and updates its payload.
    /// Function returns failure if the key was not found.
    ///
    /// @param[in]  key                     Exact Match key.
    /// @param[in]  payload                 Exact Match payload.
    ///
    /// @retval     status code.
    virtual la_status update(const bit_vector& key, const bit_vector& payload) = 0;

    /// @brief Erase from Exact Match.
    ///
    /// @param[in]  key                     Exact Match key.
    ///
    /// @retval     status code.
    virtual la_status erase(const bit_vector& key) = 0;

    /// @brief Erase from Exact Match.
    ///
    /// EMs with flexible entry options could have same key but
    /// different payload size.
    ///
    /// @param[in] key                       Exact Match key.
    ///
    /// @param[in] payload_width             Width of payload
    virtual la_status erase(const bit_vector& key, size_t payload_width) = 0;

    /// @brief Returns if EM supports flexible entry
    ///
    /// @retval true if flexible entry supported
    virtual bool is_flexible_entry_supported() const = 0;

    /// @brief Retrieve maximum table size.
    ///
    /// @retval Maximum number of entries supported by table.
    virtual size_t max_size() const = 0;

    /// @brief Retrieve percentage of the physical usage out of the total physical resource based on the number of
    /// logical entries.
    ///
    /// @param[in]   num_of_table_logical_entries    Number of the logical entries that inserted to the CEM through this table.
    /// @param[out]  out_physical_usage                    Physical entries occupied by the table.
    ///
    /// @retval     la_status
    virtual la_status get_physical_usage(size_t num_of_table_logical_entries, size_t& out_physical_usage) const = 0;

    /// @brief Retrieve estimation of the available entries left for table.
    ///
    /// @param[out]  out_available_entries                  Available entries left for table.
    ///
    /// @retval     la_status
    virtual la_status get_available_entries(size_t& out_available_entries) const = 0;

    /// @brief Set resource monitor.
    ///
    /// @param[in]  resource_monitor           Resource monitor.
    ///
    /// @retval     LA_STATUS_SUCCESS           Success.
    /// @retval     LA_STATUS_EUNKONWN          Internal error.
    virtual la_status set_resource_monitor(const resource_monitor_sptr& monitor) = 0;

    /// @brief Get resource monitor.
    ///
    /// @param[out] out_resource_monitor        Resource monitor to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Success.
    /// @retval     LA_STATUS_EUNKONWN          Internal error.
    virtual la_status get_resource_monitor(resource_monitor_sptr& out_monitor) const = 0;

    /// @brief Retrieve the number of entries in the table.
    ///
    /// @retval Number of entries.
    virtual size_t size() const = 0;
};

} // namespace silicon_one

#endif // __LOGICAL_EM_H__
