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

#ifndef __LA_LPTS_H__
#define __LA_LPTS_H__

#include "api/types/la_lpts_types.h"
#include "api/types/la_object.h"

/// @file
/// @brief Leaba LPTS API-s.
///
/// Defines API-s for configuring LPTS (Local Packet Transport System).

/// @addtogroup LPTS
/// @{

namespace silicon_one
{

/// @brief Local Packet Transport System API-s.
///
/// @details LPTS is an ordered list of Entries.\n
///          Each entry defines a match rule, a destination to send the packet to if that rule is matched
///          and a metering action associated with the matched flow.

class la_lpts : public la_object
{
public:
    /// @brief Get LPTS type.
    ///
    /// @param[out] out_type            Type of this LPTS instance.
    ///
    /// @retval     LA_STATUS_SUCCESS   Type retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_lpts_type(lpts_type_e& out_type) const = 0;

    /// @brief Get a count of the number of entries in the LPTS instance.
    ///
    /// @param[out] out_count           Entry count.
    ///
    /// @retval     LA_STATUS_SUCCESS   Key retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_count(size_t& out_count) const = 0;

    /// @brief Create and add an LPTS entry to the end of the set of LPTS entries.
    ///
    /// @param[in]  key                 LPTS key value to set.
    /// @param[in]  result              LPTS result to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   LPTS entry modified successfully.
    /// @retval     LA_STATUS_EINVAL    Either key or result is invalid.
    /// @retval     LA_STATUS_ERESOURCE No resources for appending an LPTS entry.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status append(const la_lpts_key& key, const la_lpts_result& result) = 0;

    /// @brief Add an LPTS entry at a specified position and also move following
    ////       entries down to create a hole for the new entry.
    ///
    /// @param[in]  position    Index in the LPTS entry. If it's greater than LPTS size, then it will be appended.
    /// @param[in]  key         LPTS key value to set.
    /// @param[in]  result      LPTS result to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   LPTS entry added successfully.
    /// @retval     LA_STATUS_EINVAL    Either key or result is invalid.
    /// @retval     LA_STATUS_ERESOURCE No resources for pushing an LPTS entry.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status push(size_t position, const la_lpts_key& key, const la_lpts_result& result) = 0;

    /// @brief Update an LPTS entry at a specified position.
    ///
    /// @param[in]  position    Index in the LPTS entry. If it's greater than LPTS size, then it will be appended.
    /// @param[in]  key         LPTS key value to set.
    /// @param[in]  result      LPTS result to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   LPTS entry modified successfully.
    /// @retval     LA_STATUS_EINVAL    Either key or result is invalid.
    /// @retval     LA_STATUS_ENOTFOUND No LPTS entry at a given position.
    /// @retval     LA_STATUS_ERESOURCE No resources for inserting an LPTS entry.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set(size_t position, const la_lpts_key& key, const la_lpts_result& result) = 0;

    /// @brief Remove an LPTS entry at a specific location and also move all the following entries
    ///        up to fill the hole.
    ///
    /// @param[in]  position            The position of the LPTS entry.
    ///
    /// @retval     LA_STATUS_SUCCESS   LPTS entry successfully removed.
    /// @retval     LA_STATUS_EINVAL    Position is invalid.
    /// @retval     LA_STATUS_ENOTFOUND No LPTS entry at a given position.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status pop(size_t position) = 0;

    /// @brief Retrieve an LPTS entry from a specific position.
    ///
    /// @param[in]  position            The position of the LPTS entry.
    /// @param[out] out_lpts_entry_desc  LPTS entry descriptor to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   LPTS entry found successfully.
    /// @retval     LA_STATUS_EINVAL    Position is invalid.
    /// @retval     LA_STATUS_ENOTFOUND No LPTS entry at a given position.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get(size_t position, lpts_entry_desc& out_lpts_entry_desc) const = 0;

    /// @brief Delete all entries from the LPTS instance.
    ///
    /// @retval     LA_STATUS_SUCCESS   All entries successfully removed.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear() = 0;

    ///@brief Calclute the maximum number of lines that can be inserted successfully,
    /// in the current system state.
    ///
    ///@param[out] out_available_space number of lines that can be successfully inserted.
    ///@retval     LA_STATUS_SUCCESS The value returned is valid.
    virtual la_status get_max_available_space(size_t& out_available_space) const = 0;

protected:
    ~la_lpts() override = default;
};

} // namespace silicon_one

/// @}
#endif // __LA_LPTS_H__
