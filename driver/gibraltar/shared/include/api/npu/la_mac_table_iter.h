// BEGIN_LEGAL
//
// Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_MAC_TABLE_ITER_H__
#define __LA_MAC_TABLE_ITER_H__

#include "api/types/la_common_types.h"
#include "api/types/la_ethernet_types.h"

/// @file
/// @brief Leaba MAC table iteration API-s.
///
/// Defines API-s for iterating over a MAC table.

/// @addtogroup L2SWITCH_MAC_ITER
/// @{

/// @brief Create a MAC table iterator with given filters.
///
/// Entries can be filtered by Switch, Port and Destination.
///
/// When filter_sw is valid, only entries matching that switch are returned.
/// When filter_sw is set to NULL, no switch-based filtering is performed.
///
/// When filter_destination is valid, only entries matching that destination are returned.
/// When filter_destination is set to NULL, no destination-based filtering is performed.
///
/// @param[in]  device              Device to be manipulated.
/// @param[in]  filter_sw           Switch to filter by.
/// @param[in]  filter_destination  Destination to filter by.
/// @param[out] out_iter            Pointer to #la_mac_table_iter_t to populate.
///
/// @return status.
/// @retval     LA_STATUS_SUCCESS   Iterator created successfully.
/// @retval     LA_STATUS_EINVAL    Switch, port or destination are corrupt, or out_iter is NULL.
/// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
///
/// @see la_device_destroy_mac_table_iter
la_status la_device_create_mac_table_iter(la_device_t device,
                                          const silicon_one::la_switch* filter_sw,
                                          const silicon_one::la_l2_destination* filter_destination,
                                          la_mac_table_iter_t* out_iter);

/// @brief Destroy a MAC table iterator.
///
/// @param[in]  device              Device to be manipulated.
/// @param[in]  iter                Iterator to destroy.
///
/// @retval     LA_STATUS_SUCCESS   Iterator destroyed successfully.
/// @retval     LA_STATUS_EINVAL    Iterator is corrupt/invalid.
/// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
///
/// @see la_device_create_mac_table_iter
la_status la_device_destroy_mac_table_iter(la_device_t device, la_mac_table_iter_t iter);

/// @brief Get MAC address of current entry from iterator.
///
/// @param[in]  iter                Iterator to be queried.
/// @param[out] out_mac             Pointer to #la_mac_addr_t to populate.
///
/// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
/// @retval     LA_STATUS_EINVAL    Iterator is corrupt/invalid/out of range, entry is invalid, or out_mac is NULL.
/// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
///
/// @note   Iterator entries can be invalid. la_mac_table_iter_is_valid_entry should be called
///         in advance to verify entry is valid.
la_status la_mac_table_iter_get_mac(la_mac_table_iter_t iter, la_mac_addr_t* out_mac);

/// @brief Get Switch of current entry from iterator.
///
/// @param[in]  iter                Iterator to be queried.
/// @param[out] out_sw              Pointer to #silicon_one::la_switch to populate.
///
/// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
/// @retval     LA_STATUS_EINVAL    Iterator is corrupt/invalid/out of range, entry is invalid, or out_sw is NULL.
/// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
///
/// @note   Iterator entries can be invalid. la_mac_table_iter_is_valid_entry should be called
///         in advance to verify entry is valid.
la_status la_mac_table_iter_get_switch(la_mac_table_iter_t iter, const silicon_one::la_switch*& out_sw);

/// @brief Get L2 destination of current entry from iterator.
///
/// @param[in]  iter                Iterator to be queried.
/// @param[out] out_destination     Pointer to #silicon_one::la_l2_destination* to populate.
///
/// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
/// @retval     LA_STATUS_EINVAL    Iterator is corrupt/invalid/out of range, entry is invalid, or out_destination is NULL.
/// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
///
/// @note   Iterator entries can be invalid. la_mac_table_iter_is_valid_entry should be called
///         in advance to verify entry is valid.
///
/// @see la_mac_table_iter_is_valid_entry
la_status la_mac_table_iter_get_destination(la_mac_table_iter_t iter, silicon_one::la_l2_destination*& out_destination);

/// @brief Advance MAC table iterator to next entry.
///
/// @param[in]  iter                Iterator to manipulate.
///
/// @retval     true                Iterator advanced to next entry.
/// @retval     false               Iterator is corrupt/invalid, or already done.
///
/// @see la_mac_table_iter_is_done
bool la_mac_table_iter_next(la_mac_table_iter_t iter);

/// @brief Query whether current iterator entry is valid.
///
/// An invalid entry does not mean iteration is finished.
/// #la_mac_table_iter_next should be called to advance the iterator to a next entry, which might be valid.
///
/// @param[in]  iter                Iterator to query.
///
/// @retval     true                Iterator entry is valid.
/// @retval     false               Iterator is corrupt/invalid, or current entry is invalid.
bool la_mac_table_iter_is_valid_entry(la_mac_table_iter_t iter);

/// @brief Query whether iterator advanced past last element.
///
/// @param[in]  iter                Iterator to query.
///
/// @retval     true                Iterator points past last element.
/// @retval     false               Iterator is in range and valid.
bool la_mac_table_iter_is_done(la_mac_table_iter_t iter);

/// @}
#endif
