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

#ifndef __COUNTER_UTILS_H__
#define __COUNTER_UTILS_H__

#include "api/types/la_object.h"
#include "nplapi/npl_types.h"
#include "npu/la_counter_set_impl.h"

namespace silicon_one
{
class la_meter_set_impl;

/// @brief Populate the NPL counter-ptr structure in a per slice table.
///
/// @param[in]  counter_or_meter         Counter/Meter to populate.
/// @param[in]  slice                    The slice of the table to be configured.
/// @param[in]  direction                The table to be configured is in the ingress or egress.
///
/// @retval     Populated counter-ptr structure.
npl_counter_ptr_t populate_counter_ptr_slice(const la_counter_or_meter_set_wcptr& counter_or_meter,
                                             la_slice_id_t slice,
                                             counter_direction_e direction);

/// @brief Populate the NPL counter-ptr structure in a per slice table, adding the given offset to the counter set base.
///
/// @param[in]  counter_or_meter         Counter/Meter to populate.
/// @param[in]  slice                    The slice of the table to be configured.
/// @param[in]  direction                The table to be configured is in the ingress or egress.
/// @param[in]  offset                   Counter offset.
///
/// @retval     Populated counter-ptr structure.
npl_counter_ptr_t populate_counter_ptr_slice_with_offset(const la_counter_or_meter_set_wcptr& counter_or_meter,
                                                         la_slice_id_t slice,
                                                         counter_direction_e direction,
                                                         size_t offset);

/// @brief Populate the NPL counter-ptr structure in a per slice-pair table.
///
/// @param[in]  counter_or_meter    Counter/Meter to populate.
/// @param[in]  pair_idx            The slice-pair of the table to be configured.
/// @param[in]  direction           The table to be configured is in the ingress or egress.
///
/// @retval     Populated counter-ptr structure.
npl_counter_ptr_t populate_counter_ptr_slice_pair(const la_counter_or_meter_set_wcptr& counter_or_meter,
                                                  la_slice_pair_id_t pair_idx,
                                                  counter_direction_e direction);

/// @brief Populate the NPL q_counter-ptr structure in a per slice table.
///
/// @param[in]  counter_or_meter    Counter/Meter to populate.
/// @param[in]  slice                    The slice of the table to be configured.
/// @param[in]  direction           The table to be configured is in the ingress or egress.
///
/// @retval     Populated counter-ptr structure.
npl_counter_ptr_t populate_q_counter_ptr(const la_counter_or_meter_set_wcptr& counter_or_meter,
                                         la_slice_id_t slice,
                                         counter_direction_e direction);

// Hardware workaround value to skip the p counter but still count the q counter. Consumes a counting action.
constexpr npl_counter_ptr_t NPU_COUNTER_NOP = {.update_or_read = 0, .cb_id = 0x7e, .cb_set_base = 0xfff};
constexpr npl_counter_ptr_t NPU_COUNTER_INVALID = {.update_or_read = 0, .cb_id = 0x7f, .cb_set_base = 0xfff};

} // namespace silicon_one

#endif // __COUNTER_UTILS_H__
