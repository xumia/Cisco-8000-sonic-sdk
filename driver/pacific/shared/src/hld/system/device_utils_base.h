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

#ifndef __DEVICE_UTILS_H__
#define __DEVICE_UTILS_H__

/// @file
/// @brief Device utilities. Used for getting a specific device type characteristics. Usually should be used for remote device.

#include "api/types/la_common_types.h"

namespace silicon_one
{

namespace device_utils
{

/// @brief Specific device type constants.
enum {
    PACIFIC_NUM_PIF_PER_IFG = 18, ///< Number of PIF's per IFG in Pacific device (constant for all IFGs)
    GB_MAX_NUM_PIF_PER_IFG = 24,  ///< Maximum PIF's per IFG in Gibraltar device (can be 18 or 24)
};

/// @brief Returns number of PIF per IFG according to a given device revision.
///
/// @param[in]  #la_device_revision_e    Device revision.
///
/// @return     size_t                   Number of pif per IFG of the given device revision.
size_t get_num_of_pif_per_ifg(la_device_revision_e device_revision);

} // namespace device_utils

} // namespace silicon_one

#endif // __DEVICE_UTILS_H__
