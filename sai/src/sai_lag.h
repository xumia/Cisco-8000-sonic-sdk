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

#ifndef __SAI_LAG_H__
#define __SAI_LAG_H__

#include "api/types/la_common_types.h"
#include "api/types/la_system_types.h"

#include "saitypes.h"

#include "sai_device.h"

namespace silicon_one
{
namespace sai
{

/// @brief	Get MTU from the underlying mac_port
///
/// @param[in]  sys_port	Pointer of sys_port
/// @param[out] mtu_value	Return of MTU value
///
/// @return     sai_status_t
/// @retval		SAI_STATUS_ITEM_NOT_FOUND   Underlying port is not a mac_port, may not be an error.
/// @retval		SAI_STATUS_SUCCESS          Successfully return MTU value.
sai_status_t lsai_get_mac_port_mtu(const la_system_port* sys_port, la_uint_t& mtu_value);

/// @brief	Set MTU on the underlying mac_port
///
/// @param[in]  sys_port	Pointer of sys_port
/// @param[in]  mtu_value	MTU value
///
/// @return     sai_status_t
/// @retval		SAI_STATUS_ITEM_NOT_FOUND   Underlying port is not a mac_port, may not be an error.
/// @retval		SAI_STATUS_SUCCESS          Successfully return MTU value.
sai_status_t lsai_set_mac_port_mtu(const la_system_port* sys_port, la_uint_t mtu_value);

// Get MTU and Set MTU function for lag port and sai port. Definitions are located in both sai_lag.cpp and sai_port.cpp
sai_status_t lsai_get_mtu(port_entry pentry, la_uint_t& mtu_value);
sai_status_t lsai_get_mtu(lag_entry lentry, la_uint_t& mtu_value);
sai_status_t lsai_set_mtu(port_entry pentry, la_uint_t mtu_value);
sai_status_t lsai_set_mtu(lag_entry lentry, la_uint_t mtu_value);
}
}
#endif
