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

#ifndef __COMMON_STRINGS_H__
#define __COMMON_STRINGS_H__

#include "api/system/la_mac_port.h"
#include "api/types/la_common_types.h"
#include "api/types/la_notification_types.h"
#include "api/types/la_system_types.h"

#include <sstream>

/// @file
/// @brief Leaba common structs/enums to strings definitions.

namespace silicon_one
{

/// @brief Return bool as a string.
std::string to_string(bool value);

/// @brief Return SerDes direction as a string.
std::string to_string(la_serdes_direction_e direction);

/// @brief Return integer value as a hex string.
std::string to_hex_string(int value);

/// @brief Return port debug info type as a string.
std::string to_string(la_mac_port::port_debug_info_e info_type);

/// @brief Return formated string in the form of (slice/ifg/serdes number)
std::string to_string(la_slice_id_t slice_id, la_ifg_id_t ifg_id, la_uint_t serdes_idx);

/// @brief Return la_mem_protect_error_e as a string.
std::string to_string(la_mem_protect_error_e mem_protect_error);

/// @brief Return dram_corrupted_buffer as a string.
std::string to_string(dram_corrupted_buffer value);

/// @brief Return la_device_family_e as a string.
std::string to_string(la_device_family_e family);

/// @brief Return la_device_revision_e as a string.
std::string to_string(la_device_revision_e revision);

/// @brief return resource descriptor type as string.
std::string to_string(la_resource_descriptor::type_e resource_type);

} // namespace silicon_one

#endif /* __COMMON_STRINGS_H__  */
