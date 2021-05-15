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

#ifndef __WARM_BOOT_VERSION_H__
#define __WARM_BOOT_VERSION_H__

#include "api/types/la_common_types.h"
#include "common/la_status.h"

/// @file
/// @brief Leaba warm boot versions.
///
/// @details Defines WB versions for managing WB upgrade and rollback.
///          Upgrade from SDK V1 to V2 (V2 is current version) is supported only if
///          all of the following conditions are met:
///             1- V1 and V2 have the same WB_VERSION.
///             2- V2's WB_REVISION is greater or equal to V1's WB_REVISION.
///             3- V1's WB_REVISION is greater or equal to V2's WB_MIN_REVISION.
///
///          Rollback from V2 (V2 is current version) to V1 is supported only if
///          all of the following conditions are met:
///             1- V1 and V2 have the same WB_VERSION.
///             2- V1's WB_REVISION is less or equal to V2's WB_REVISION.
///             3- V1's WB_REVISION is greater or equal to V2's WB_MIN_REVISION.
///
/// @addtogroup SYSTEM
/// @{

namespace silicon_one
{

/// @brief Defines the warm boot version.
///
/// @details WB_VERSION defines a family of SDK versions that are capable of
///          performing upgrade or rollback warm boot from one to the other.
static constexpr const char* WB_VERSION = "NA";

/// @brief Defines the current SDK warm-boot revision.
///
/// @see la_warm_boot_rollback_save_and_destroy()
static constexpr la_uint32_t WB_REVISION = 1;

/// @brief Defines the min SDK warm-boot revision that is upgradable to current SDK.
static constexpr la_uint32_t WB_MIN_REVISION = 1;

/// @brief Retrieves the warm boot revision of a given SDK version.
///
/// @param[in]  sdk_version      SDK version to get its wb revision.
/// @param[out] out_wb_revision  WB revision of sdk_version.
///
/// @retval LA_STATUS_SUCCESS    Operation completed successfully, out_wb_revision contains the wb revision.
/// @retval LA_STATUS_EINVAL     WB to/from sdk_version is not supported by current SDK version.
/// @see la_warm_boot_rollback_save_and_destroy()
la_status sdk_version_to_wb_revision(const std::string sdk_version, la_uint32_t& out_wb_revision);

} // namespace silicon_one

/// @}
#endif // __WARM_BOOT_VERSION_H__
