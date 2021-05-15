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

#ifndef __LA_SECURITY_GROUP_TYPES_H__
#define __LA_SECURITY_GROUP_TYPES_H__

#include "api/types/la_common_types.h"
#include "api/types/la_ip_types.h"

/// @file
/// @brief Leaba Security Group (SG) type definitions.
///
/// @details Defines SG-related types and enumerations.

namespace silicon_one
{
} // namespace silicon_one

/// @addtogroup SYSTEM
/// @{

/// SGT Tag Identifier.
typedef la_uint16_t la_sgt_t;

/// DGT Tag Identifier.
typedef la_uint16_t la_dgt_t;

/// SGACL Identifier.
typedef la_uint32_t la_sgacl_id_t;

/// @}
#endif // __LA_SECURITY_GROUP_TYPES_H__
