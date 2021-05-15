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

#ifndef __LEABA_CTM_STRING_H__
#define __LEABA_CTM_STRING_H__

#include "ctm/ctm_common.h"
#include "ctm/ctm_common_tcam.h"

#include <string>

/// @file
/// @brief CTM implementations types.

namespace silicon_one
{

/// @brief return table description as a string.
///
/// @param[in]  table   table to return as a string.
std::string to_string(ctm::table_desc table);

/// @brief return group description as a string.
///
/// @param[in]  group   group to return as a string.
std::string to_string(ctm::group_desc group);

/// @brief return TCAM description as a string.
///
/// @param[in]  tcam   TCAM to return as a string.
std::string to_string(const tcam_desc& tcam);

/// @brief return description for a vector of tcam containers.
///
/// @param[in] tcam_containers_vector a vector of tcam containers to return as string.
std::string to_string(const tcams_container_vec& tcam_pairs_vector);

} // namespace silicon_one

#endif
