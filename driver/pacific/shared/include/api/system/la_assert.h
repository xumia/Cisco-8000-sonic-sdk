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

#ifndef __LA_ASSERT_H__
#define __LA_ASSERT_H__

#include "common/dassert.h"

namespace silicon_one
{

/// @brief Set dynamic assert behavior for severity level.
///
/// @param[in]  level                Level to set behavior for.
/// @param[in]  settings             Level settings.
void la_assert_set_settings(const dassert::level_e level, const dassert::settings& settings);

/// @brief Get dynamic assert behavior for severity level.
///
/// @param[in]  level             Level to get behavior for.
/// @return     Structure holding settings for this level.
dassert::settings la_assert_get_settings(const dassert::level_e level);
}

#endif // __LA_ASSERT_H__
