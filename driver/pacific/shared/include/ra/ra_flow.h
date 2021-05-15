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

#ifndef __RA_FLOW_H__
#define __RA_FLOW_H__

#include "lld/lld_fwd.h"
#include "ra/ra_types_fwd.h"

#include "nplapi/npl_enums.h"
#include "nplapi/nplapi_fwd.h"
#include <vector>

/// @file RA package interfaces

namespace silicon_one
{

class translator_creator;
class resource_manager;

/// @brief Create RA implementation of #silicon_one::translator_creator interface.
///
/// @param[in]  resource_mgr            Pointer to opaque resource manager object.
/// @param[in]  lld                     Low-level device.
/// @param[in]  npl_context_slices      NPL context mode of slices.
///
/// @retval Pointer to newly allocated #silicon_one::translator_creator.
silicon_one::translator_creator_sptr create_ra_translator_creator(const resource_manager_sptr& resource_mgr,
                                                                  const ll_device_sptr& lld,
                                                                  const std::vector<npl_context_e>& npl_context_slices,
                                                                  const std::vector<udk_translation_info_sptr>& trans_info);

/// Temporary workaround to solve dynamic memory issues in simulation
void init_buggy_dynamic_memories(const ll_device_sptr& ldevice);
}

#endif // __RA_FLOW_H__
