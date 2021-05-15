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

#ifndef __NSIM_FLOW_H__
#define __NSIM_FLOW_H__

#include "lld/lld_fwd.h"
#include "nplapi/npl_enums.h"
#include "nplapi/nplapi_fwd.h"
#include <stddef.h>

#include <vector>

/// @file nsim_provider package interfaces

namespace silicon_one
{
class device_simulator;
};

/// @brief Create NSIM implementation of #silicon_one::translator_creator interface.
///
/// @param[in]  lld                     Low-level device.
/// @param[in]  npl_context_slices      NPL context mode of slices.
///
/// @retval Pointer to newly allocated #silicon_one::translator_creator.
silicon_one::translator_creator_sptr create_nsim_translator_creator(silicon_one::ll_device_sptr lld,
                                                                    const std::vector<npl_context_e>& npl_context_slices);

/// @brief Create socket based NSIM simulator implementing #silicon_one::device_simulator interface.
///
/// Assumes that NSIM simulator server already created socket on the provided socket address.
///
/// @param[in]  socket_addr     Socket address.
/// @param[in]  port            Port number for the connection.
/// @param[in]  sdk_version     SDK version.
///
/// @retval         Pointer to newly allocated #silicon_one::device_simulator.
silicon_one::device_simulator* create_nsim_simulator(const char* socket_addr, size_t port, const char* sdk_version);

#endif // __NSIM_FLOW_H__
