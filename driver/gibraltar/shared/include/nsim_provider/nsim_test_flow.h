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

#ifndef __NSIM_TEST_FLOW_H__
#define __NSIM_TEST_FLOW_H__

#include "nsim_provider/nsim_provider.h"

#include <stddef.h>

/// @file test/nsim_provider package interfaces

namespace silicon_one
{
class device_simulator;
class device_simulator_server;
};

/// @brief Create NSIM simulator server and runs it in a separate thread.
///
/// Creates NSIM simulator server, allowing devices (clients) connecting to it, by opening socket connection.
/// Returns the port number, where the connection was opened.
///
/// @param[in]  provider        #nsim_provider object.
/// @param[in]  host            Host name to open connection on. If NULL, connection will be opened on the local host.
/// @param[in]  port            Port to open connection on. If 0, port will be selected automatically.
///
/// @retval         New device path for client connection.
silicon_one::nsim_provider* create_and_run_simulator_server(const char* host, size_t port, const char* device_path);

/// @brief Enabling/Disabling debug on nsim_provider module
///
/// @param[in]  val             Enable/Disable debug
void set_nsim_flow_debug(bool val);

#endif // __NSIM_TEST_FLOW_H__
