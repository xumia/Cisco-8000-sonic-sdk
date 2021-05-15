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

#ifndef __TEST_RA_FLOW__
#define __TEST_RA_FLOW__

#include "ra_device_simulator.h"
#include <vector>

namespace silicon_one
{
class ll_device;
class ra_device_simulator;
class translator_creator;
};

/// @brief Create RA simulator implementing #silicon_one::device_simulator interface.
///
/// The simulator is logging device reads/writes to the #silicon_one::logger
///
/// @param[in]  port            Socket port number.
/// @param[in]  block_filter    List of blocks to filter reads/writes upon. If the list is empty, no filter is created.
/// @param[in]  sim_options     RA simulator options to initialize the simulator with.
///
/// @retval         Pointer to newly allocated #silicon_one::device_simulator.
silicon_one::ra_device_simulator* create_ra_simulator(const std::vector<size_t>& block_filter_vec,
                                                      la_device_id_t device_id,
                                                      silicon_one::simulator_options sim_options);

/// @brief Checks the address in the simulator memory/register vrt. expected value.
///
/// @param[in]  ldevice     Low Level device.
/// @param[in]  addr        Memory/register address including block offset.
/// @param[in]  val         String representing hex int expected memory/register value.
/// @param[in]  is_mem      true if memory - otherwise register.
///
/// @retval         true if content matches, false otherwise.
std::string ra_simulator_check_address(const silicon_one::ll_device* ldevice, size_t addr, const char* val, bool is_mem);

#endif //__TEST_RA_FLOW__
