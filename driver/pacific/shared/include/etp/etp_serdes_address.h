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

#ifndef _ETP_SERDES_ADDRESS_H__
#define _ETP_SERDES_ADDRESS_H__

#include "etp_types.h"
namespace silicon_one
{

/// @brief eTopus SerDes address structure.
union etp_serdes_address {
    struct fields_s {
        uint32_t serdes_index : 4;         /// SerDes index in pool group - range is [0:3].
        uint32_t serdes_quad : 4;          /// Quad in pool group - range is [0:3].
        uint32_t serdes_pool : 2;          /// SerDes pool group in the IFG - range is [0:2]. View etp_serdes_pool_e for more info.
        uint32_t addressing_component : 2; /// Interface with device component:  SerDes, PLL or BGR. View
                                           /// etp_serdes_addressing_component_e for more info.
        uint32_t serdes_broadcast : 1;     /// Perform a broadcast write to all serdes quads in the serdes pool.
        uint32_t device_id : 4;            /// device_id used to get APB handler
        uint32_t reserved : 15;            /// Reserved space.
    } fields;
    uint32_t u32;
};

#ifndef SWIG
static_assert(sizeof(etp_serdes_address) == sizeof(uint32_t), "size must be 4 bytes");
#endif

} // namespace silicon_one

#endif
