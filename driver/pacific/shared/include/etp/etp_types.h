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

#ifndef _ETP_TYPES_H__
#define _ETP_TYPES_H__

namespace silicon_one
{

/// @brief Naming for the individual SerDes pools in the IFG. There are datasheet defined values.
enum class etp_serdes_pool_e { A = 0, B, C, FIRST = A, LAST = C };

/// @brief Vendor SerDes has 3 components that we interface with. These are datasheet defined values.
enum class etp_serdes_addressing_component_e {
    SERDES = 0,
    PLL,
    BGR,
};

} // namespace silicon_one

#endif
