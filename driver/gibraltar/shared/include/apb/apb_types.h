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

#ifndef __LEABA_APB_TYPES_H__
#define __LEABA_APB_TYPES_H__

#include "api/types/la_common_types.h"
#include "common/bit_vector.h"
#include "common/la_status.h"

/// @file
/// @brief Leaba APB types.
///
/// Defines API for accessing APB interface.

namespace silicon_one
{

enum class apb_interface_type_e : uint8_t {
    PCIE, ///< APB interface to PCIe SerDes
    FIRST = PCIE,
    SERDES, ///< APB interface to MAC port SerDes
    HBM,    ///< APB interface to HBM SerDes
    LAST = HBM
};

} // namespace silicon_one

#endif
