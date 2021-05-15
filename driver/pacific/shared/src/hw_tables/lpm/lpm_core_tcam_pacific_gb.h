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

#ifndef __LEABA_LPM_CORE_TCAM_PACIFIC_GB_H__
#define __LEABA_LPM_CORE_TCAM_PACIFIC_GB_H__

#include "lpm_core_tcam.h"

namespace silicon_one
{

class lpm_core_tcam_pacific_gb : public lpm_core_tcam
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Construct a LPM Core TCAM object.
    ///
    /// @param[in]    name                 Name of core TCAM.
    /// @param[in]    num_banksets         Number of banksets in TCAM.
    /// @param[in]    num_cells_per_bank   Number of cells in each bank.
    /// @param[in]    max_num_quad_blocks  Max number of QUAD blocks the can be inserted to TCAM.
    /// @param[in]    core_tcam_utils      Pointer to TCAM utils object.
    lpm_core_tcam_pacific_gb(std::string name,
                             size_t num_banksets,
                             size_t num_cells_per_bank,
                             size_t max_num_quad_blocks,
                             const lpm_core_tcam_utils_scptr& core_tcam_utils);

protected:
    /// @brief Default c'tor - shouldn't be used, allowed only for serialization purposes.
    lpm_core_tcam_pacific_gb() = default;
};

} // namespace silicon_one

#endif // __LEABA_LPM_CORE_TCAM_PACIFIC_GB_H__
