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

#ifndef __LPM_TOP_HW_WRITER_H__
#define __LPM_TOP_HW_WRITER_H__

#include "common/la_status.h"
#include "hw_tables/lpm_types.h"
#include "lpm/lpm_internal_types.h"
#include "lpm_distributor.h"

namespace silicon_one
{

class ll_device;

/// @brief Database level HW writer, responsible for distributor and group to core mapping updates.
class lpm_top_hw_writer
{
public:
    virtual ~lpm_top_hw_writer()
    {
    }

    /// @brief Get device of this LPM top hardware writer.
    ///
    /// @return ll_device_sptr of this writer device.
    virtual const ll_device_sptr& get_ll_device() const = 0;

    /// @brief Perform update instructions in HW.
    ///
    /// @param[in]      instructions       Hardware instructions to perform.
    ///
    /// @return  la_status.
    virtual la_status update_distributor(const lpm_distributor::hardware_instruction_vec& instructions) = 0;

    /// @brief Read indices last HBM queried buckets.
    ///
    /// @param[out]      out_hw_indices       Vector of HW indices of last queried HBM buckets.
    ///
    /// @return #la_status.
    virtual la_status read_indices_of_last_accessed_hbm_buckets(vector_alloc<size_t>& out_hw_indices) = 0;
};

} // namespace silicon_one

#endif // __LPM_TOP_HW_WRITER_H__
