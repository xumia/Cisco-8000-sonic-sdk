// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LEABA_LPM_CORE_TCAM_UTILS_BASE_H__
#define __LEABA_LPM_CORE_TCAM_UTILS_BASE_H__

#include "lld/ll_device.h"
#include "lpm_internal_types.h"

/// @file
namespace silicon_one
{

class lpm_core_tcam_utils_base
{
public:
    ///@brief Default destructor.
    virtual ~lpm_core_tcam_utils_base() = default;

    /// @brief Get number of cells in a block of a given type.
    ///
    /// @param[in]   block_type     Type of block.
    ///
    /// @return Number of cells in a block type.
    static uint8_t get_num_cells_in_block_type(logical_tcam_type_e block_type)
    {
        constexpr std::array<uint8_t, 4> block_size_arr{{1, 2, 4, 1}}; // include NOBODY

        size_t block_idx = static_cast<size_t>(block_type);
        return block_size_arr[block_idx];
    }

    /// @brief Map a LPM key to a logical TCAM.
    ///
    /// @param[in]     key          Key to map.
    ///
    /// @return Relevant logical TCAM type for key.
    virtual logical_tcam_type_e get_logical_tcam_type_of_key(const lpm_key_t& key) const = 0;

protected:
    ///@brief Default constructor.
    lpm_core_tcam_utils_base() = default;

}; // class lpm_core_tcam_utils_base

/// @brief Create core tcam utils per project.
///
/// @param[in]  ll_device  Low level device.
///
/// @return Pointer to core tcam utils object.
lpm_core_tcam_utils_scptr create_core_tcam_utils(const ll_device_sptr& ll_device);

} // namespace silicon_one

#endif // __LEABA_LPM_CORE_TCAM_UTILS_BASE_H__
