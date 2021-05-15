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

#ifndef __LPM_TOP_HW_WRITER_PACIFIC_H__
#define __LPM_TOP_HW_WRITER_PACIFIC_H__

#include "lpm_top_hw_writer.h"

namespace silicon_one
{

/// @brief Database level HW writer, responsible for distributor and group to core mapping updates.
class lpm_top_hw_writer_pacific : public lpm_top_hw_writer
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief C'tor
    ///
    /// @param[in]      ldevice                 Low level device.
    explicit lpm_top_hw_writer_pacific(const ll_device_sptr& ldevice);

    // lpm_core_hw_writer API-s
    const ll_device_sptr& get_ll_device() const override;
    la_status update_distributor(const lpm_distributor::hardware_instruction_vec& instructions) override;
    la_status read_indices_of_last_accessed_hbm_buckets(vector_alloc<size_t>& out_hw_indices) override;

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lpm_top_hw_writer_pacific() = default;

    enum {
        // Due to HW bug, IPV4 keys are LSB aligned.
        // Since the key is 46 bits, it's offset from MSB is 34 bits.
        IPV4_KEY_MSB_OFFSET = 34,
        NUM_DISTRIBUTER_ENTRIES = 128,
    };

    /// @brief Write in the distributor line.
    ///
    /// @param[in]      line            Line to write.
    /// @param[in]      key             Key to write.
    /// @param[in]      payload         Payload to write.
    ///
    /// @return #la_status.
    la_status set_distributor_line(size_t line, const lpm_key_t& key, lpm_payload_t payload);

    /// @brief Invalidate distributor line.
    ///
    /// @param[in]      line            Line to invalidate.
    ///
    /// @return #la_status.
    la_status remove_distributor_line(size_t line);

    /// @brief Update group to core map.
    ///
    /// @param[in]      group           Group to modify.
    /// @param[in]      core            Core for the group.
    ///
    /// @return #la_status.
    la_status update_group_to_core_map(size_t group, size_t core);

private:
    ll_device_sptr m_ll_device; ///< Low level device.
    size_t m_entries;           ///< Number of entries per type.
};

} // namespace silicon_one

#endif // __LPM_TOP_HW_WRITER_H__
