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

#ifndef __LPM_TOP_HW_WRITER_PL_GR_H__
#define __LPM_TOP_HW_WRITER_PL_GR_H__

#include "lpm_top_hw_writer.h"

namespace silicon_one
{

/// @brief Database level HW writer, responsible for distributor and group to core mapping updates.
class lpm_top_hw_writer_pl_gr : public lpm_top_hw_writer
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    // lpm_top_hw_writer API-s
    const ll_device_sptr& get_ll_device() const override;
    la_status update_distributor(const lpm_distributor::hardware_instruction_vec& instructions) override;
    la_status read_indices_of_last_accessed_hbm_buckets(vector_alloc<size_t>& hw_indices) override = 0;

protected:
    /// @brief CDB top resources needed to write LPM distributor and group to core updates.
    struct cdb_top_akpg {
        lld_memory_array_sptr lpm_tcam_index_to_core; ///< Group index to core map.
        lld_memory_array_sptr lpm_core_map_tcam;      ///< Distributor TCAMs.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(cdb_top_akpg);

    enum {
        NUM_TCAMS_PER_LOOKUP_INTERFACE = 4,
        NUM_CELLS_IN_BANK = 256,
        NUM_BANKS_FOR_IPV4_ENTRY = NUM_TCAMS_PER_LOOKUP_INTERFACE / 2,
        NUM_BANKS_FOR_IPV6_ENTRY = NUM_TCAMS_PER_LOOKUP_INTERFACE,
        CORE_ENTRY_WIDTH = 4
    };

    /// @brief C'tor
    ///
    /// @param[in]      ldevice                 Low level device.
    explicit lpm_top_hw_writer_pl_gr(const ll_device_sptr& ldevice);

    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lpm_top_hw_writer_pl_gr() = default;

    /// @brief Write to distributor location.
    ///
    /// @param[in]      location        Location to write.
    /// @param[in]      key             Key to write.
    /// @param[in]      payload         Payload to write.
    ///
    /// @return #la_status.
    la_status set_distributor_line(const distributor_cell_location& location, const lpm_key_t& key, lpm_payload_t payload);

    /// @brief Invalidate location in distributor.
    ///
    /// @param[in]      location        Location to invalidate.
    /// @param[in]      key             Key of distributor entry.
    ///
    /// @return #la_status.
    la_status remove_distributor_line(const distributor_cell_location& location, const lpm_key_t& key);

    /// @brief Update index to core map.
    ///
    /// @param[in]      location        Location to write.
    /// @param[in]      key             Key to write.
    /// @param[in]      payload         Payload to write.
    ///
    /// @return #la_status.
    la_status update_index_to_core(const distributor_cell_location& location, const lpm_key_t& key, lpm_payload_t payload);

    // Members
    ll_device_sptr m_ll_device;           ///< Low level device.
    size_t m_number_indexes_per_line;     ///< Number of entries in index to core SRAM line.
    size_t m_number_of_tcams;             ///< Number of distributor TCAMs.
    size_t m_distributor_row_width;       ///< Distributor row width.
    vector_alloc<cdb_top_akpg> m_cdb_top; ///< Vector of CDB top resources.
};

} // namespace silicon_one

#endif // __LPM_TOP_HW_WRITER_PL_GR_H__
