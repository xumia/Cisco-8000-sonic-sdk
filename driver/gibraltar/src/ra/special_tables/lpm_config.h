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

#ifndef __LPM_CONFIG_H__
#define __LPM_CONFIG_H__

#include "common/bit_vector.h"
#include "common/la_status.h"

#include <stddef.h>

#include "lld/lld_register.h"

namespace silicon_one
{

class ll_device;

/// @brief Static configuration of LPM.
///
/// The following is configured:
/// 1. LPM cache_mode is set to 0 since cache mode was not checked by design, means
/// it's not production.
/// 2. TCAM bypass is turned off. Unused.
///
/// Distributer is configured to send all packets to core0. For testing.
///
class lpm_config
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    enum {
        LPM_CORES_PER_CDB_CORE = 2,       ///< Number of LPM cores residing in once CDB core.
        TCAM_BYPASS_INDEX_FIELD_LEN = 13, ///< Length of index field in tcam bypass register.
        TCAM_BYPASS_KEY_FIELD_LEN = 142,  ///< Length of key/mask_n fields in tcam bypass register.
    };

    /// @brief Write Database configuration to the device.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  hbm_enabled         Enable L2 data storage in HBM.
    /// @param[in]  tcam_num_banksets   Number of TCAM banksets.
    ///
    /// @retval     status code.
    la_status configure_hw(const ll_device_sptr& ldevice, bool hbm_enabled, size_t tcam_num_banksets) const;

    /// @brief Configuring MMU to use HBM for LPM L2 storage.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    ///
    /// @return     #la_status.
    la_status configure_hbm(const ll_device_sptr& ldevice) const;

    lpm_config() = default;

private:
    template <class CDB_CORE>
    la_status write_cdb_core_config(const ll_device_sptr& ldevice, const CDB_CORE& core, size_t tcam_num_banksets) const;

    /// @brief Configuring allocation of LPM tcam between LPM and Central Tcam pool.
    template <class CDB_CORE>
    la_status configure_lpm_tcams(const ll_device_sptr& ldevice, const CDB_CORE& core, size_t tcam_num_banksets) const;

    struct hbm_fbm_bit_location {
        size_t fbm_instance;
        size_t row;
        size_t column;
    };

    // Each DRAM buffer is represented by a bit in FBM. FBM consists of 16 banks, each one with 512 rows x 128 columns.
    static constexpr size_t FBM_NUM_INSTANCES = 16;
    static constexpr size_t FBM_NUM_ROWS = 512;
    static constexpr size_t FBM_ROW_WIDTH_BITS = 128;

    using fbm_bit_vector_array = std::array<std::array<bit_vector, FBM_NUM_ROWS>, FBM_NUM_INSTANCES>;

    /// @brief Take a DRAM buffer from FBM for LPM use.
    ///
    /// @param[in]  fbm                 FBM Shadow.
    /// @param[in]  dram_buf_id         ID of DRAM Buffer to take.
    void steal_dram_buf_from_fbm(fbm_bit_vector_array& fbm, size_t dram_buf_id) const;

    /// @brief Write FBM Shadow to HW.
    ///
    /// @param[in]  ldevice             Low level device.
    /// @param[in]  fbm                 FBM Shadow.
    ///
    /// @return #la_status.
    la_status write_fbm_shadow_to_hw(const ll_device_sptr& ldevice, const fbm_bit_vector_array& fbm) const;

    /// @brief Write FBM Valid rows to HW.
    ///
    /// @param[in]  ldevice             Low level device.
    /// @param[in]  fbm                 FBM Shadow.
    ///
    /// @return #la_status.
    la_status write_fbm_valid_rows_to_hw(const ll_device_sptr& ldevice, const fbm_bit_vector_array& fbm) const;

    /// @brief Map a DRAM Buffer ID to a bit in FBM.
    ///
    /// @param[in]  dram_buf_id         DRAM Buffer ID.
    ///
    /// @return Location of FBM Bit.
    hbm_fbm_bit_location dram_buf_id_to_fbm_bit(size_t dram_buf_id) const;

    /// @brief Map a location of DRAM Buffer in HBM to a buffer ID.
    ///
    /// @param[in]  row                 HBM Row.
    /// @param[in]  col                 HBM Column.
    /// @param[in]  buf_idx             Index of DRAM buffer within row-column.
    ///
    /// @return DRAM Buffer ID.
    size_t dram_buf_location_to_id(size_t row, size_t col, size_t buf_idx) const;
};

} // namespace silicon_one

#endif // __LPM_CONFIG_H__
