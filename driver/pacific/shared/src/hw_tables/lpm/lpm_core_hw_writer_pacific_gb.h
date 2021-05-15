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

#ifndef __LEABA_LPM_CORE_HW_WRITER_PACIFIC_GB_H__
#define __LEABA_LPM_CORE_HW_WRITER_PACIFIC_GB_H__

#include "common/la_status.h"
#include "lpm_core_hw_writer.h"

/// @file

namespace silicon_one
{

class lpm_core_hw_writer_pacific_gb : public lpm_core_hw_writer
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    // lpm_core_hw_writer API-s
    la_status write_tcam(const tcam_cell_location& location,
                         const lpm_key_t& key,
                         lpm_payload_t payload,
                         bool only_update_payload) const override;
    la_status invalidate_tcam(const tcam_cell_location& location, const lpm_key_t& key) override;
    lpm_entry read_tcam(const tcam_cell_location& location) const override;
    la_status write_tcam_default_row() const override;

    /// @brief Mask L2 SRAM ECC Interrupt Registers.
    ///
    /// In Pacific, false ECC error notification is raised when writing to LPM.
    /// This is the WA implementation.
    ///
    /// @param[in]      enable             Predicate indicating whether to enable/disable the L2 ECC interrupts.
    ///
    /// @return #la_status.
    la_status set_l2_sram_ecc_regs_interrupts_enabled(bool enable) const;

protected:
    enum {
        TCAM_BANK_SIZE = 512,
        NUM_BANKS_PER_TCAM = 2,
        TCAM_SIZE = TCAM_BANK_SIZE * NUM_BANKS_PER_TCAM,
        NUM_TCAMS_PER_BANKSET = 2,
        NUM_CELLS_PER_BANKSET = TCAM_BANK_SIZE * NUM_BANKS_PER_TCAM * NUM_TCAMS_PER_BANKSET,

        // Payload in TCAM contains two fields:
        // 1. ID - pointer to L1,
        TCAM_PAYLOAD_FIELD_ID_WIDTH = 13,
        // 2. Length of prefix, already captured in TCAM.
        TCAM_PAYLOAD_FIELD_LENGTH_WIDTH = 7,
        TCAM_PAYLOAD_WIDTH = TCAM_PAYLOAD_FIELD_ID_WIDTH + TCAM_PAYLOAD_FIELD_LENGTH_WIDTH,
        TCAM_PAYLOAD_FIELD_LENGTH_MAX_VALUE = (1 << TCAM_PAYLOAD_FIELD_LENGTH_WIDTH) - 1,

        // Number of TCAMs in a cdb core
        TCAMS_IN_REDUCED_CDB_CORE = 4,
        TCAMS_IN_FULL_CDB_CORE = 6,

        TCAM_MAX_NUM_OF_QUAD_LENGTH_ENTRIES = 240,
    };

    /// @brief CDB core resources needed to write LPM core. (relevant to Pacific/GB)
    struct cdb_core_resources_pacific_gb {
        lld_memory_scptr trie_mem[2];                    ///< LPM TCAM's memory.
        lld_memory_scptr subtrie_extended_mem;           ///< LPM L1 memory extension.
        lpm_core_hw_writer::cdb_core_resources cdb_core; ///< Relevant cdb core resources.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(cdb_core_resources_pacific_gb);

    /// @brief Construct a core HW writer.
    ///
    /// @param[in]      ldevice                  Low level device
    /// @param[in]      core_id                  Core id, unique for each core.
    /// @param[in]      num_tcam_banksets        Number of allocated TCAM banksets.
    lpm_core_hw_writer_pacific_gb(const ll_device_sptr& ldevice, lpm_core_id_t core_id, uint8_t num_tcam_banksets);

    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lpm_core_hw_writer_pacific_gb() = default;

    // Members
    cdb_core_resources_pacific_gb m_cdb_core_pa_gb; ///< Relevant cdb core resources.

private:
    /// @brief Write TCAM single row key to HW.
    ///
    /// @param[in]      location        Location to write to.
    /// @param[in]      node_key        Key to write.
    ///
    /// @return #la_status.
    la_status write_tcam_single_row_key(const tcam_cell_location& location, const lpm_key_t& node_key) const;

    /// @brief Write TCAM multiple rows key to HW.
    ///
    /// @param[in]      location        Location to write to.
    /// @param[in]      node_key        Key to write.
    ///
    /// @return #la_status.
    la_status write_tcam_multiple_rows_key(const tcam_cell_location& location, const lpm_key_t& node_key) const;
};

} // namespace silicon_one

#endif
