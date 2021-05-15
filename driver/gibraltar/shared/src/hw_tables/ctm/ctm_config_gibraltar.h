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

#ifndef __CTM_CONFIG_GIBRALTAR_H__
#define __CTM_CONFIG_GIBRALTAR_H__

#include "ctm_config_tcam.h"

namespace silicon_one
{

class ll_device;

/// @brief Configuration object of CDB Central TCAM.
///
class ctm_config_gibraltar : public ctm_config_tcam
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    // C'tor
    ctm_config_gibraltar(const ll_device_sptr& ldevice,
                         bool is_linecard_mode,
                         size_t lpm_tcam_num_banksets,
                         size_t number_of_slices);

    // Helpers
    la_status configure_cdb_top() const override;

    template <class CORE>
    la_status set_default_cdb_core(const CORE& cdb_core, size_t core_idx) const;

    /// @brief Write Database configuration to the device.
    ///
    /// @retval     status code.
    la_status configure_hw() override;

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    ctm_config_gibraltar() = default;

    enum {
        NUM_SUBRINGS = 2,        ///< Number of subrings CDB core.
        KEY_320_TCAM_OFFSET = 1, ///< 320b keys are written to two consequitive TCAMs with indices X, X+1, where X is even number.
    };

    // Return true if the TCAM is extended TCAM in 320 key TCAM pair, false otherwise.
    bool is_msb_tcam(const size_t tcam_idx) const override;

    // 320b keys are written to two consequitive TCAMs with indices X, X+1, where X is even number.
    size_t get_key_320_tcam_offset() const override;

    size_t get_number_of_subrings() const override;

    /// @brief Invalidate TCAM in HW.
    ///
    /// @param[in]     tcam             TCAM to invalidate.
    /// @param[in]     srams            SRAMs pair to free.
    /// @param[in]     result_channel   Result channel to remove SRAM from.
    ///
    void invalidate_tcam(const tcam_desc& tcam, const ctm_sram_pair& srams, size_t result_channel) override;

    template <class CORE>
    void core_invalidate_tcam_subring0(const CORE& cdb_core,
                                       const tcam_desc& tcam,
                                       const ctm_sram_pair& srams,
                                       size_t result_channel);

    template <class CORE>
    void core_invalidate_tcam_subring1(const CORE& cdb_core,
                                       const tcam_desc& tcam,
                                       const ctm_sram_pair& srams,
                                       size_t result_channel);

    template <class CORE>
    void core_invalidate_sram_subring0(const CORE& cdb_core,
                                       const tcam_desc& tcam,
                                       size_t sram_idx,
                                       ctm_sram_half sram_half,
                                       size_t result_channel);
    template <class CORE>
    void core_invalidate_sram_subring1(const CORE& cdb_core,
                                       const tcam_desc& tcam,
                                       size_t sram_idx,
                                       ctm_sram_half sram_half,
                                       size_t result_channel);

    // HW writing
    void configure_tcam(size_t ring_idx, size_t subring_idx, size_t tcam_idx, size_t channel, bool configure_sram) override;

    template <class CORE>
    void core_configure_tcam_subring0(const CORE& cdb_core, size_t ring_idx, size_t tcam_idx, size_t channel, bool configure_sram);

    template <class CORE>
    void core_configure_tcam_subring1(const CORE& cdb_core, size_t ring_idx, size_t tcam_idx, size_t channel, bool configure_sram);

    template <class CORE>
    void core_configure_sram_to_tcam_subring0(const CORE& cdb_core,
                                              size_t ring_idx,
                                              size_t tcam_idx,
                                              size_t channel,
                                              size_t sram_idx,
                                              ctm_sram_half sram_half);

    template <class CORE>
    void core_configure_sram_to_tcam_subring1(const CORE& cdb_core,
                                              size_t ring_idx,
                                              size_t tcam_idx,
                                              size_t channel,
                                              size_t sram_idx,
                                              ctm_sram_half sram_half);

    // Configuration constants
    const vector_alloc<size_t> lpm_tcams = {0, 1};
};

} // namespace silicon_one

#endif // __CTM_CONFIG_GIBRALTAR_H__
