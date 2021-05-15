// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_TM_UTILS_H__
#define __LA_TM_UTILS_H__

#include "api/tm/la_output_queue_scheduler.h"
#include "api/types/la_tm_types.h"
#include "common/bit_vector.h"
#include "lld/gibraltar_mem_structs.h"

#include "hld_types_fwd.h"
#include "lld/lld_memory.h"

namespace silicon_one
{

class tm_utils
{
public:
    enum {
        TM_WEIGHT_MAX = 255, ///< TM weight max value.
        TPSE_WFQ_WEIGHT_WIDTH
        = gibraltar::sch_tpse_wfq_cfg_memory::fields::TPSE_WFQ_WEIGHT0_WIDTH, ///< TM WFQ weight width in bits.
        TM_WFQ_WEIGHT_MAX = 63,                                               ///< TM WFQ weight max value.

        NUM_OQS_PER_SYSTEM_PORT_SCH = 8, ///< OQs per system port

        VSC_MAP_CFG_ENTRIES = 4, ///< Number of entries per-line in the VSC map configuration memory.

        IFG_SYSTEM_PORT_SCHEDULERS = 20,    ///< System ports scheduler per IFG.
        TM_IFG_SYSTEM_PORT_SCHEDULERS = 26, ///< System ports scheduler per IFG of TM blocks.

        IFG_OUTPUT_QUEUE_SCHEDULERS = 4 * 1024, ///< OQSEs per IFG

        EIR_WEIGHT_MAP_OFFSET = 64, ///< EIR weight map offset in the "global" weight map

        TM_MAX_RATE_VALUE
        = 0x3FFFF, ///< The TM rate value is 18 bits, so max value is all ones. This actually represents the lowest rate.

        MIN_BUCKET_SIZE = 2,               ///< Min bucket size.
        MAX_BUCKET_SIZE = 0xFF,            ///< Max bucket size.
        UNLIMITED_BUCKET_SIZE = 0x1FF,     ///< Unlimited bucket size.
        DEFAULT_CREDIT_BUCKET_SIZE = 30,   ///< Credit bucket size default value.
        DEFAULT_TRANSMIT_BUCKET_SIZE = 30, ///< Transmit bucket size default value.
        MAX_CREDIT_BUCKET_SIZE = 10,       ///< Credit max bucket size.
        MAX_TRANSMIT_BUCKET_SIZE = 40,     ///< Transmit max bucket size.

    };

    // Token Bucket configuration
    union token_bucket_ratio_cfg_t {
        uint32_t flat;
        struct fields_s {
            uint32_t mantissa : 5; ///< Mantissa of the rate
            uint32_t exponent : 5; ///< Exponent of the rate
        } fields;
    };

    /// @brief Convert rate in bps to device value which represents same rate.
    ///
    /// @param[in]  rate                    Rate in bps.
    /// @param[in]  sch_token_size          Size in bytes of a credit scheduler token.
    /// @param[in]  dev_freq_khz            Device frequency in KHz.
    /// @param[out] out_device_rate         Rate in device value.
    ///
    /// @retval     LA_STATUS_SUCCESS       Rate converted successfully.
    /// @retval     LA_STATUS_EINVAL        Rate is unsupported.
    /// @retval     LA_STATUS_EOUTOFRANGE   Rate is out of range.
    static la_status convert_rate_to_device_val(la_rate_t rate,
                                                size_t sch_token_size,
                                                size_t dev_freq_khz,
                                                uint32_t& out_device_rate);

    /// @brief Convert rate from device value to bps.
    ///
    /// @param[in]  device_rate     Rate in device value.
    /// @param[in]  sch_token_size  Size in bytes of a scheduler token.
    /// @param[in]  dev_freq_khz    Device frequency in KHz.
    ///
    /// @return Same rate in bps.
    static la_rate_t convert_rate_from_device_val(la_uint64_t device_rate, size_t sch_token_size, size_t dev_freq_khz);

    /// @brief Convert rate from device value to bps.
    ///
    /// @param[in]  device_rate         Rate in device value.
    /// @param[in]  num_tokens_incr     Number of tokens given every cycle.
    /// @param[in]  sch_token_size      Size in bytes of a scheduler token.
    /// @param[in]  dev_freq_khz        Device frequency in KHz.
    ///
    /// @return Same rate in bps.
    static la_rate_t convert_rate_from_device_val(la_uint64_t device_rate,
                                                  uint64_t num_tokens_incr,
                                                  size_t sch_token_size,
                                                  size_t dev_freq_khz);

    /// @brief Calculate ratio of a rate compared to other rate and return TM style floating value of this ratio.
    ///
    /// The bit vector has 5 bits for mantissa and 5 bits for exponent.
    ///
    /// @param[in]  full            Full rate to use (in bps).
    /// @param[in]  partial         Partial/fraction of full rate to use (in bps).
    ///
    /// @return #bit_vector with 5 bits for mantissa and 5 bits for exponent as used by TM.
    static token_bucket_ratio_cfg_t calc_rate_ratio(la_rate_t full, la_rate_t partial);

    /// @brief Convert device representation to IEEE floating point.
    ///
    /// @param[in]  exponent        Pacific exponent.
    /// @param[in]  mantissa        Pacific mantissa.
    ///
    /// @return IEEE floating point.
    static float convert_float_from_device_val(uint32_t exponent, uint32_t mantissa);

    /// @brief Convert IEEE floating point to device representation.
    ///
    /// @param[in]  val             IEEE floating point.
    ///
    /// @return Exponent and Mantissa in device representation.
    static token_bucket_ratio_cfg_t convert_float_to_device_val(float val);

    /// @brief Return whether an output queue scheduling mode is 8-priority
    static inline bool scheduling_mode_is_8p(la_output_queue_scheduler::scheduling_mode_e mode)
    {
        return (size_t)mode >= (size_t)la_output_queue_scheduler::scheduling_mode_e::FIRST_LPSE_8P_MAP;
    }

    /// @brief Convert weight vector into la_rate_t vector.
    ///
    /// Convert API weight to HW rate.
    ///
    /// @param[in]  weights         Vector of all wights.
    /// @param[in]  num_of_bits     Register size in bits that the max rate should fit in.
    ///
    /// @return Vector with calculated rate.
    static std::vector<la_rate_t> convert_weight_2_rate_vector(const std::vector<la_wfq_weight_t>& weights, size_t num_of_bits);

    static la_status set_burst_size(const la_device_impl_wptr& device,
                                    lld_memory_sptr cfg_memory,
                                    lld_memory_sptr dynamic_memory,
                                    size_t mem_line,
                                    lld_register_sptr shaper_update_reg,
                                    size_t burst);

    static la_status set_oqcs_rate(const la_device_impl_wptr& device,
                                   lld_memory_sptr cfg_memory,
                                   lld_memory_sptr dynamic_memory,
                                   size_t mem_line,
                                   lld_register_sptr shaper_update_reg,
                                   la_rate_t rate,
                                   la_rate_t port_speed,
                                   la_rate_t full_rate,
                                   size_t requested_burst_size);

    static la_status get_vsc_mapping(const la_device_impl_wptr& device,
                                     lld_memory_sptr map_cfg_memory,
                                     la_vsc_gid_t vsc,
                                     size_t& out_oqse_id);
};

} // namespace silicon_one

#endif // __LA_TM_UTILS_H__
