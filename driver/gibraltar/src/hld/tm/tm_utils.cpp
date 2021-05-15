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

#include <algorithm>
#include <cmath>

#include "common/bit_utils.h"
#include "common/defines.h"
#include "common/math_utils.h"
#include "lld/gibraltar_mem_structs.h"
#include "system/la_device_impl.h"
#include "tm_utils.h"

namespace silicon_one
{
union float_union {
    float f_val;

    struct {
        unsigned int mantissa : 23;
        unsigned int exponent : 8;
        unsigned int sign : 1;
    } f_fields;
};

enum {
    MANTISSA_SIZE = 5,
    TM_RATE_MAX_EXP = 19,
};

// Minimum is calculated by the lowest mantissa and highest exponent.
static tm_utils::token_bucket_ratio_cfg_t MIN_RATE_BUCKET_RATIO = {0x270}; /* exponent = TM_RATE_MAX_EXP, mantissa = 0x10 */

// Maximum is calculated by the highest mantissa and lowest exponent.
static tm_utils::token_bucket_ratio_cfg_t MAX_RATE_BUCKET_RATIO = {0x1f}; /* exponent = 0, mantissa = 0x1f */

la_status
tm_utils::convert_rate_to_device_val(la_rate_t rate, size_t sch_token_size, size_t dev_freq_khz, uint32_t& out_device_rate)
{
    if (rate == LA_RATE_UNLIMITED) {
        out_device_rate = 0x10;
        return LA_STATUS_SUCCESS;
    }
    if (rate == 0) {
        out_device_rate = 0;
        return LA_STATUS_SUCCESS;
    }

    la_uint64_t kbps_rate = unit_to_kilo(rate);

    if (kbps_rate == 0) {
        return LA_STATUS_EINVAL;
    }

    // TM_CREDIT_RATE = Credit value(in bits) * Device Clock (sch_token_size * 8 * DEV_FREQ_GHz) * 16
    // TM_CREDIT_RATE = 1000 * sch_token_size * 8 * (DEV_FREQ_KHz / 1000000) * 16 = 128 * sch_token_size * DEV_FREQ_KHz
    out_device_rate = (128 * sch_token_size * dev_freq_khz) / kbps_rate;
    if (out_device_rate > TM_MAX_RATE_VALUE) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return LA_STATUS_SUCCESS;
}

la_rate_t
tm_utils::convert_rate_from_device_val(la_uint64_t device_rate, size_t sch_token_size, size_t dev_freq_khz)
{
    return convert_rate_from_device_val(device_rate, 1 /* num_tokens_incr */, sch_token_size, dev_freq_khz);
}

la_rate_t
tm_utils::convert_rate_from_device_val(la_uint64_t device_rate,
                                       uint64_t num_tokens_incr,
                                       size_t sch_token_size,
                                       size_t dev_freq_khz)
{
    if (device_rate == 0) {
        return 0;
    }

    // device_rate = The time interval between every two allocations of credit in units of 1/16 clock cycles.
    // credit_rate_per_clock    = 16 / device_rate
    // credit_rate_per_sec      = credit_rate_per_clock * dev_freq_hz
    // kilo_credit_rate_per_sec = credit_rate_per_sec / KILO(10^3) = credit_rate_per_clock * dev_freq_khz = 16 / device_rate *
    // dev_freq_khz
    //
    // num_tokens_in_credit = The number of tokens in a credit (==num_tokens_incr)
    // token_size_in_bytes  = The size of a token in bytes (==sch_token_size)
    // token_size_in_bits   = token_size_in_bytes * 8
    //
    // kilo_bits_per_sec    = kilo_credit_rate_per_sec         * num_tokens_in_credit * token_size_in_bits
    //                      = 16 / device_rate * dev_freq_khz  * num_tokens_in_credit * token_size_in_bytes * 8
    //                      = 16 * 8 * token_size_in_bytes   * dev_freq_khz * num_tokens_in_credit / device_rate
    //                      = 16 * 8 * sch_token_size * dev_freq_khz * num_tokens_incr      / device_rate
    //
    // TM_TRANSMIT_RATE = Transmit value(in bits) * Device Clock (sch_token_size * 8 * DEV_FREQ_GHz) * 16
    // TM_TRANSMIT_RATE = 1000 * sch_token_size * 8 * (DEV_FREQ_KHz / 1000000) * 16 = 128 * sch_token_size * DEV_FREQ_KHz
    la_rate_t rate = ((128 * sch_token_size * dev_freq_khz * num_tokens_incr) / device_rate) * UNITS_IN_KILO;
    return rate;
}

tm_utils::token_bucket_ratio_cfg_t
tm_utils::calc_rate_ratio(la_rate_t full, la_rate_t partial)
{
    if (partial == 0) {
        return MIN_RATE_BUCKET_RATIO;
    }

    float ratio;
    ratio = (float)partial / (float)full;
    if (ratio >= 1) {
        return MAX_RATE_BUCKET_RATIO;
    }

    return convert_float_to_device_val(ratio);
}

float
tm_utils::convert_float_from_device_val(uint32_t exponent, uint32_t mantissa)
{
    float ratio = 0.0;
    for (size_t i = 0; i < MANTISSA_SIZE; i++) {
        size_t bit = bit_utils::get_bit(mantissa, i);
        ratio += bit / (float)(1ull << (1 + exponent + i));
    }

    return ratio;
}

tm_utils::token_bucket_ratio_cfg_t
tm_utils::convert_float_to_device_val(float val)
{
    float_union fu = {.f_val = val};
    tm_utils::token_bucket_ratio_cfg_t tb_cfg;
    size_t normalized_exp = 126 - fu.f_fields.exponent;
    if (normalized_exp >= TM_RATE_MAX_EXP + MANTISSA_SIZE) {
        return MIN_RATE_BUCKET_RATIO;
    }

    tb_cfg.fields.exponent = normalized_exp;
    tb_cfg.fields.mantissa = 1;

    size_t normalized_mantissa = fu.f_fields.mantissa >> 19;
    tb_cfg.fields.mantissa |= (bit_utils::reverse(normalized_mantissa, MANTISSA_SIZE - 1) << 1);

    if (tb_cfg.fields.exponent > TM_RATE_MAX_EXP) {
        tb_cfg.fields.mantissa <<= (tb_cfg.fields.exponent - TM_RATE_MAX_EXP);
        tb_cfg.fields.exponent = TM_RATE_MAX_EXP;
        // mantissa is 5 bits and LSB is always 1. Exponent must be < (TM_RATE_MAX_EXP + MANTISSA_SIZE) so maximum shift is 4.
        // Therefore, mantissa is always > 0.
        dassert_crit(tb_cfg.fields.mantissa > 0);
    }

    return tb_cfg;
}

std::vector<la_rate_t>
tm_utils::convert_weight_2_rate_vector(const std::vector<la_wfq_weight_t>& weights, size_t num_of_bits)
{
    std::vector<la_rate_t> res(weights.size());

    uint64_t max_allowed_result = ((1 << num_of_bits) - 1);

    auto minmax = std::minmax_element(weights.cbegin(), weights.cend());
    uint64_t min_weight = *minmax.first;
    uint64_t max_weight = *minmax.second;

    // Determine scale factor for min weight to use the largest result value.
    // This provides better granularity than scaling for max_weight to use result = 1.
    uint64_t scale_factor_based_on_min = min_weight * max_allowed_result;

    // Determine best-fit result for max weight, given the min-weight scaling. In case full-range is
    // used (e.g. 63:1 for 6-bits), this will be 1.
    uint64_t result_for_max_weight = std::max(div_round_nearest(scale_factor_based_on_min, max_weight), uint64_t{1});

    // Determine scale factor for max-weight to scale to its best-fit result.
    // In case of perfect fit, then this will be the same as scale_factor_based_on_min.
    uint64_t scale_factor_based_on_max = max_weight * result_for_max_weight;

    std::transform(weights.cbegin(), weights.cend(), res.begin(), [=](la_wfq_weight_t weight) {
        // Generate result value based on the scaling factor used for max weight
        uint64_t result = div_round_nearest(scale_factor_based_on_max, weight);

        // Ensure it is in range.
        return clamp(result, 1, max_allowed_result);
    });

    return res;
}

la_status
tm_utils::set_burst_size(const la_device_impl_wptr& device,
                         lld_memory_sptr cfg_memory,
                         lld_memory_sptr dynamic_memory,
                         size_t mem_line,
                         lld_register_sptr shaper_update_reg,
                         size_t burst)
{
    // All mem fields are built the same so taking sch_oq_pir_token_bucket_cfg_memory as template.
    // Making sure all structs are identical.
    static_assert((size_t)gibraltar::sch_oq_pir_token_bucket_cfg_memory::fields::OQ_PIR_MAX_BUCKET_VALUE_WIDTH
                      == (size_t)gibraltar::pdoq_oq_pir_token_bucket_cfg_memory::fields::OQ_PIR_MAX_BUCKET_VALUE_WIDTH,
                  "sch_oq_pir_token_bucket_cfg and pdoq_oq_pir_token_bucket_cfg dont match");
    static_assert((size_t)gibraltar::sch_oq_pir_token_bucket_cfg_memory::fields::OQ_PIR_MAX_BUCKET_VALUE_WIDTH
                      == (size_t)gibraltar::sch_oqpg_cir_token_bucket_cfg_memory::fields::OQPG_CIR_MAX_BUCKET_VALUE_WIDTH,
                  "sch_oq_pir_token_bucket_cfg and pdoq_oq_pir_token_bucket_cfg dont match");
    static_assert((size_t)gibraltar::sch_oq_pir_token_bucket_cfg_memory::fields::OQ_PIR_MAX_BUCKET_VALUE_WIDTH
                      == (size_t)gibraltar::pdoq_oqpg_cir_token_bucket_cfg_memory::fields::OQPG_CIR_MAX_BUCKET_VALUE_WIDTH,
                  "sch_oq_pir_token_bucket_cfg and pdoq_oq_pir_token_bucket_cfg dont match");
    static_assert((size_t)gibraltar::sch_oq_pir_token_bucket_cfg_memory::fields::OQ_PIR_MAX_BUCKET_VALUE_WIDTH
                      == (size_t)gibraltar::sch_oqse_cir_token_bucket_cfg_memory::fields::OQSE_CIR_MAX_BUCKET_VALUE_WIDTH,
                  "sch_oq_pir_token_bucket_cfg and pdoq_oq_pir_token_bucket_cfg dont match");
    static_assert((size_t)gibraltar::sch_oq_pir_token_bucket_cfg_memory::fields::OQ_PIR_MAX_BUCKET_VALUE_WIDTH
                      == (size_t)gibraltar::sch_oqse_eir_token_bucket_cfg_memory::fields::OQSE_EIR_MAX_BUCKET_VALUE_WIDTH,
                  "sch_oq_pir_token_bucket_cfg and pdoq_oq_pir_token_bucket_cfg dont match");

    size_t max_bucket_value = (1 << gibraltar::sch_oq_pir_token_bucket_cfg_memory::fields::OQ_PIR_MAX_BUCKET_VALUE_WIDTH) - 1;
    if (burst > max_bucket_value) {
        return LA_STATUS_EOUTOFRANGE;
    }

    gibraltar::sch_oq_pir_token_bucket_cfg_memory token_bucket_cfg;
    la_status status = device->m_ll_device->read_memory(*cfg_memory, mem_line, token_bucket_cfg);
    return_on_error(status);

    size_t current_burst_size = token_bucket_cfg.fields.oq_pir_max_bucket_value;
    if (current_burst_size == burst) {
        return LA_STATUS_SUCCESS;
    }

    // To change bucket size we need to do it in the following order:
    // 1. Set cfg_mem.MaxBucketValue =  UNLIMITED
    // 2. Set dynamic_mem.TokenBucketValue = burst
    // 3. Set cfg_mem.MaxBucketValue = burst

    // cfg_mem.MaxBucketValue = UNLIMITED
    token_bucket_cfg.fields.oq_pir_max_bucket_value = UNLIMITED_BUCKET_SIZE;
    status = device->m_ll_device->write_memory(*cfg_memory, mem_line, token_bucket_cfg);
    return_on_error(status);

    // Sleep
    bool sleep_in_set_max_burst = false;
    status = device->get_bool_property(la_device_property_e::SLEEP_IN_SET_MAX_BURST, sleep_in_set_max_burst);
    return_on_error(status);
    if (sleep_in_set_max_burst) {
        // Sleep time is the longest possible time between bit flips of
        // one of the shaper's coefficients. It happens at the coefficient with the highest index.
        // The shaper credits are refreshed every 8ns. That is - the time it takes for the
        // coefficient to flip is 8ns * 2^(max_coefficient). Sleep time should be at least this long.
        // It is doubled to be on the safe side
        status = device->m_ll_device->read_memory(*cfg_memory, mem_line, token_bucket_cfg);
        return_on_error(status);
        uint64_t exp = token_bucket_cfg.fields.oq_pir_rate_exponent;
        uint64_t man = token_bucket_cfg.fields.oq_pir_rate_mantissa;
        size_t max_coeff_index = exp + ((man == 0) ? 4 : bit_utils::get_msb(man));
        max_coeff_index %= 24; // Max coefficient index is 24
        size_t sleep_time_nanosec = 8 * (1 << max_coeff_index) * 2;
        log_debug(HLD,
                  "%s: exp=%lu man=%lu max_coeff_index=%lu sleep_time_nanosec=%lu",
                  __func__,
                  exp,
                  man,
                  max_coeff_index,
                  sleep_time_nanosec);

        status = device->flush();
        return_on_error(status);
        std::this_thread::sleep_for(std::chrono::nanoseconds(sleep_time_nanosec));
    }

    // dynamic_mem.TokenBucketValue = burst
    status = device->m_ll_device->write_memory(*dynamic_memory, mem_line, burst);
    return_on_error(status);

    // cfg_mem.MaxBucketValue = burst
    token_bucket_cfg.fields.oq_pir_max_bucket_value = burst;
    status = device->m_ll_device->write_memory(*cfg_memory, mem_line, token_bucket_cfg);
    return_on_error(status);

    if (current_burst_size == 0) {
        status = device->m_ll_device->write_register(shaper_update_reg, mem_line /*OQ ID*/);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
tm_utils::set_oqcs_rate(const la_device_impl_wptr& device,
                        lld_memory_sptr cfg_memory,
                        lld_memory_sptr dynamic_memory,
                        size_t mem_line,
                        lld_register_sptr shaper_update_reg,
                        la_rate_t rate,
                        la_rate_t port_speed,
                        la_rate_t full_rate,
                        size_t requested_burst_size)
{
    using namespace gibraltar;

    // All mem fields are built the same so taking sch_oqse_cir_token_bucket_cfg_memory as template.
    // Making sure all structs are identical.
    static_assert((size_t)sch_oqse_cir_token_bucket_cfg_memory::fields::OQSE_CIR_RATE_MANTISSA_WIDTH
                      == (size_t)sch_oqse_eir_token_bucket_cfg_memory::fields::OQSE_EIR_RATE_MANTISSA_WIDTH,
                  "sch_oq_pir_token_bucket_cfg and pdoq_oq_pir_token_bucket_cfg dont match");
    static_assert((size_t)sch_oqse_cir_token_bucket_cfg_memory::fields::OQSE_CIR_RATE_EXPONENT_WIDTH
                      == (size_t)sch_oqse_eir_token_bucket_cfg_memory::fields::OQSE_EIR_RATE_EXPONENT_WIDTH,
                  "sch_oq_pir_token_bucket_cfg and pdoq_oq_pir_token_bucket_cfg dont match");

    static_assert((size_t)sch_oqse_cir_token_bucket_cfg_memory::fields::OQSE_CIR_RATE_MANTISSA_WIDTH
                      == (size_t)sch_oq_pir_token_bucket_cfg_memory::fields::OQ_PIR_RATE_MANTISSA_WIDTH,
                  "sch_oq_pir_token_bucket_cfg and pdoq_oq_pir_token_bucket_cfg dont match");
    static_assert((size_t)sch_oqse_cir_token_bucket_cfg_memory::fields::OQSE_CIR_RATE_EXPONENT_WIDTH
                      == (size_t)sch_oq_pir_token_bucket_cfg_memory::fields::OQ_PIR_RATE_EXPONENT_WIDTH,
                  "sch_oq_pir_token_bucket_cfg and pdoq_oq_pir_token_bucket_cfg dont match");

    static_assert((size_t)sch_oqse_cir_token_bucket_cfg_memory::fields::OQSE_CIR_RATE_MANTISSA_WIDTH
                      == (size_t)pdoq_oq_pir_token_bucket_cfg_memory::fields::OQ_PIR_RATE_MANTISSA_WIDTH,
                  "sch_oq_pir_token_bucket_cfg and pdoq_oq_pir_token_bucket_cfg dont match");
    static_assert((size_t)sch_oqse_cir_token_bucket_cfg_memory::fields::OQSE_CIR_RATE_EXPONENT_WIDTH
                      == (size_t)pdoq_oq_pir_token_bucket_cfg_memory::fields::OQ_PIR_RATE_EXPONENT_WIDTH,
                  "sch_oq_pir_token_bucket_cfg and pdoq_oq_pir_token_bucket_cfg dont match");

    static_assert((size_t)sch_oqse_cir_token_bucket_cfg_memory::fields::OQSE_CIR_RATE_MANTISSA_WIDTH
                      == (size_t)sch_oqpg_cir_token_bucket_cfg_memory::fields::OQPG_CIR_RATE_MANTISSA_WIDTH,
                  "sch_oq_pir_token_bucket_cfg and pdoq_oq_pir_token_bucket_cfg dont match");
    static_assert((size_t)sch_oqse_cir_token_bucket_cfg_memory::fields::OQSE_CIR_RATE_EXPONENT_WIDTH
                      == (size_t)sch_oqpg_cir_token_bucket_cfg_memory::fields::OQPG_CIR_RATE_EXPONENT_WIDTH,
                  "sch_oq_pir_token_bucket_cfg and pdoq_oq_pir_token_bucket_cfg dont match");

    static_assert((size_t)sch_oqse_cir_token_bucket_cfg_memory::fields::OQSE_CIR_RATE_MANTISSA_WIDTH
                      == (size_t)pdoq_oqpg_cir_token_bucket_cfg_memory::fields::OQPG_CIR_RATE_MANTISSA_WIDTH,
                  "sch_oq_pir_token_bucket_cfg and pdoq_oq_pir_token_bucket_cfg dont match");
    static_assert((size_t)sch_oqse_cir_token_bucket_cfg_memory::fields::OQSE_CIR_RATE_EXPONENT_WIDTH
                      == (size_t)pdoq_oqpg_cir_token_bucket_cfg_memory::fields::OQPG_CIR_RATE_EXPONENT_WIDTH,
                  "sch_oq_pir_token_bucket_cfg and pdoq_oq_pir_token_bucket_cfg dont match");

    gibraltar::sch_oqse_cir_token_bucket_cfg_memory token_bucket_cfg;
    la_status status = device->m_ll_device->read_memory(*cfg_memory, mem_line, token_bucket_cfg);
    return_on_error(status);

    // If requested rate to be configured is higher than total port speed then shaper is disabled by setting burst size to
    // UNLIMITED.
    // If shaper was previously disabled, then if current requested rate is in limit - need to restore previous burst size.
    size_t burst_size = requested_burst_size;
    if (rate > port_speed) {
        burst_size = UNLIMITED_BUCKET_SIZE;
        log_debug(HLD,
                  "Requested scheduler rate: %llu - is higher than underlying mac_port speed: %llu, so shaper is being disabled",
                  rate,
                  port_speed);
    }

    // Set burst size 0 for rate 0, to close Rx/Tx completely.
    // SDK when configuring a rate(CIR/PIR) to 0, calculates and sets a small non-zero value,
    // configuring 0 burst size enforces 0 rate.
    if (rate == 0) {
        burst_size = 0;
        log_debug(HLD, "Setting burst size 0 for the requested rate: %llu", rate);
    }

    status = set_burst_size(device, cfg_memory, dynamic_memory, mem_line, shaper_update_reg, burst_size);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_EACCES) {
        return (status);
    }

    if (status == LA_STATUS_EACCES) {
        log_err(HLD, "Ignoring Burst Size set failure.");
    }

    // Need to read memory again as the call to set_burst_size performed write action
    status = device->m_ll_device->read_memory(*cfg_memory, mem_line, token_bucket_cfg);
    return_on_error(status);

    // Ratio between OQ rate and full rate is stored
    token_bucket_ratio_cfg_t ratio_cfg = calc_rate_ratio(full_rate, rate);
    token_bucket_cfg.fields.oqse_cir_rate_mantissa = ratio_cfg.fields.mantissa;
    token_bucket_cfg.fields.oqse_cir_rate_exponent = ratio_cfg.fields.exponent;

    status = device->m_ll_device->write_memory(*cfg_memory, mem_line, token_bucket_cfg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
tm_utils::get_vsc_mapping(const la_device_impl_wptr& device, lld_memory_sptr map_cfg_memory, la_vsc_gid_t vsc, size_t& out_oqse_id)
{
    // Verify the given VSC mapped to this OQSE
    size_t sch_mem_line = vsc / VSC_MAP_CFG_ENTRIES;
    gibraltar::sch_vsc_map_cfg_memory vsc_map_cfg;
    la_status stat = device->m_ll_device->read_memory(*map_cfg_memory, sch_mem_line, vsc_map_cfg);
    return_on_error(stat);

    switch (vsc % VSC_MAP_CFG_ENTRIES) {
    case 0:
        out_oqse_id = vsc_map_cfg.fields.oqse_id;
        return LA_STATUS_SUCCESS;
    case 1:
        out_oqse_id = vsc_map_cfg.fields.oqse_id1;
        return LA_STATUS_SUCCESS;
    case 2:
        out_oqse_id = vsc_map_cfg.fields.oqse_id2;
        return LA_STATUS_SUCCESS;
    case 3:
        out_oqse_id = vsc_map_cfg.fields.oqse_id3;
        return LA_STATUS_SUCCESS;
        break;
    }

    return LA_STATUS_EUNKNOWN;
}

} // namespace silicon_one
