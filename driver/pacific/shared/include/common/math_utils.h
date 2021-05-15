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

#ifndef __MATH_UTILS_H__
#define __MATH_UTILS_H__

#include "bit_utils.h"
#include <stdint.h>

/// @file
/// @brief Math utilities.

namespace silicon_one
{

/// @brief Unit order of magnitude constants
enum {
    UNITS_IN_KILO = 1000,                  ///< The number of units in a decimal kilo
    UNITS_IN_MEGA = 1000ULL * 1000,        ///< The number of units in a decimal mega
    UNITS_IN_GIGA = 1000ULL * 1000 * 1000, ///< The number of units in a decimal giga
    UNITS_IN_KIBI = 1024,                  ///< The number of units in a binary kilo
};

/// @brief Rounds a value up to the closest multiple of step.
///
/// @param[in]  value       Value to round up.
/// @param[in]  step        Step size to round to.
///
/// @return The value rounded up to the closest multiple of step.
constexpr static inline uint64_t
round_up(uint64_t value, uint64_t step)
{
    return ((value + step - 1) / step) * step;
}

/// @brief Rounds a value down to the closest multiple of step.
///
/// @param[in]  value       Value to round down.
/// @param[in]  step        Step size to round to.
///
/// @return The value rounded down to the closest multiple of step.
static inline uint64_t
round_down(uint64_t value, uint64_t step)
{
    return (value / step) * step;
}

/// @brief Get log2 rounded down to the nearest integer.
///
/// @param[in]  value   Value.
///
/// @return Lower discrete point of log2(value).
inline size_t
int_log(uint64_t value)
{
    return bit_utils::get_msb(value);
}

/// @brief Divides numerator by denominator, rounding the result up
///
/// @param[in]  numerator      Numerator for the division
/// @param[in]  denominator    Denominator for the division
///
/// @return  (numerator / denominator) with any fractional part rounded up
constexpr uint64_t
div_round_up(uint64_t numerator, uint64_t denominator)
{
    return ((numerator + denominator - 1) / denominator);
}

/// @brief Convert a value from mega-units magnitude to units magnitude.
///
/// @param[in]  mega_units  Value in mega-units magnitude.
///
/// @return Converted value to units magnitude.
static inline uint64_t
mega_to_unit(uint64_t mega_units)
{
    return (mega_units * UNITS_IN_MEGA);
}

/// @brief Convert a value from units magnitude to mega-units magnitude.
///
/// @param[in]  units       Value in units magnitude.
///
/// @return Converted value to mega-units magnitude.
static inline uint64_t
unit_to_mega(uint64_t units)
{
    return (units / UNITS_IN_MEGA);
}

/// @brief Convert a value from kilo-units magnitude to units magnitude.
///
/// @param[in]  kilo_units  Value in kilo-units magnitude.
///
/// @return Converted value to units magnitude.
static inline uint64_t
kilo_to_unit(uint64_t kilo_units)
{
    return (kilo_units * UNITS_IN_KILO);
}

/// @brief Convert a value from units magnitude to kilo-units magnitude.
///
/// @param[in]  units       Value in units magnitude.
///
/// @return Converted value to kilo-units magnitude.
static inline uint64_t
unit_to_kilo(uint64_t units)
{
    return (units / UNITS_IN_KILO);
}

/// @brief Convert a value from units magnitude to 1024-units magnitude.
///
/// @param[in]  units       Value in units magnitude.
///
/// @return Converted value to kilo-units magnitude.
static inline uint64_t
unit_to_kibi(uint64_t units)
{
    return (units / UNITS_IN_KIBI);
}

/// @brief Round integer division to nearest value.
///
/// @param[in]  dividend        Dividend value.
/// @param[in]  divisor         Divisor value.
///
/// @return The rounded value of the division to the nearest discrete point.
static inline uint64_t
div_round_nearest(uint64_t dividend, uint64_t divisor)
{
    return (dividend + (divisor / 2)) / divisor;
}

/// @brief Return the maximum of two values.
///
/// @note In C++11 the max signature is: const T& max (const T& a, const T& b).
///       In C++14 the max signature is: constexpr const T& max (const T& a, const T& b).
///       With the C++11 signature, max is not compile-time evaluated.
///
/// @param[in] a    First value.
/// @param[in] b    Second value.
///
/// @return The maximum of two values.
template <class T>
constexpr const T&
constexpr_max(const T& a, const T& b)
{
    return (a > b) ? a : b;
}

/// @brief Return the greatest common divisor (GCD) of two numbers.
///
/// @param[in]  a        First number.
/// @param[in]  b        Second number.
///
/// @return The GCD of the given two numbers. If both numbers are equal to 0, then 0 is returned.
static uint64_t
gcd(uint64_t a, uint64_t b)
{
    // assume a <= b, otherwise, we will have one more iteration
    while (a) {
        uint64_t tmp = a;
        a = b % a;
        b = tmp;
    }
    return b;
}

/// @brief Return the lowest common multiplier (LCM) of two numbers.
///
/// @param[in]  a        First number.
/// @param[in]  b        Second number.
///
/// @return The LCM of the given two numbers. If both numbers are equal to 0, then 0 is returned.
static inline uint64_t
lcm(uint64_t a, uint64_t b)
{
    if (a == 0 || b == 0) {
        return 0;
    }

    if (a > b) {
        uint64_t tmp = a;
        a = b;
        b = tmp;
    }
    // This is an optimization check.
    if (b % a == 0) {
        return b;
    }
    uint64_t a_b_gcd = gcd(a, b);
    return a * b / a_b_gcd;
}

/// @brief Maps the input value into a min-max range.
///
/// @param[in]  value      Value to be normalized.
/// @param[in]  min        Minimum number.
/// @param[in]  max        Maximum number.
///
/// @return Value between min and max.
constexpr static inline uint64_t
clamp(uint64_t value, uint64_t min, uint64_t max)
{
    return (value < min) ? min : (value > max) ? max : value;
}

} // namespace silicon_one

#endif
