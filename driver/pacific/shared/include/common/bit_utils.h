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

#ifndef __BIT_UTILS_H__
#define __BIT_UTILS_H__

#include "common/dassert.h"
#include <cstring>
#include <stddef.h>
#include <stdint.h>

/// @file
/// @brief Bit utilities.

namespace silicon_one
{

namespace bit_utils
{
enum {
    BITS_IN_BYTE = 8, ///< Number of bits in byte.
    BITS_IN_UINT16 = BITS_IN_BYTE * sizeof(uint16_t),
    BITS_IN_UINT32 = BITS_IN_BYTE * sizeof(uint32_t),
    BITS_IN_UINT64 = BITS_IN_BYTE * sizeof(uint64_t)
};

/// @brief Get the MSB index of a uint64_t number.
///
/// @param[in]  value       Value to get the MSB from.
///
/// @return The MSB of the value.
constexpr inline int
get_msb(uint64_t value)
{
    return (value == 0) ? -1 : 63 - __builtin_clzll(value);
}

/// @brief Get the LSB index of a uint64_t number.
///
/// @param[in]  value       Value to get the LSB from.
///
/// @return The LSB bit of the value or -1 if no bits set
constexpr int
get_lsb(uint64_t value)
{
    return __builtin_ffsll(value) - 1;
}

/// @brief Helper function for the function bitsof(). This function is gcc-dependent, and may be used on plain structs only.
///
/// @tparam  T           Type of the struct.
///
/// @return The struct T filled by all ones
template <class T>
T
umaxof()
{
    T t;
    std::memset(&t, 0xFF, sizeof(T));
    return t;
}

/// @brief Get number of bits for a bitfield.
///        Usage: struct A { uint32_t x:22; uint32_t y:14; }; size_t s = bitsof(umaxof<A>().y); // s gets assign 14
///
/// @tparam  T           Type of the struct.
/// @param[in] umax   The bitfield of a struct that is filled by ones.
///
/// @return Number of bits in the bitfields
template <class T>
size_t
bitsof(const T& umax)
{
    return get_msb(umax) + 1;
}

/// @brief Get the 1-bit parity of a uint64_t number.
///
/// @param[in]  value       Value to get the parity from.
///
/// @return The parity bit of the value.
constexpr size_t
get_parity(uint64_t value)
{
    return __builtin_parityll(value);
}

/// @brief Get number of bits needed to represent value.
///
/// @param[in]  value       Value to count bits to represent.
///
/// @return Number of bits to represent.
inline size_t
bits_to_represent(uint64_t value)
{
    if (value == 0) {
        return 1;
    }

    return get_msb(value) + 1;
}

/// @brief Get a uint64_t mask_width wide mask containing ones, aligned to lsb.
///
/// @param[in]  mask_width  Width of mask to get.
///
/// @return Mask with given width from lsb.
inline uint64_t
get_lsb_mask(size_t mask_width)
{
    if (mask_width == 0) {
        return 0;
    }

    uint64_t mask = (uint64_t)-1;
    size_t shift = (BITS_IN_UINT64 - mask_width);

    return mask >> shift;
}

/// @brief Get a uint64_t width_bits wide value containing ones, aligned to lsb.
///
/// @param[in]  width_bits  Width of value to get.
///
/// @return width_bits wide value containing ones, aligned to lsb.
inline uint64_t
ones(size_t width_bits)
{
    return get_lsb_mask(width_bits);
}

/// @brief Returns a mask with specified bits set.
///
/// Returns a mask with bits [lsb .. lsb + mask_len -1] set.
///
/// @param[in] lsb          First bit to set.
/// @param[in] mask_width   Number of bits to set.
///
/// @note If lsb + mask_width >= BITS_IN_UINT64, the returned value is erroneous
/// @return A mask with specified bits set.
inline uint64_t
get_range_mask(size_t lsb, size_t mask_width)
{
    return get_lsb_mask(mask_width) << lsb;
}

/// @brief Get mask to clear invalid bits.
///
/// Typical usage:
/// uint64_t n_bits_elem;
/// uint64_t clear_mask = get_clear_mask(n, 64);
/// n_bits_elem &= clear_mask;
///
/// @param[in]  valid_bits  Number of valid bits to maintain.
/// @param[in]  granularity Element granularity.
///
/// @return Mask used to clear invalid MSB bits.
///
/// @note Another possible implementation is to have the storage passed as a template argument.
///       Main benefit is the fact granularity calculation will be done inside the function.
inline uint64_t
get_clear_mask(size_t valid_bits, size_t granularity)
{
    size_t bits_to_keep = ((valid_bits - 1) % granularity) + 1;

    return get_lsb_mask(bits_to_keep);
}

/// @brief Set bits in given range [msb, lsb].
///
/// If value is narrower than (msb - lsb + 1), value is zero-extended.
/// if value is wider than (msb - lsb + 1), extra bits in value are ignored.
///
/// @param[in]      base            Base value to set from.
/// @param[in]      msb             Upper bound.
/// @param[in]      lsb             Lower bound.
/// @param[in]      val             Given bits to set.
///
/// @return         Base with [msb-lsb] bits overrides.
inline uint64_t
set_bits(uint64_t base, size_t msb, size_t lsb, uint64_t val)
{
    uint64_t value_mask = get_lsb_mask(msb - lsb + 1);
    uint64_t base_mask = ~(value_mask << lsb);
    return (base & base_mask) | ((val & value_mask) << lsb);
}

/// @brief Get sub-sequence of bits starting at 'lsb' and ending at 'msb'.
///
/// @param[in] value    Original value.
/// @param[in] msb      Index of the highest bit in the sub-sequence.
/// @param[in] lsb      Index of the lowest bit in the sub-sequence.
///
/// @return    Sub-sequence of bits starting at 'lsb' and ending at 'msb'.
inline uint64_t
get_bits(uint64_t value, size_t msb, size_t lsb)
{
    uint64_t mask = get_lsb_mask(msb - lsb + 1);
    uint64_t bits = (value >> lsb) & mask;

    return bits;
}

/// @brief Get a single bit at position 'pos'
///
/// @param[in] value    Original value.
/// @param[in] pos      Bit index to retrieve.
///
/// @return The value of a single bit at position 'pos'.
inline uint64_t
get_bit(uint64_t value, uint8_t pos)
{
    return (value >> pos) & 0x1;
}

/// @brief Set a single bit at position 'pos' to a given value.
///
/// @param[in] value        Value to modify.
/// @param[in] pos          Bit index to modify.
/// @param[in] bit_value    Bit value to set.
inline void
set_bit(uint64_t* value, uint8_t pos, bool bit_value)
{
    uint64_t bit_to_modify = 1ULL << pos;
    if (bit_value) {
        // set the bit
        (*value) |= bit_to_modify;
    } else {
        // clear the bit
        (*value) &= ~bit_to_modify;
    }
}

/// @brief Set a single bit at position 'pos' to a given value.
///
/// @param[in] value        Value to modify.
/// @param[in] pos          Bit index to modify.
/// @param[in] bit_value    Bit value to set.
///
/// @return         Base with [pos] bit override.
inline uint64_t
set_bit(uint64_t value, size_t pos, bool bit_value)
{
    uint64_t bit_to_modify = 1ULL << pos;

    value &= ~bit_to_modify;
    value |= (bit_value * bit_to_modify);

    return value;
}

/// @brief      Transform width in bytes (8bit) to width in double-words (32bit).
///
/// @param[in]  byte_width  Width in bytes.
///
/// @return     Width in integer number of dwords.
inline size_t
width_bytes_to_dwords(size_t byte_width)
{
    return ((byte_width + 3) >> 2);
}

/// @brief      Transform width in bits to width in double-words (32bit).
///
/// @param[in]  bit_width  Width in bits.
///
/// @return     Width in integer number of dwords.
inline size_t
width_bits_to_dwords(size_t bit_width)
{
    return ((bit_width + 31) >> 5);
}

/// @brief      Transform width in bytes (8bit) to width in double-words (32bit) converted to number of bits.
///
/// @param[in]  byte_width  Width in bytes.
///
/// @return     Width in integer number of dwords converted to number of bits.
inline size_t
width_bytes_to_dword_bits(size_t byte_width)
{
    return (((byte_width + 3) >> 2) << 5);
}

/// @brief      Reverse N LSB bits from a given value.
///
/// Rest of the value is dropped.
///
/// @param[in]  value       Source value.
/// @param[in]  num_bits    Number of bits to reverse from LSB.
///
/// @return     Reversed N LSBs.
inline uint64_t
reverse(uint64_t value, size_t num_bits)
{
    uint64_t res = 0;
    for (size_t i = 0; i < num_bits; i++) {
        res = (res << 1) | (value & 1);
        value >>= 1;
    }

    return res;
}

/// @brief Set bits in given range [msb, lsb].
///
///
/// @param[in]      target          Buffer to contain the bits.
/// @param[in]      msb             Upper bound.
/// @param[in]      lsb             Lower bound.
/// @param[in]      val             Data to write.
void set_bits(uint64_t* target, size_t msb, size_t lsb, const uint64_t* val);

/// @brief Get bits in given range [msb, lsb].
///
///
/// @param[in]      source          Buffer to contain the bits.
/// @param[in]      msb             Upper bound.
/// @param[in]      lsb             Lower bound.
///
/// @param[out]     out_val         Bits read.
void get_bits(const uint64_t* source, size_t msb, size_t lsb, uint64_t* out_val);

/// @brief      Returns bit from uint8_t array
///
///
/// @param[in]  array       Buffer to contain the bits
/// @param[in]  pos         Bit's position inside the array
///
/// @return     True if bit is set, false otherwise
inline bool
is_bit_set(const uint8_t* array, size_t pos)
{
    size_t element_index = pos >> 3;
    size_t bit_offset = pos & 0x07;

    return (array[element_index] >> bit_offset) & 0x01;
}

} // namespace bit_utils

} // namespace silicon_one

#endif

#define BITS_SIZEOF(S, F)                                                                                                          \
    silicon_one::bit_utils::bitsof(silicon_one::bit_utils::umaxof<std::remove_reference<decltype(S)>::type>().F)
