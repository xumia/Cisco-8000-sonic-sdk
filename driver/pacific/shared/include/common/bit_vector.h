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

#if __GNUC__ == 7 && __GNUC_MINOR__ == 5
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#pragma GCC diagnostic ignored "-Wuninitialized"
#endif

#ifndef __BIT_VECTOR_H__
#define __BIT_VECTOR_H__

#include "common/allocator_wrapper.h"
#include "common/bit_utils.h"
#include "common/dassert.h"
#include "common/math_utils.h"
#include <string.h>
#include <string>

/// @file
/// @brief Bit vector class definition.

namespace silicon_one
{

/// @brief Bit vector base class.
///
/// _Storage object provides the following API-s:
///     _Storage(size_t size, uint64_t value)           ///< Allocate storage for size elements; given value is assigned to each
///     element.
///     size_t size() const;                            ///< Current number of elements in storage
///     uint64_t& operator[](size_t index);             ///< Reference to a requested element
///     const uint64_t& operator[](size_t index) const; ///< Const reference to a requested element
///     void resize(size_t new_size);                   ///< Resize storage to new size, added elements are set to 0
///
/// Efficient implementation of variable-width bit vector
template <class _Storage>
class bit_vector_base
{
public:
    /// @brief Construct a NULL bit vector.
    ///
    /// NULL bit vector refers to a bit vector with zero width.
    bit_vector_base();

    /// @brief Construct and initialize a bit vector.
    ///
    /// Width is set to be the minimal width to contain value.
    ///
    /// @param[in]      value           Initial value.
    bit_vector_base(uint64_t value);

    /// @brief Construct and initialize a bit vector, and set its width.
    ///
    /// Insert zeros if necessary, set to value's minimal width if larger than given width.
    ///
    /// @param[in]      value           Initial value.
    /// @param[in]      width           Width to set.
    bit_vector_base(uint64_t value, size_t width);

    /// @brief Construct and initialize a bit vector, and set its width.
    ///
    /// Treats val_array as big-endian array and set the bit vector's value from it. Array's size is calculated from the width
    /// parameter. Insert zeros if necessary, set to value's minimal width if larger than given width.
    ///
    /// @param[in]      val_array_sz    The size in bytes of val_array.
    /// @param[in]      val_array       Initial value array in big-endian order.
    /// @param[in]      width           Width to set.
    bit_vector_base(size_t val_array_sz, const uint8_t* val_array, size_t width);

    /// @brief Construct and initialize a bit vector using an already existing storage.
    ///
    /// The constructed bit vector wraps existing storage; no copying occurs.
    ///
    /// @param[in]      data        Data to wrap.
    /// @param[in]      width       Width of the bit_vector.
    bit_vector_base(uint64_t*& data, size_t width);

    /// @brief Construct and initialize a bit vector according to string.
    ///
    /// Width is set to be the minimal width to contain value.
    ///
    /// @param[in]      value           Initial value, as string, in hexadecimal base.
    bit_vector_base(std::string value);

    /// @brief Construct and initialize a bit vector according to string, and set its width.
    ///
    /// Insert zeros if necessary, set to value's minimal width if larger than given width.
    ///
    /// @param[in]      value           Initial value, as string, in hexadecimal base.
    /// @param[in]      width           Width to set.
    bit_vector_base(std::string value, size_t width);

    /// @brief Copy constructor from same storage type.
    ///
    /// @param[in]      other           Other bit_vector.
    bit_vector_base(const bit_vector_base& other);

    /// @brief Copy constructor from other storage type.
    ///
    /// @param[in]      other           Other bit_vector.
    template <class _OtherStorage>
    bit_vector_base(const bit_vector_base<_OtherStorage>& other);

    /// @brief Move constructor from same storage type.
    ///
    /// @param[in]      other           Other bit_vector.
    bit_vector_base(bit_vector_base&& other);

    ///@brief Create a bit-vector of the specifieed width with all bits set to 1
    static bit_vector_base ones(size_t width_bits)
    {
        bit_vector_base bv(0, width_bits);
        bv.negate();

        return bv;
    }

    ///@brief Create a bit-vector of the specifieed width with bits [msb..lsb] set to 1
    static bit_vector_base ones_range(size_t msb, size_t lsb, size_t width_bits)
    {
        if (msb < lsb) {
            return bit_vector_base(0, width_bits);
        }

        bit_vector_base<_Storage> shifted = ones(msb - lsb + 1) << lsb;
        shifted.resize(width_bits);

        return shifted;
    }

    /// @brief Assigns the complete value of the other bit vector with the same storage type.
    ///
    /// @param[in]      other           Other bit_vector.
    bit_vector_base& operator=(const bit_vector_base& other);

    /// @brief Assigns the complete value of the other bit vector, regardless of the storage type.
    ///
    /// @param[in]      other           Other bit_vector.
    template <class _OtherStorage>
    bit_vector_base& operator=(const bit_vector_base<_OtherStorage>& other);

    /// @brief Move assigns the complete value of the other bit vector with the same storage type.
    ///
    /// @param[in]      other           Other bit_vector.
    bit_vector_base& operator=(bit_vector_base&& other);

    /// @brief Destroy a bit vector.
    ~bit_vector_base() = default;

    /// @brief Check if bit vector is NULL.
    ///
    /// @return true if width is zero, false otherwise.
    bool is_null() const;

    /// @brief Check if bit vector is zero.
    ///
    /// @return true if all stored bits are zero, false otherwise.
    bool is_zero() const;

    /// @brief Get the least significant element.
    ///
    /// @return Least significant element.
    uint64_t get_value() const;

    /// @brief Get bit vector width in bits.
    ///
    /// @return Width in bits.
    size_t get_width() const;

    /// @brief Get bit vector width in bytes.
    ///
    /// @return Width in bytes.
    size_t get_width_in_bytes() const;

    /// @brief Get minimum width in bits, that can contain current value.
    ///
    /// @return Minimal width in bits.
    size_t get_minimal_width() const;

    /// @brief Get hash value of the current value.
    ///
    /// @return Hash value.
    size_t hash() const;

    /// @brief Get bits between given bounds [msb, lsb].
    ///
    /// @param[in]      msb             Upper bound.
    /// @param[in]      lsb             Lower bound.
    ///
    /// @return Bit vector containing requested bits.
    bit_vector_base bits(size_t msb, size_t lsb) const;

    /// @brief Get bits between given bounds [m_width - 1 - offset, m_width - offset - width].
    ///
    /// @param[in]      offset          Offset from msb.
    /// @param[in]      width           Requested bits width.
    ///
    /// @return Bit vector containing requested bits.
    bit_vector_base bits_from_msb(size_t offset, size_t width) const;

    /// @brief Get bits between given bounds [offset + width - 1, offset].
    ///
    /// @param[in]      offset          Offset from lsb.
    /// @param[in]      width           Requested bits width.
    ///
    /// @return Bit vector containing requested bits.
    bit_vector_base bits_from_lsb(size_t offset, size_t width) const;

    /// @brief Set bits in given range [msb, lsb].
    ///
    /// If value is narrower than (msb - lsb + 1), value is zero-extended.
    /// if value is wider than (msb - lsb + 1), extra bits in value are ignored.
    ///
    /// @param[in]      msb             Upper bound.
    /// @param[in]      lsb             Lower bound.
    /// @param[in]      value           Given bits to set.
    template <class _OtherStorage>
    void set_bits(size_t msb, size_t lsb, const bit_vector_base<_OtherStorage>& value);

    /// @brief Set bits in given range [m_width - 1 - offset, m_width - offset - width].
    ///
    /// @param[in]      offset          Offset from msb.
    /// @param[in]      width           Width of bits to set.
    /// @param[in]      value           Given bits to set.
    ///
    /// @return number of set bits.
    template <class _OtherStorage>
    size_t set_bits_from_msb(size_t offset, size_t width, const bit_vector_base<_OtherStorage>& value);

    /// @brief Set bits in given range [offset + width - 1, offset].
    ///
    /// @param[in]      offset          Offset from lsb.
    /// @param[in]      width           Width of bits to set.
    /// @param[in]      value           Given bits to set.
    ///
    /// @return number of set bits.
    template <class _OtherStorage>
    size_t set_bits_from_lsb(size_t offset, size_t width, const bit_vector_base<_OtherStorage>& value);

    /// @brief Set bits in given range [msb, lsb].
    ///
    /// If value is narrower than (msb - lsb + 1), value is zero-extended.
    /// if value is wider than (msb - lsb + 1), extra bits in value are ignored.
    ///
    /// @param[in]      msb             Upper bound.
    /// @param[in]      lsb             Lower bound.
    /// @param[in]      value           Given bits to set.
    void set_bits(size_t msb, size_t lsb, uint64_t value);

    /// @brief Set bits in given range [m_width - 1 - offset, m_width - offset - width].
    ///
    /// @param[in]      offset          Offset from msb.
    /// @param[in]      width           Width of bits to set.
    /// @param[in]      value           Given bits to set.
    ///
    /// @return number of set bits.
    size_t set_bits_from_msb(size_t offset, size_t width, uint64_t value);

    /// @brief Set bits in given range [m_width - 1 - offset, m_width - offset - width].
    ///
    /// @param[in]      offset          Offset from msb.
    /// @param[in]      width           Width of bits to set.
    /// @param[in]      value           Given bits to set.
    ///
    /// @return number of set bits.
    size_t set_bits_from_lsb(size_t offset, size_t width, uint64_t value);

    /// @brief Resize to a new width.
    ///
    /// @param[in]      new_width       New bit vector width.
    void resize(size_t new_width);

    /// @brief Get bit in given position.
    ///
    /// @param[in]      pos             Requested bit position.
    ///
    /// @return true if requested bit is one, false otherwise.
    bool bit(size_t pos) const;

    /// @brief Get bit in given position from msb.
    ///
    /// @param[in]      offset          Requested bit offset from msb.
    ///
    /// @return true if requested bit is one, false otherwise.
    bool bit_from_msb(size_t offset) const;

    /// @brief Set bit in given position.
    ///
    /// @param[in]      pos             Requested bit position.
    /// @param[in]      val             New value.
    void set_bit(size_t pos, bool val);

    /// @brief Performs negation operation on all bits.
    void negate();

    /// @brief Bit vector Negation operator.
    bit_vector_base operator~() const;

    /// @brief Bit vector OR operator.
    ///
    /// @param[in]      other           Bit vector to OR with this.
    ///
    /// @return Operation result.
    template <class _OtherStorage>
    bit_vector_base operator|(const bit_vector_base<_OtherStorage>& other) const;

    /// @brief Bit vector OR operator.
    /// Object is assigned with the operation result.
    ///
    /// @param[in]      other           Bit vector to OR with.
    template <class _OtherStorage>
    void operator|=(const bit_vector_base<_OtherStorage>& other);

    /// @brief Bit vector AND operator.
    ///
    /// @param[in]      other           Bit vector to AND with.
    ///
    /// @return Operation result.
    template <class _OtherStorage>
    bit_vector_base operator&(const bit_vector_base<_OtherStorage>& other) const;

    /// @brief Bit vector AND operator.
    /// Object is assigned with the operation result.
    ///
    /// @param[in]      other           Bit vector to AND with this.
    template <class _OtherStorage>
    void operator&=(const bit_vector_base<_OtherStorage>& other);

    /// @brief Bit vector XOR operator.
    ///
    /// @param[in]      other           Bit vector to XOR with.
    ///
    /// @return Operation result.
    template <class _OtherStorage>
    bit_vector_base operator^(const bit_vector_base<_OtherStorage>& other) const;

    /// @brief Bit vector XOR operator.
    /// Object is assigned with the operation result.
    ///
    /// @param[in]      other           Bit vector to XOR with.
    template <class _OtherStorage>
    void operator^=(const bit_vector_base<_OtherStorage>& other);

    /// @brief Shift left other and XOR with this bit vector.
    /// Object is assigned with the operation result.
    ///
    /// Operation is: this ^= (other << left_shift).
    ///
    /// @param[in]      other           Bit vector to shift and XOR with.
    /// @param[in]      left_shift     Amount to left shift other before XORing.
    template <class _OtherStorage>
    void xor_with_other_shifted_left(const bit_vector_base<_OtherStorage>& other, size_t left_shift);

    /// @brief Shift left operator.
    ///
    /// @param[in]      shift           Number of bits to shift.
    ///
    /// @return Operation result.
    bit_vector_base operator<<(size_t shift) const;

    /// @brief Shift right operator.
    ///
    /// @param[in]      shift           Number of bits to shift.
    ///
    /// @return Operation result.
    bit_vector_base operator>>(size_t shift) const;

    /// @brief Equal operator.
    ///
    /// Compares value and width.
    ///
    /// @param[in]      other           Bit vector to compare to.
    ///
    /// @return true if value and width are equal, false otherwise.
    template <class _OtherStorage>
    bool operator==(const bit_vector_base<_OtherStorage>& other) const;

    /// @brief Not equal operator.
    ///
    /// @param[in]      other           Bit vector to compare to.
    ///
    /// @return true if value or width are not equal, false otherwise.
    template <class _OtherStorage>
    bool operator!=(const bit_vector_base<_OtherStorage>& other) const;

    /// @brief Hexadecimal string representation of bit vector's value.
    ///
    /// @return string with bit vector's bits.
    std::string to_string() const;

    /// @brief Byte array representation of bit vector's value.
    ///
    /// @return pointer to byte array with bit vector's values.
    /// @note The array is not null terminated.
    ///       Use #get_width_in_bytes to get its length.
    uint8_t* byte_array();

    /// @brief Byte array representation of bit vector's value.
    ///
    /// @return pointer to byte array with bit vector's values.
    /// @note The array is not null terminated.
    ///       Use #get_width_in_bytes to get its length.
    const uint8_t* byte_array() const;

    /// @brief Get number of set bits in a bit vector.
    ///
    /// @return number of set bits in bit vector
    size_t count_ones() const;

    // Required when using private members of bit_vector_base<_OtherStorage>
    template <class _OtherStorage>
    friend class bit_vector_base;

    enum {
        BV_ELEMENT_SIZE_IN_BITS = 64,                                         ///< Number of bits in element.
        BV_BITS_IN_BYTE = 8,                                                  ///< Number of bits in byte.
        BV_ELEMENT_SIZE_IN_BYTES = BV_ELEMENT_SIZE_IN_BITS / BV_BITS_IN_BYTE, ///< Number of bytes in element.
    };

    template <class Archive>
    void serialize(Archive& ar)
    {
        ar(m_width, m_bits);
    }

private:
    /// @brief Get element accorfing to given index.
    ///
    /// Zero is returned if index exceeds last element index.
    ///
    /// @param[in]      index           Index of requested element.
    ///
    /// @return Requested element.
    uint64_t get_element(size_t index) const;

    /// @brief Get an element starting at given position [lsb + BV_ELEMENT_SIZE_IN_BITS - 1, lsb].
    ///
    /// @param[in]      lsb             Starting position of new element.
    ///
    /// @return Unaligned element.
    uint64_t get_unaligned_element(size_t lsb) const;

    // Members
    _Storage m_bits;    ///< Bit vector's bits storage.
    size_t m_width = 0; ///< Bit vector's width (in bits).
};

template <class _Storage>
bit_vector_base<_Storage>::bit_vector_base() : m_width(0)
{
}

template <class _Storage>
bit_vector_base<_Storage>::bit_vector_base(uint64_t value) : m_bits(1 /* size */, value /* value */)
{
    m_width = get_minimal_width();
}

template <class _Storage>
bit_vector_base<_Storage>::bit_vector_base(uint64_t value, size_t width) : m_bits(1 /* size */, value /* value */)
{
    m_width = get_minimal_width();

    if (width > m_width) {
        resize(width);
    }
}

template <class _Storage>
bit_vector_base<_Storage>::bit_vector_base(size_t val_array_sz, const uint8_t* val_array, size_t width)
    : m_bits(div_round_up(width, BV_ELEMENT_SIZE_IN_BITS), 0 /* value */), m_width(width)
{
    uint8_t* byte_arr = byte_array();
    size_t bytes_to_copy = std::min(val_array_sz, div_round_up(width, BV_BITS_IN_BYTE));
    memcpy(byte_arr, val_array, bytes_to_copy);

    // Set the actual width needed to store the value
    // Zero out the not-in-use bits of the last in-use element
    uint64_t clear_mask = bit_utils::get_clear_mask(m_width, BV_ELEMENT_SIZE_IN_BITS);
    size_t last_element = m_bits.size() - 1;
    m_bits[last_element] &= clear_mask;
}

template <class _Storage>
bit_vector_base<_Storage>::bit_vector_base(uint64_t*& data, size_t width)
    : m_bits(div_round_up(width, BV_ELEMENT_SIZE_IN_BITS), data), m_width(width)
{
    uint64_t clear_mask = bit_utils::get_clear_mask(m_width, BV_ELEMENT_SIZE_IN_BITS);
    size_t last_element = m_bits.size() - 1;
    m_bits[last_element] &= clear_mask;
}

template <class _Storage>
bit_vector_base<_Storage>::bit_vector_base(std::string value)
{
    unsigned int base = 16;
    size_t iters_per_elem = BV_ELEMENT_SIZE_IN_BITS / 4;
    size_t value_size = value.size();

    m_bits.resize((value_size + iters_per_elem - 1) / iters_per_elem);
    for (size_t i = 0; i < value_size; i += iters_per_elem) {
        uint64_t element = 0;

        size_t bytes_to_process = std::min(iters_per_elem, value_size - i);

        for (size_t j = 0; j < bytes_to_process; j++) {
            size_t byte_index = value_size - i - j - 1;
            char c[] = {value[byte_index], '\0'};
            char* dummy;

            uint64_t v = strtoul(c, &dummy, base);
            element |= (v << (4 * j));
        }

        m_bits[i / iters_per_elem] = element;
    }

    m_width = get_minimal_width();
}

template <class _Storage>
bit_vector_base<_Storage>::bit_vector_base(std::string value, size_t width)
{
    *this = bit_vector_base(value);
    if (width > m_width) {
        resize(width);
    }
}

template <class _Storage>
bit_vector_base<_Storage>::bit_vector_base(const bit_vector_base<_Storage>& other)
{
    *this = other;
}

template <class _Storage>
template <class _OtherStorage>
bit_vector_base<_Storage>::bit_vector_base(const bit_vector_base<_OtherStorage>& other)
{
    *this = other;
}

template <class _Storage>
bit_vector_base<_Storage>::bit_vector_base(bit_vector_base<_Storage>&& other) : m_bits(other.m_bits), m_width(other.m_width)
{
    other.m_width = 0;
}

template <class _Storage>
size_t
bit_vector_base<_Storage>::count_ones() const
{
    int count = 0;
    for (size_t elem = 0; elem < m_bits.size(); elem++) {
        uint64_t value = get_element(elem);
        count += __builtin_popcountll(value);
    }
    return count;
}

template <class _Storage>
bit_vector_base<_Storage>&
bit_vector_base<_Storage>::operator=(const bit_vector_base<_Storage>& other)
{
    m_bits.resize(other.m_bits.size());
    m_width = other.m_width;

    for (size_t i = 0; i < m_bits.size(); i++) {
        m_bits[i] = other.m_bits[i];
    }

    return *this;
}

template <class _Storage>
template <class _OtherStorage>
bit_vector_base<_Storage>&
bit_vector_base<_Storage>::operator=(const bit_vector_base<_OtherStorage>& other)
{
    m_bits.resize(other.m_bits.size());
    m_width = other.m_width;

    for (size_t i = 0; i < m_bits.size(); i++) {
        m_bits[i] = other.m_bits[i];
    }

    return *this;
}

template <class _Storage>
bit_vector_base<_Storage>&
bit_vector_base<_Storage>::operator=(bit_vector_base<_Storage>&& other)
{
    m_bits = std::move(other.m_bits);
    m_width = other.m_width;

    return *this;
}

template <class _Storage>
bool
bit_vector_base<_Storage>::is_null() const
{
    return (m_width == 0);
}

template <class _Storage>
bool
bit_vector_base<_Storage>::is_zero() const
{
    size_t bits_size = m_bits.size();
    for (size_t i = 0; i < bits_size; i++) {
        if (m_bits[i] != 0) {
            return false;
        }
    }

    return true;
}

template <class _Storage>
uint64_t
bit_vector_base<_Storage>::get_value() const
{
    return m_bits.size() == 0 ? 0 : m_bits[0];
}

template <class _Storage>
size_t
bit_vector_base<_Storage>::get_width() const
{
    return m_width;
}

template <class _Storage>
size_t
bit_vector_base<_Storage>::get_width_in_bytes() const
{
    return (get_width() + BV_BITS_IN_BYTE - 1) / BV_BITS_IN_BYTE;
}

template <class _Storage>
size_t
bit_vector_base<_Storage>::get_minimal_width() const
{
    size_t min_width = 0;
    size_t bits_size = m_bits.size();

    for (size_t i = 0; i < bits_size; i++) {
        uint64_t element = m_bits[i];
        if (element == 0) {
            continue;
        }

        size_t msb = bit_utils::get_msb(element);
        min_width = (i * BV_ELEMENT_SIZE_IN_BITS) + msb + 1;
    }

    return min_width;
}

template <class _Storage>
size_t
bit_vector_base<_Storage>::hash() const
{
    std::hash<size_t> h;
    size_t hash_value = 0;
    size_t bits_size = m_bits.size();
    for (size_t i = 0; i < bits_size; i++) {
        hash_value ^= h(m_bits[i]);
    }

    return hash_value;
}

template <class _Storage>
bit_vector_base<_Storage>
bit_vector_base<_Storage>::bits(size_t msb, size_t lsb) const
{
    if (lsb >= m_width || msb < lsb) {
        return bit_vector_base();
    }

    bit_vector_base bv;

    size_t new_width = msb - lsb + 1;
    size_t last_element = (new_width - 1) / BV_ELEMENT_SIZE_IN_BITS;
    bv.m_bits.resize(last_element + 1);

    size_t current_lsb = lsb;
    for (size_t i = 0; i < last_element; i++) {
        uint64_t element = get_unaligned_element(current_lsb);
        bv.m_bits[i] = element;
        current_lsb += BV_ELEMENT_SIZE_IN_BITS;
    }

    uint64_t element = get_unaligned_element(current_lsb);
    uint64_t mask = bit_utils::get_lsb_mask(msb - current_lsb + 1);
    bv.m_bits[last_element] = element & mask;

    bv.m_width = new_width;

    return bv;
}

template <class _Storage>
bit_vector_base<_Storage>
bit_vector_base<_Storage>::bits_from_msb(size_t offset, size_t width) const
{
    if (offset >= m_width) {
        return bit_vector_base();
    }

    size_t msb = m_width - offset - 1;
    size_t lsb = (width > msb) ? 0 : msb - width + 1;

    return bits(msb, lsb);
}

template <class _Storage>
bit_vector_base<_Storage>
bit_vector_base<_Storage>::bits_from_lsb(size_t offset, size_t width) const
{
    if (offset >= m_width) {
        return bit_vector_base();
    }

    size_t msb = (offset + width > m_width) ? (m_width - 1) : (offset + width - 1);
    size_t lsb = offset;

    return bits(msb, lsb);
}

template <class _Storage>
template <class _OtherStorage>
void
bit_vector_base<_Storage>::set_bits(size_t msb, size_t lsb, const bit_vector_base<_OtherStorage>& value)
{
    if (msb >= m_width) {
        resize((size_t)(msb + 1));
    }

    for (size_t current_lsb = lsb; current_lsb <= msb;
         current_lsb += (BV_ELEMENT_SIZE_IN_BITS - (current_lsb % BV_ELEMENT_SIZE_IN_BITS))) {
        size_t bits_to_update = std::min(msb - current_lsb + 1, (size_t)BV_ELEMENT_SIZE_IN_BITS);
        size_t value_current_lsb = current_lsb - lsb;
        uint64_t mask = bit_utils::get_lsb_mask(bits_to_update);
        uint64_t v = value.get_unaligned_element(value_current_lsb) & mask;

        size_t index = current_lsb / BV_ELEMENT_SIZE_IN_BITS;
        size_t element_low_bit = current_lsb % BV_ELEMENT_SIZE_IN_BITS;

        m_bits[index] &= ~(mask << element_low_bit);
        m_bits[index] |= (v << element_low_bit);
    }
}

template <class _Storage>
template <class _OtherStorage>
size_t
bit_vector_base<_Storage>::set_bits_from_msb(size_t offset, size_t width, const bit_vector_base<_OtherStorage>& value)
{
    if (offset >= m_width) {
        return 0;
    }

    size_t msb = m_width - offset - 1;
    size_t lsb = (width > msb) ? 0 : msb - width + 1;

    set_bits(msb, lsb, value);
    return msb - lsb + 1;
}

template <class _Storage>
template <class _OtherStorage>
size_t
bit_vector_base<_Storage>::set_bits_from_lsb(size_t offset, size_t width, const bit_vector_base<_OtherStorage>& value)
{
    if (offset >= m_width) {
        return 0;
    }

    size_t msb = (offset + width > m_width) ? (m_width - 1) : (offset + width - 1);
    size_t lsb = offset;

    set_bits(msb, lsb, value);
    return msb - lsb + 1;
}

template <class _Storage>
void
bit_vector_base<_Storage>::set_bits(size_t msb, size_t lsb, uint64_t value)
{
    set_bits(msb, lsb, bit_vector_base<_Storage>(value));
}

template <class _Storage>
size_t
bit_vector_base<_Storage>::set_bits_from_msb(size_t offset, size_t width, uint64_t value)
{
    return set_bits_from_msb(offset, width, bit_vector_base<_Storage>(value));
}

template <class _Storage>
size_t
bit_vector_base<_Storage>::set_bits_from_lsb(size_t offset, size_t width, uint64_t value)
{
    return set_bits_from_lsb(offset, width, bit_vector_base<_Storage>(value));
}

template <class _Storage>
void
bit_vector_base<_Storage>::resize(size_t new_width)
{
    if (new_width == m_width) {
        return;
    }

    // Update elements count and zero out the elements that are not in use
    size_t new_elements_count = (new_width + BV_ELEMENT_SIZE_IN_BITS - 1) / BV_ELEMENT_SIZE_IN_BITS;
    m_bits.resize(new_elements_count);

    // Zero out the not-in-use bits of the last in-use element
    uint64_t clear_mask = bit_utils::get_clear_mask(new_width, BV_ELEMENT_SIZE_IN_BITS);
    size_t last_element = new_elements_count - 1;
    m_bits[last_element] &= clear_mask;

    m_width = new_width;
}

template <class _Storage>
bool
bit_vector_base<_Storage>::bit(size_t pos) const
{
    if (pos >= m_width) {
        return false;
    }

    size_t element_index = pos / BV_ELEMENT_SIZE_IN_BITS;
    size_t bit_offset = pos % BV_ELEMENT_SIZE_IN_BITS;

    uint64_t element = get_element(element_index);
    uint64_t shifted_element = element >> bit_offset;

    return shifted_element & 0x1;
}

template <class _Storage>
bool
bit_vector_base<_Storage>::bit_from_msb(size_t offset) const
{
    if (offset >= m_width) {
        return false;
    }

    return bit(m_width - offset - 1);
}

template <class _Storage>
void
bit_vector_base<_Storage>::set_bit(size_t pos, bool val)
{
    return set_bits(pos, pos, val);
}

template <class _Storage>
void
bit_vector_base<_Storage>::negate()
{
    for (size_t i = 0; i < m_bits.size(); i++) {
        // Take 64 for middle elements and residue for the last element.
        size_t mask_bits = std::min((size_t)BV_ELEMENT_SIZE_IN_BITS, m_width - i * BV_ELEMENT_SIZE_IN_BITS);
        uint64_t mask = bit_utils::get_lsb_mask(mask_bits);

        m_bits[i] = m_bits[i] ^ mask;
    }
}

template <class _Storage>
bit_vector_base<_Storage> bit_vector_base<_Storage>::operator~() const
{
    bit_vector_base bv(*this);
    bv.negate();

    return bv;
}

template <class _Storage>
template <class _OtherStorage>
bit_vector_base<_Storage>
bit_vector_base<_Storage>::operator|(const bit_vector_base<_OtherStorage>& other) const
{
    bit_vector_base bv(*this);
    bv |= other;

    return bv;
}

template <class _Storage>
template <class _OtherStorage>
bit_vector_base<_Storage> bit_vector_base<_Storage>::operator&(const bit_vector_base<_OtherStorage>& other) const
{
    bit_vector_base bv(*this);
    bv &= other;

    return bv;
}

template <class _Storage>
template <class _OtherStorage>
bit_vector_base<_Storage>
bit_vector_base<_Storage>::operator^(const bit_vector_base<_OtherStorage>& other) const
{
    bit_vector_base bv(*this);
    bv ^= other;

    return bv;
}

template <class _Storage>
template <class _OtherStorage>
void
bit_vector_base<_Storage>::operator|=(const bit_vector_base<_OtherStorage>& other)
{
    size_t elements = std::max(m_bits.size(), other.m_bits.size());
    m_bits.resize(elements);

    for (size_t i = 0; i < elements; i++) {
        uint64_t lelem = get_element(i);
        uint64_t relem = other.get_element(i);
        m_bits[i] = lelem | relem;
    }

    m_width = std::max(m_width, other.m_width);
}

template <class _Storage>
template <class _OtherStorage>
void
bit_vector_base<_Storage>::operator&=(const bit_vector_base<_OtherStorage>& other)
{
    size_t elements = std::max(m_bits.size(), other.m_bits.size());
    m_bits.resize(elements);

    for (size_t i = 0; i < elements; i++) {
        uint64_t lelem = get_element(i);
        uint64_t relem = other.get_element(i);
        m_bits[i] = lelem & relem;
    }

    m_width = std::max(m_width, other.m_width);
}

template <class _Storage>
template <class _OtherStorage>
void
bit_vector_base<_Storage>::operator^=(const bit_vector_base<_OtherStorage>& other)
{
    size_t elements = std::max(m_bits.size(), other.m_bits.size());
    m_bits.resize(elements);

    for (size_t i = 0; i < elements; i++) {
        uint64_t lelem = get_element(i);
        uint64_t relem = other.get_element(i);
        m_bits[i] = lelem ^ relem;
    }

    m_width = std::max(m_width, other.m_width);
}

template <class _Storage>
template <class _OtherStorage>
void
bit_vector_base<_Storage>::xor_with_other_shifted_left(const bit_vector_base<_OtherStorage>& other, size_t left_shift)
{
    size_t elements = std::max(m_bits.size(), other.m_bits.size());
    m_bits.resize(elements);

    size_t left_element_shift = left_shift / BV_ELEMENT_SIZE_IN_BITS;
    size_t rem_left_shift = left_shift % BV_ELEMENT_SIZE_IN_BITS;
    size_t rem_right_shift = BV_ELEMENT_SIZE_IN_BITS - rem_left_shift;

    uint64_t prev = 0;
    uint64_t prev_mask = (uint64_t)-1;
    if (rem_left_shift == 0) {
        prev_mask = 0;
    }

    for (size_t i = 0; i < elements; i++) {
        uint64_t curr = other.get_element(i - left_element_shift);

        uint64_t relem = (curr << rem_left_shift | prev);
        m_bits[i] ^= relem;

        prev = prev_mask & (curr >> rem_right_shift);
    }

    m_width = std::max(m_width, other.m_width);
}

template <class _Storage>
bit_vector_base<_Storage>
bit_vector_base<_Storage>::operator<<(size_t shift) const
{
    if (shift == 0) {
        return *this;
    }

    bit_vector_base bv;

    size_t element_shift = shift % BV_ELEMENT_SIZE_IN_BITS;
    size_t low_zero_elements = shift / BV_ELEMENT_SIZE_IN_BITS;

    size_t bits_size = m_bits.size();
    bv.m_bits.resize(bits_size + low_zero_elements);

    uint64_t low_bits = 0;
    for (size_t i = 0; i < bits_size; i++) {
        uint64_t shifted_element = (m_bits[i] << element_shift) | low_bits;
        bv.m_bits[low_zero_elements + i] = shifted_element;

        // Right shift by 64 bits has undefined behavior, so make sure to zero out explicitly in this case.
        low_bits = 0;
        if (element_shift != 0) {
            low_bits = m_bits[i] >> (BV_ELEMENT_SIZE_IN_BITS - element_shift);
        }
    }

    if (low_bits != 0) {
        size_t bv_bits_size = bv.m_bits.size();
        bv.m_bits.resize(bv_bits_size + 1);
        bv.m_bits[bv_bits_size] = low_bits;
    }

    bv.m_width = m_width + shift;

    return bv;
}

template <class _Storage>
bit_vector_base<_Storage>
bit_vector_base<_Storage>::operator>>(size_t shift) const
{
    if (shift >= m_width) {
        return bit_vector_base();
    }

    return bits(m_width - 1, shift);
}

template <class _Storage>
template <class _OtherStorage>
bool
bit_vector_base<_Storage>::operator==(const bit_vector_base<_OtherStorage>& other) const
{
    if (m_width != other.m_width) {
        return false;
    }

    size_t bits_size = m_bits.size();
    for (size_t i = 0; i < bits_size; i++) {
        uint64_t lelem = get_element(i);
        uint64_t relem = other.get_element(i);
        if (lelem != relem) {
            return false;
        }
    }

    return true;
}

template <class _Storage>
template <class _OtherStorage>
bool
bit_vector_base<_Storage>::operator!=(const bit_vector_base<_OtherStorage>& other) const
{
    return !(*this == other);
}

template <class _Storage>
std::string
bit_vector_base<_Storage>::to_string() const
{
    if (m_bits.size() == 0) {
        return "0";
    }

    // size_t array_size = m_bits.size() * 8;
    size_t array_size = get_width_in_bytes();
    const uint8_t* bytearray = byte_array();

    // Each char is a nibble. Need 2 for each byte.
    std::string v(array_size * 2, '0');

    for (size_t i = 0; i < array_size; i++) {
        size_t index = array_size - 1 - i;
        char c[3]; // 2 nibbles + \0
        snprintf(c, 3, "%02x", bytearray[index]);
        v.replace(i * 2, 2, c);
    }

    return v;
}

template <class _Storage>
uint8_t*
bit_vector_base<_Storage>::byte_array()
{
    uint64_t* data_u64 = &(m_bits[0]);
    return (uint8_t*)data_u64;
}

template <class _Storage>
const uint8_t*
bit_vector_base<_Storage>::byte_array() const
{
    const uint64_t* data_u64 = &(m_bits[0]);
    return (const uint8_t*)data_u64;
}

template <class _Storage>
uint64_t
bit_vector_base<_Storage>::get_element(size_t index) const
{
    if (index >= m_bits.size()) {
        return 0;
    }

    return m_bits[index];
}

template <class _Storage>
uint64_t
bit_vector_base<_Storage>::get_unaligned_element(size_t lsb) const
{
    size_t low_element_index = lsb / BV_ELEMENT_SIZE_IN_BITS;
    size_t high_element_bits = lsb % BV_ELEMENT_SIZE_IN_BITS;
    uint64_t low_element = get_element(low_element_index);
    uint64_t element = (low_element >> high_element_bits);

    if (high_element_bits != 0) {
        size_t low_element_bits = BV_ELEMENT_SIZE_IN_BITS - high_element_bits;
        uint64_t high_element = get_element(low_element_index + 1);
        element |= (high_element << low_element_bits);
    }

    return element;
}

/// @brief Dynamic storage for bit vector base class
///
/// Holds dynamic storage and a size indicator, and implements basic interface.
/// Can also wrap an existing object without allocating memory.
class bit_vector_dynamic_storage
{
public:
    /// @brief Construct empty storage.
    bit_vector_dynamic_storage() : m_bits(nullptr), m_size(0), m_is_owner(true)
    {
    }

    /// @brief Destructor.
    ~bit_vector_dynamic_storage()
    {
        if (m_is_owner && m_bits != nullptr) {
            thread_allocator_manager::deallocate(m_bits, m_size * sizeof(uint64_t));
        }
    }

    /// @brief Construct new storage.
    bit_vector_dynamic_storage(size_t size, uint64_t value) : m_bits(nullptr), m_size(0), m_is_owner(true)
    {
        resize(size);
        for (size_t i = 0; i < m_size; i++) {
            m_bits[i] = value;
        }
    }

    /// @brief Construct new bit_vector_dynamic_storage wrapping an existing allocated memory.
    bit_vector_dynamic_storage(size_t size, uint64_t*& data) : m_bits(data), m_size(size), m_is_owner(false)
    {
    }

    bit_vector_dynamic_storage(const bit_vector_dynamic_storage& other) : m_bits(nullptr), m_size(0), m_is_owner(true)
    {
        resize(other.size());
        if (other.m_bits != nullptr) {
            memcpy(m_bits, other.m_bits, m_size * sizeof(uint64_t));
        }
    }

    bit_vector_dynamic_storage(bit_vector_dynamic_storage&& other)
        : m_bits(other.m_bits), m_size(other.m_size), m_is_owner(other.m_is_owner)
    {
        other.m_bits = nullptr;
        other.m_size = 0;
        other.m_is_owner = false;
    }

    bit_vector_dynamic_storage& operator=(const bit_vector_dynamic_storage& other)
    {

        if (m_is_owner && m_bits != nullptr) {
            thread_allocator_manager::deallocate(m_bits, m_size * sizeof(uint64_t));
            m_bits = nullptr;
        }
        m_size = 0;
        resize(other.size());
        if (other.size() != 0) {
            memcpy(m_bits, other.m_bits, m_size * sizeof(uint64_t));
        }
        return *this;
    }

    bit_vector_dynamic_storage& operator=(bit_vector_dynamic_storage&& other)
    {
        if (m_is_owner && m_bits != nullptr) {
            thread_allocator_manager::deallocate(m_bits, m_size * sizeof(uint64_t));
        }

        m_bits = other.m_bits;
        m_size = other.m_size;
        m_is_owner = other.m_is_owner;

        other.m_bits = nullptr;
        other.m_size = 0;
        other.m_is_owner = false;

        return *this;
    }

    /// @brief Get storage current size.
    ///
    /// @return Storage size.
    size_t size() const
    {
        return m_size;
    }

    /// @brief Get reference to an element of given index.
    ///
    /// @param[in]     index       Index of requested element.
    ///
    /// @return Reference to requested element.
    uint64_t& operator[](size_t index)
    {
        return *(m_bits + index);
    }

    /// @brief Get const reference to an element of given index.
    ///
    /// @param[in]     index       Index of requested element.
    ///
    /// @return Const reference to requested element.
    const uint64_t& operator[](size_t index) const
    {
        return *(m_bits + index);
    }

    /// @brief Resize storage to new size, set new elements to 0.
    ///
    /// @param[in]      new_size    New storage size.
    void resize(size_t new_size)
    {
        dassert_crit(m_is_owner);
        if (m_size == new_size) {
            return;
        }

        m_bits = static_cast<uint64_t*>(
            thread_allocator_manager::reallocate(m_bits, m_size * sizeof(uint64_t), new_size * sizeof(uint64_t)));

        if (m_size < new_size) {
            memset((m_bits + m_size), 0, (new_size - m_size) * sizeof(uint64_t));
        }
        m_size = new_size;
    }

    template <class Archive>
    void save(Archive& ar) const
    {
        dassert_crit(m_is_owner, "serializing bit_vector with no owned data is not supported!");
        ar(m_is_owner);
        ar(m_size);
        for (size_t i = 0; i < m_size; ++i) {
            ar(m_bits[i]);
        }
    }

    template <class Archive>
    void load(Archive& ar)
    {
        ar(m_is_owner);
        dassert_crit(m_is_owner, "serializing bit_vector with no owned data is not supported!");
        size_t loaded_size = 0;
        ar(loaded_size);
        resize(loaded_size);
        for (size_t i = 0; i < loaded_size; ++i) {
            ar(m_bits[i]);
        }
    }

private:
    uint64_t* m_bits; ///< Data.
    size_t m_size;    ///< Current storage size in bits.
    bool m_is_owner;  ///< Indicates whether the object is the memory allocation's owner.
};

/// @brief Static storage for bit vector base class
///
/// Holds static _Size length vector storage and a size indicator, and implements basic interface.
template <size_t _Size>
class bit_vector_static_storage
{
public:
    /// @brief Construct empty storage.
    bit_vector_static_storage() : m_size((uint8_t)0)
    {
    }

    /// @brief Construct storage with given size and value.
    bit_vector_static_storage(size_t size, uint64_t value) : m_size(size)
    {
        dassert_crit(m_size <= _Size);

        for (size_t i = 0; i < m_size; i++) {
            m_bits[i] = value;
        }

        for (size_t i = m_size; i < _Size; i++) {
            m_bits[i] = 0;
        }
    }

    /// @brief Get storage current size.
    ///
    /// @return Storage size.
    size_t size() const
    {
        return m_size;
    }

    /// @brief Get reference to an element of given index.
    ///
    /// @param[in]     index       Index of requested element.
    ///
    /// @return Reference to requested element.
    uint64_t& operator[](size_t index)
    {
        return m_bits[index];
    }

    /// @brief Get const reference to an element of given index.
    ///
    /// @param[in]     index       Index of requested element.
    ///
    /// @return Const reference to requested element.
    const uint64_t& operator[](size_t index) const
    {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
        return m_bits[index];
#pragma GCC diagnostic pop
    }

    /// @brief Resize storage to new size, set new elements to 0.
    ///
    /// @param[in]      new_size    New storage size.
    void resize(uint8_t new_size)
    {
        dassert_crit(new_size <= _Size);
        if (m_size == new_size) {
            return;
        }

        size_t start = std::min(m_size, new_size);
        size_t n = std::max(m_size, new_size) - start;

        memset(&m_bits[start], 0, n * sizeof(m_bits[0]));
        m_size = new_size;
    }

    template <class Archive>
    void serialize(Archive& ar)
    {
        ar(m_size);
        for (uint8_t i = 0; i < m_size; ++i) {
            ar(m_bits[i]);
        }
    }

private:
    uint64_t m_bits[_Size]; ///< Static _Size length vector.
    uint8_t m_size;         ///< Current storage size.
};

// Common uses of bit_vector_base class:
// bit_vector: Dynamic bit vector, uses std::vector<uint_64_t>
// bit_vectorX_t: Static bit vector, uses bit_vector_static_storage<X>
typedef bit_vector_base<bit_vector_dynamic_storage> bit_vector;
typedef bit_vector_base<bit_vector_static_storage<1> > bit_vector64_t;
typedef bit_vector_base<bit_vector_static_storage<2> > bit_vector128_t;
typedef bit_vector_base<bit_vector_static_storage<3> > bit_vector192_t;
typedef bit_vector_base<bit_vector_static_storage<5> > bit_vector320_t;
typedef bit_vector_base<bit_vector_static_storage<6> > bit_vector384_t;
typedef bit_vector_base<bit_vector_static_storage<8> > bit_vector512_t;

} // namespace silicon_one

#ifndef SWIG
// Implementing this hash overload allows using bit_vector in unordered_set and unordered_map.
namespace std
{
template <class _Storage>
struct hash<silicon_one::bit_vector_base<_Storage> > {
    size_t operator()(const silicon_one::bit_vector_base<_Storage>& bv) const
    {
        return bv.hash();
    }
};
}
#endif

#endif

#if __GNUC__ == 7 && __GNUC_MINOR__ == 5
#pragma GCC diagnostic pop
#endif
