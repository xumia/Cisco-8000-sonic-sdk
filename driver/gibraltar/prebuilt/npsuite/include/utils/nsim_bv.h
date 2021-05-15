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

#ifndef __NSIM_BV_H__
#define __NSIM_BV_H__

#include <stdint.h>
#include <string>
#include <vector>

namespace nsim
{

class bit_vector
{
public:
    bit_vector();
    bit_vector(uint64_t value);
    bit_vector(uint64_t value, size_t width_in_bits);
    bit_vector(std::string value);
    bit_vector(std::string value, size_t width_in_bits);

    // val_array_sz    The size in bytes of val_array.
    // val_array       Initial value array in big-endian order.
    // width           Width to set.
    bit_vector(size_t val_array_sz, const uint8_t* val_array, size_t width);

    bool is_zero() const
    {
        for (size_t i = 0; i < m_bits.size(); i++) {
            if (m_bits[i] != 0) {
                return false;
            }
        }

        return true;
    }

    bool is_true() const
    {
        return !is_zero();
    }

    uint64_t get_value() const
    {
        return m_bits.empty() ? 0 : m_bits[0];
    }

    void set_value(uint64_t value)
    {
        if (m_bits.empty()) {
            resize(64, value);
        } else {
            m_bits[0] = value;
        }
    }

    bool bit(size_t pos) const;
    void reset();
    size_t get_width() const
    {
        return m_width;
    }
    size_t get_minimal_width() const;
    size_t get_width_in_bytes() const
    {
        return (get_width() + 7) / 8;
    }

    bit_vector bits(size_t msb, size_t lsb) const;
    bit_vector bits_from_msb(size_t offset, size_t width) const;
    bool bits(size_t msb, size_t lsb, bit_vector& out_value) const;
    bool bits_from_msb(size_t offset, size_t width, bit_vector& out_value) const;
    uint64_t bits_as_uint64_t(size_t msb, size_t lsb) const;
    uint64_t bits_from_msb_as_uint64_t(size_t offset, size_t width) const;
    void set_bit(size_t pos, bool val);

    void set_bits(size_t msb, size_t lsb, const bit_vector& value);
    void set_bits(
        size_t msb,
        size_t lsb,
        uint64_t value); // created in order to support SDK bv API, using this method too often may result in performance loss
    void set_bits_from_msb(size_t offset, size_t width, const bit_vector& value);
    void set_bits_from_msb(size_t offset, size_t width, uint64_t value);
    void set_bits_from_uint64_t(size_t msb, size_t lsb, uint64_t value);
    void set_bits_from_uint64_t(uint64_t value);
    void set_bits_from_msb_from_uint64_t(size_t offset, size_t width, uint64_t value);

    bit_vector operator~() const;
    bit_vector operator|(const bit_vector& other) const;
    bit_vector operator&(const bit_vector& other) const;
    bit_vector operator^(const bit_vector& other) const;
    bit_vector operator<<(size_t shift) const;
    bit_vector operator+(const bit_vector& other) const;
    bit_vector operator*(const bit_vector& other) const;

    bit_vector& operator|=(const bit_vector& other);
    bit_vector& operator&=(const bit_vector& other);
    bit_vector& operator^=(const bit_vector& other);
    bit_vector& operator<<=(size_t shift);
    bit_vector& operator+=(const bit_vector& other);

    bool operator==(const bit_vector& other) const;
    bool operator==(uint64_t other) const;
    bool operator!=(const bit_vector& other) const;

    bool operator<(const bit_vector& other) const;
    bool operator<=(const bit_vector& other) const;
    bool operator>(const bit_vector& other) const;
    bool operator>=(const bit_vector& other) const;

    //
    // Convert the bit vector to a hex string, rounded to an even number of bytes with "0" padding as needed. Also prepend "0x" to
    // the head of the string.
    //
    std::string to_string() const;

    //
    // Convert the bit vector to a hex string but do not round to an even number of bytes. Also prepend "0x" to the head of the
    // string.
    //
    std::string to_string_without_leading_0() const;

    //
    // Convert the bit vector to a hex string, rounded to an even number of bytes with "0" padding as needed. Do not prepend "0x" to
    // the head of the string.
    //
    std::string to_string_without_leading_0x() const;

    void clear(void); // maintain capacity and resize to 0
    void resize(size_t new_width);
    void resize(size_t new_width, uint64_t val);
    void resize(const uint8_t* val_array, size_t width);

    uint8_t* byte_array();
    const uint8_t* byte_array() const;

    static bit_vector ones(size_t width);

    void add_fixed_width(const bit_vector& first, const bit_vector& second);
    void sub_fixed_width(const bit_vector& first, const bit_vector& second);
    void and_or_mask(const bit_vector& and_value, const bit_vector& or_value);

    void get(std::vector<uint64_t>& bits, uint32_t& width) const
    {
        bits = m_bits;
        width = static_cast<uint32_t>(m_width);
    }

    void set(const std::vector<uint64_t>& bits, const uint32_t& width)
    {
        m_bits = bits;
        m_width = static_cast<size_t>(width);
    }

private:
    enum { BV_ELEMENT_SIZE_IN_BITS = 64, BV_BITS_PER_BYTE = 8 };

    //
    // Convert the bit vector to a hex string, with optional padding and "0x" prefix.
    //
    std::string to_string(size_t length, bool include_leading_0x = true) const;

    uint64_t get_element(size_t index) const
    {
        if (index < m_bits.size()) {
            return m_bits[index];
        } else {
            return 0;
        }
    }
    uint64_t get_unaligned_element(size_t lsb) const;
    uint64_t get_unaligned_element_unsafe(size_t lsb) const;

    int get_msb(uint64_t value) const;

    uint64_t get_lsb_mask(size_t bits) const
    {
        uint64_t mask = (uint64_t)-1;
        return mask >> (64 - bits);
    }

    size_t num_of_array_elements(size_t width_in_bits);

    std::vector<uint64_t> m_bits;
    size_t m_width;
};
typedef bit_vector bit_vector64_t;
typedef bit_vector bit_vector128_t;
typedef bit_vector bit_vector192_t;
typedef bit_vector bit_vector384_t;
}

using nsim::bit_vector;

#endif
