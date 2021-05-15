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

#include "utils/nsim_bv.h"

#include <algorithm>
#include <assert.h>
#include <bitset>
#include <string.h>
#include <stdexcept>

#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

using namespace std;

bit_vector::bit_vector() : m_width(0)
{
}

bit_vector::bit_vector(uint64_t value)
{
    m_bits.push_back(value);
    m_width = get_minimal_width();
}

bit_vector::bit_vector(uint64_t value, size_t width)
{
    m_bits.reserve(num_of_array_elements(width));
    m_bits.push_back(value);
    m_width = get_minimal_width();

    if (width > m_width) {
        resize(width);
    }
}

bit_vector::bit_vector(std::string value) : bit_vector(value, 0) // width will be set to minimal width
{
}

bit_vector::bit_vector(std::string value, size_t width)
{
    unsigned int base = 16;
    size_t iters_per_elem = BV_ELEMENT_SIZE_IN_BITS / 4;
    size_t array_items = max(num_of_array_elements(width), num_of_array_elements(value.size() * 4));
    m_bits.reserve(array_items);

    for (size_t i = 0; i < value.size(); i += iters_per_elem) {
        uint64_t element = 0;

        size_t bytes_to_process = min(iters_per_elem, value.size() - i);

        for (size_t j = 0; j < bytes_to_process; j++) {
            size_t byte_index = value.size() - i - j - 1;
            char c[] = {value[byte_index], '\0'};
            char* dummy;

            uint64_t v = strtoul(c, &dummy, base);
            element |= (v << (4 * j));
        }

        m_bits.push_back(element);
    }

    m_width = get_minimal_width();

    if (width > m_width) {
        resize(width);
    }
}

bit_vector::bit_vector(size_t val_array_sz, const uint8_t* val_array, size_t width) : m_width(0)
{
    // Reserve enough space to copy the whole value
    size_t num_of_bits_in_val_array = val_array_sz * 8;
    resize(num_of_bits_in_val_array);

    uint8_t* byte_arr = byte_array();
    memcpy(byte_arr, val_array, val_array_sz);

    // Set the actual width needed to store the value
    m_width = get_minimal_width();
    if (width > m_width) {
        resize(width);
    }
}

void
bit_vector::resize(const uint8_t* val_array, size_t width)
{
    resize(width);
    uint8_t* byte_arr = byte_array();
    memcpy(byte_arr, val_array, m_bits.size() * sizeof(uint64_t));
    // Set the actual width needed to store the value
    resize(width); // calling again for zeroing the reminder of buffer
}

size_t
bit_vector::get_minimal_width() const
{
    size_t min_width = 0;

    for (size_t i = 0; i < m_bits.size(); i++) {
        size_t elem_idx = m_bits.size() - 1 - i;
        if (m_bits[elem_idx] == 0) {
            continue;
        }

        min_width = (elem_idx * BV_ELEMENT_SIZE_IN_BITS) + get_msb(m_bits[elem_idx]) + 1;
        break;
    }

    return min_width;
}

bool
bit_vector::bit(size_t pos) const
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

bit_vector
bit_vector::bits(size_t msb, size_t lsb) const
{
    bit_vector bv(*this);
    bits(msb, lsb, bv);
    return bv;
}

bit_vector
bit_vector::bits_from_msb(size_t offset, size_t width) const
{
    bit_vector bv(*this);
    bits_from_msb(offset, width, bv);
    return bv;
}

bool
bit_vector::bits(size_t msb, size_t lsb, bit_vector& out_value) const
{
    if (lsb >= get_width()) {
        return false;
    }

    size_t new_width = 1 + msb - lsb;
    if (out_value.get_width() < new_width) {
        out_value.resize(new_width);
    }

    for (size_t current_lsb = lsb, index = 0; current_lsb <= msb; current_lsb += BV_ELEMENT_SIZE_IN_BITS) {
        uint64_t element = get_unaligned_element(current_lsb);

        size_t bits_to_keep = min(msb - current_lsb + 1, (size_t)BV_ELEMENT_SIZE_IN_BITS);
        uint64_t mask = get_lsb_mask(bits_to_keep);
        element &= mask;

        out_value.m_bits[index] = element;
        index++;
    }

    out_value.resize(new_width);

    return true;
}

uint64_t
bit_vector::bits_as_uint64_t(size_t msb, size_t lsb) const
{
    if (lsb >= get_width()) {
        return 0;
    }

    uint64_t result = get_unaligned_element(lsb);

    size_t bits_to_keep = msb - lsb + 1;
    if (bits_to_keep < BV_ELEMENT_SIZE_IN_BITS) {
        uint64_t mask = get_lsb_mask(bits_to_keep);
        result &= mask;
    }
    return result;
}

void
bit_vector::set_bit(size_t pos, bool val)
{
    if (pos >= m_width) {
        resize(pos + 1);
    }

    size_t index = pos / BV_ELEMENT_SIZE_IN_BITS;
    size_t bit_offset = pos % BV_ELEMENT_SIZE_IN_BITS;

    uint64_t mask = 1ULL << bit_offset;
    m_bits[index] &= ~mask;

    m_bits[index] |= ((uint64_t)val << bit_offset);
}

void
bit_vector::set_bits(size_t msb, size_t lsb, const bit_vector& value)
{
    if (msb >= m_width) {
        resize(msb + 1);
    }

    for (size_t current_lsb = lsb; current_lsb <= msb;
         current_lsb += (BV_ELEMENT_SIZE_IN_BITS - (current_lsb % BV_ELEMENT_SIZE_IN_BITS))) {
        size_t bits_to_update = min(msb - current_lsb + 1, (size_t)BV_ELEMENT_SIZE_IN_BITS);
        uint64_t v = value.bits_as_uint64_t(current_lsb + bits_to_update - 1 - lsb, current_lsb - lsb);

        size_t index = current_lsb / BV_ELEMENT_SIZE_IN_BITS;
        size_t element_low_bit = current_lsb % BV_ELEMENT_SIZE_IN_BITS;

        uint64_t mask = get_lsb_mask(bits_to_update) << element_low_bit;

        m_bits[index] &= ~mask;
        m_bits[index] |= (v << element_low_bit);
    }
}

void
bit_vector::set_bits_from_msb(size_t offset, size_t width, const bit_vector& value)
{
    if (offset >= m_width) {
        throw std::out_of_range("Got offset larger than bit_vector width (offset: " + std::to_string(offset)
                                + ", bit_vector width: "
                                + std::to_string(m_width)
                                + ")");
    }
    if (offset >= m_width || width == 0) {
        return;
    }

    size_t msb = m_width - offset - 1;
    if (msb < width - 1) {
        throw std::out_of_range("Got offset + width is larger than bit_vector width (offset: " + std::to_string(offset)
                                + ", width: "
                                + std::to_string(width)
                                + ", bit_vector width: "
                                + std::to_string(m_width)
                                + ")");
    }
    size_t lsb = msb - width + 1;

    set_bits(msb, lsb, value);
}

void
bit_vector::set_bits_from_msb(size_t offset, size_t width, uint64_t value)
{
    return set_bits_from_msb(offset, width, bit_vector(value));
}

void
bit_vector::set_bits(size_t msb, size_t lsb, uint64_t value)
{
    set_bits(msb, lsb, bit_vector(value));
}

void
bit_vector::set_bits_from_uint64_t(size_t msb, size_t lsb, uint64_t value)
{
    if (msb > lsb + 64 - 1) {
        throw std::out_of_range("Trying to set more than 64 bits using integer (msb: " + std::to_string(msb) + ", lsb: "
                                + std::to_string(lsb)
                                + ", width: "
                                + std::to_string(msb - lsb + 1)
                                + ")");
    }

    if (msb >= m_width) {
        resize(msb + 1);
    }

    for (size_t current_lsb = lsb; current_lsb <= msb;
         current_lsb += (BV_ELEMENT_SIZE_IN_BITS - (current_lsb % BV_ELEMENT_SIZE_IN_BITS))) {
        size_t bits_to_update = min(msb - current_lsb + 1, (size_t)BV_ELEMENT_SIZE_IN_BITS);

        uint64_t v = value >> (current_lsb - lsb);
        uint64_t mask = get_lsb_mask(bits_to_update);
        v &= mask;

        size_t index = current_lsb / BV_ELEMENT_SIZE_IN_BITS;
        size_t element_low_bit = current_lsb % BV_ELEMENT_SIZE_IN_BITS;

        mask <<= element_low_bit;

        m_bits[index] &= ~mask;
        m_bits[index] |= (v << element_low_bit);
    }
}

void
bit_vector::set_bits_from_uint64_t(uint64_t value)
{
    set_bits_from_uint64_t(63, 0, value);
}

void
bit_vector::set_bits_from_msb_from_uint64_t(size_t offset, size_t width, uint64_t value)
{
    if (offset >= m_width) {
        throw std::out_of_range("Got offset larger than bit_vector width (offset: " + std::to_string(offset)
                                + ", bit_vector width: "
                                + std::to_string(m_width)
                                + ")");
    }
    if (offset >= m_width || width == 0) {
        return;
    }

    size_t msb = m_width - offset - 1;
    if (msb < width - 1) {
        throw std::out_of_range("Got offset + width larger than bit_vector width (offset: " + std::to_string(offset) + ", width: "
                                + std::to_string(width)
                                + ", bit_vector width: "
                                + std::to_string(m_width)
                                + ")");
    }
    size_t lsb = msb - width + 1;

    set_bits_from_uint64_t(msb, lsb, value);
}

bool
bit_vector::bits_from_msb(size_t offset, size_t width, bit_vector& out_value) const
{
    if (offset >= m_width) {
        throw std::out_of_range("Got offset larger than bit_vector width (offset: " + std::to_string(offset)
                                + ", bit_vector width: "
                                + std::to_string(m_width)
                                + ")");
    }
    if (offset >= m_width || width == 0) {
        return false;
    }

    size_t msb = m_width - offset - 1;
    if (msb < width - 1) {
        throw std::out_of_range("Got offset + width larger than bit_vector width (offset: " + std::to_string(offset) + ", width: "
                                + std::to_string(width)
                                + ", bit_vector width: "
                                + std::to_string(m_width)
                                + ")");
    }
    size_t lsb = msb - width + 1;

    return bits(msb, lsb, out_value);
}

uint64_t
bit_vector::bits_from_msb_as_uint64_t(size_t offset, size_t width) const
{
    if (offset >= m_width) {
        throw std::out_of_range("Got offset larger than bit_vector width (offset: " + std::to_string(offset)
                                + ", bit_vector width: "
                                + std::to_string(m_width)
                                + ")");
    }

    if (offset >= m_width || width == 0) {
        return -1;
    }

    size_t msb = m_width - offset - 1;
    if (msb < width - 1) {
        throw std::out_of_range("Got offset + width larger than bit_vector width (offset: " + std::to_string(offset) + ", width: "
                                + std::to_string(width)
                                + ", bit_vector width: "
                                + std::to_string(m_width)
                                + ")");
    }
    size_t lsb = msb - width + 1;

    return bits_as_uint64_t(msb, lsb);
}

bit_vector bit_vector::operator~() const
{
    bit_vector bv(0, m_width);

    size_t elements = (m_width + BV_ELEMENT_SIZE_IN_BITS - 1) / BV_ELEMENT_SIZE_IN_BITS;
    for (size_t i = 0; i < elements; i++) {
        uint64_t elem = get_element(i);
        bv.m_bits[i] = ~elem;
    }

    // calling resize() again for removing leading '1's
    bv.resize(m_width);

    return bv;
}

bit_vector
bit_vector::operator|(const bit_vector& other) const
{
    bit_vector bv(*this);
    bv |= other;
    return bv;
}

bit_vector bit_vector::operator&(const bit_vector& other) const
{
    bit_vector bv(*this);
    bv &= other;
    return bv;
}

bit_vector
bit_vector::operator^(const bit_vector& other) const
{
    bit_vector bv(*this);
    bv ^= other;
    return bv;
}

bit_vector
bit_vector::operator<<(size_t shift) const
{
    bit_vector bv(*this);
    bv <<= shift;
    return bv;
}

bit_vector
bit_vector::operator+(const bit_vector& other) const
{
    bit_vector bv(*this);
    bv += other;
    return bv;
}

bit_vector bit_vector::operator*(const bit_vector& other) const
{
    bit_vector bv;

    for (size_t i = 0; i < m_width; i++) {
        if (bit(i)) {
            bv += (other << i);
        }
    }

    return bv;
}
bit_vector&
bit_vector::operator|=(const bit_vector& other)
{
    resize(max(m_width, other.m_width));

    size_t elements = m_bits.size();
    for (size_t i = 0; i < elements; i++) {
        m_bits[i] |= other.get_element(i);
    }

    return *this;
}

bit_vector&
bit_vector::operator&=(const bit_vector& other)
{
    resize(min(m_width, other.m_width));

    size_t elements = m_bits.size();
    for (size_t i = 0; i < elements; i++) {
        m_bits[i] &= other.get_element(i);
    }

    return *this;
}

bit_vector&
bit_vector::operator^=(const bit_vector& other)
{
    resize(max(m_width, other.m_width));

    size_t elements = m_bits.size();
    for (size_t i = 0; i < elements; i++) {
        m_bits[i] ^= other.get_element(i);
    }

    return *this;
}

bit_vector&
bit_vector::operator<<=(size_t shift)
{
    if (shift == 0) {
        return *this;
    }

    resize(m_width + shift);

    int element_index = static_cast<int>(m_bits.size() - 1);

    for (int src_lsb = (int)((m_bits.size() - 1) * BV_ELEMENT_SIZE_IN_BITS) - (int)shift; src_lsb > 0;
         src_lsb -= BV_ELEMENT_SIZE_IN_BITS, element_index--) {
        m_bits[element_index] = get_unaligned_element_unsafe(src_lsb);
    }

    m_bits[element_index] = m_bits[0] << (shift % BV_ELEMENT_SIZE_IN_BITS);
    element_index--;

    for (; element_index >= 0; element_index--) {
        m_bits[element_index] = 0;
    }

    return *this;
}

bit_vector&
bit_vector::operator+=(const bit_vector& other)
{
    resize(max(m_width, other.m_width));

    uint64_t carry = 0;
    size_t elements = m_bits.size();
    for (size_t i = 0; i < elements; i++) {
        uint64_t lelem = get_element(i);
        uint64_t relem = other.get_element(i);
        uint64_t sum = lelem + relem + carry;
        m_bits[i] = sum;
        carry = (lelem > 0 && relem > 0 && sum <= lelem && sum <= relem) ? 1 : 0;
    }
    if (carry != 0) {
        m_bits.push_back(carry);
    }

    m_width = max(m_width, get_minimal_width());

    return *this;
}

void
bit_vector::add_fixed_width(const bit_vector& first, const bit_vector& second)
{
    uint64_t carry = 0;
    size_t elements = m_bits.size();
    for (size_t i = 0; i < elements; i++) {
        uint64_t lelem = first.get_element(i);
        uint64_t relem = second.get_element(i);
        uint64_t sum = lelem + relem + carry;
        m_bits[i] = sum;
        carry = (lelem > 0 && relem > 0 && sum <= lelem && sum <= relem) ? 1 : 0;
    }

    size_t remainder = m_width % BV_ELEMENT_SIZE_IN_BITS;
    if (remainder != 0) {
        m_bits.back() &= ((1ULL << remainder) - 1ULL);
    }
}

void
bit_vector::sub_fixed_width(const bit_vector& first, const bit_vector& second)
{
    if (m_width > BV_ELEMENT_SIZE_IN_BITS) {
        throw std::out_of_range("Currently up to 64 bits are supported in subtruct operation ( width = " + std::to_string(m_width)
                                + ")");
    }

    uint64_t value_as_uint64_t = first.get_value() - second.get_value();
    set_value(value_as_uint64_t);

    size_t remainder = m_width % BV_ELEMENT_SIZE_IN_BITS;
    if (remainder != 0) {
        m_bits[0] &= ((1ULL << remainder) - 1ULL);
    }
}

bool
bit_vector::operator==(const bit_vector& other) const
{
    size_t elements = max(m_bits.size(), other.m_bits.size());
    for (size_t i = 0; i < elements; i++) {
        uint64_t lelem = get_element(i);
        uint64_t relem = other.get_element(i);
        if (lelem != relem) {
            return false;
        }
    }

    return true;
}

void
bit_vector::and_or_mask(const bit_vector& and_value, const bit_vector& or_value)
{
    size_t elements = m_bits.size();
    for (size_t i = 0; i < elements; i++) {
        m_bits[i] &= and_value.get_element(i);
        m_bits[i] |= or_value.get_element(i);
    }
}

bool
bit_vector::operator==(uint64_t other) const
{
    if (m_bits.size() > 1) {
        throw std::out_of_range(
            "Comparing bit_vector to uint64_t can be done only for bit_vectors with width <= 64 (bit_vector width: "
            + std::to_string(m_width)
            + ")");
    }
    return get_element(0) == other;
}

bool
bit_vector::operator!=(const bit_vector& other) const
{
    return !(*this == other);
}

bool
bit_vector::operator<(const bit_vector& other) const
{
    size_t elements = max(m_bits.size(), other.m_bits.size());
    for (size_t i = elements; i > 0; i--) {
        uint64_t lelem = get_element(i - 1);
        uint64_t relem = other.get_element(i - 1);

        if (lelem != relem) {
            return lelem < relem;
        }
    }

    return false;
}

bool
bit_vector::operator<=(const bit_vector& other) const
{
    size_t elements = max(m_bits.size(), other.m_bits.size());
    for (size_t i = elements; i > 0; i--) {
        uint64_t lelem = get_element(i - 1);
        uint64_t relem = other.get_element(i - 1);

        if (lelem != relem) {
            return lelem < relem;
        }
    }

    return true;
}

bool
bit_vector::operator>(const bit_vector& other) const
{
    return other < *this;
}

bool
bit_vector::operator>=(const bit_vector& other) const
{
    return other <= *this;
}

//
// Convert the bit vector to a hex string, rounded to an even number of bytes with "0" padding as needed. Also prepend "0x" to the
// head of the string.
//
string
bit_vector::to_string() const
{
    return to_string(m_width);
}

//
// Convert the bit vector to a hex string but do not round to an even number of bytes. Also prepend "0x" to the head of the string.
//
std::string
bit_vector::to_string_without_leading_0() const
{
    return to_string(get_minimal_width());
}

//
// Convert the bit vector to a hex string, rounded to an even number of bytes with "0" padding as needed. Do not prepend "0x" to the
// head of the string.
//
std::string
bit_vector::to_string_without_leading_0x() const
{
    return to_string(m_width, false /* include_leading_0x */);
}

bit_vector
bit_vector::ones(size_t width)
{
    bit_vector result;
    result.resize(width, UINT64_MAX);
    return result;
}

std::string
bit_vector::to_string(size_t length, bool include_leading_0x) const
{
    if (length == 0) {
        if (include_leading_0x) {
            return "0x0";
        } else {
            return "";
        }
    }

    string v("");
    if (m_bits.size() == 0) {
        v = "0";
    } else {
        for (size_t i = 0; i < m_bits.size(); i++) {
            size_t index = m_bits.size() - 1 - i;
            char c[32];
            snprintf(c, 32, "%016" PRIx64, m_bits[index]);
            v += c;
        }
    }

    size_t num_of_chars = (length + 3) / 4;

    if (num_of_chars < v.size()) {
        size_t spare_chars = v.size() - num_of_chars;
        v = v.substr(spare_chars);
    } else if (num_of_chars > v.size()) {
        try {
            v.append(num_of_chars - v.size(), '0');
        } catch (std::bad_alloc& e) {
            return e.what() + std::string(" exception in bit_vector::to_string() with length ") + std::to_string(length);
        }
    }

    if (include_leading_0x) {
        v = string("0x") + v;
        return v;
    }
    return v;
}

uint8_t*
bit_vector::byte_array()
{
    uint64_t* data_u64 = &(m_bits[0]);
    return (uint8_t*)data_u64;
}

const uint8_t*
bit_vector::byte_array() const
{
    const uint64_t* data_u64 = &(m_bits[0]);
    return (const uint8_t*)data_u64;
}

uint64_t
bit_vector::get_unaligned_element(size_t lsb) const
{
    size_t low_element_index = (size_t)lsb / BV_ELEMENT_SIZE_IN_BITS;
    uint64_t low_element = get_element(low_element_index);
    size_t high_element_bits = lsb % BV_ELEMENT_SIZE_IN_BITS;
    if (high_element_bits == 0) {
        return low_element;
    }

    uint64_t high_element = get_element(low_element_index + 1);
    size_t low_element_bits = BV_ELEMENT_SIZE_IN_BITS - high_element_bits;
    uint64_t element = (low_element >> high_element_bits) | (high_element << low_element_bits);

    return element;
}

uint64_t
bit_vector::get_unaligned_element_unsafe(size_t lsb) const
{
    assert(lsb + BV_ELEMENT_SIZE_IN_BITS <= m_bits.size() * BV_ELEMENT_SIZE_IN_BITS);
    return get_unaligned_element(lsb);
}

int
bit_vector::get_msb(uint64_t value) const
{
    int msb = BV_ELEMENT_SIZE_IN_BITS - 1;
    uint64_t mask = 1ULL << msb;

    while (mask > 0) {
        if (value & mask) {
            return msb;
        }

        msb--;
        mask >>= 1;
    }

    return -1;
}

void
bit_vector::resize(size_t new_width)
{
    resize(new_width, 0);
}

void
bit_vector::resize(size_t new_width, uint64_t val)
{
    size_t new_elements_size = num_of_array_elements(new_width);

    m_bits.resize(new_elements_size, val);

    size_t remainder = new_width % BV_ELEMENT_SIZE_IN_BITS;
    if (remainder != 0) {
        m_bits.back() &= ((1ULL << remainder) - 1ULL);
    }

    m_width = new_width;
}

size_t
bit_vector::num_of_array_elements(size_t width_in_bits)
{
    return (width_in_bits + BV_ELEMENT_SIZE_IN_BITS - 1) / BV_ELEMENT_SIZE_IN_BITS;
}

void
bit_vector::reset()
{
    memset(&(m_bits[0]), 0, sizeof(uint64_t) * m_bits.size());
}

void bit_vector::clear(void) // maintain capacity and resize to 0
{
    m_bits.clear();
    m_width = 0;
}
