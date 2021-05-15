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

#include "hw_tables/em_hasher.h"

using namespace std;

namespace silicon_one
{

em_hasher::em_hasher(size_t key_width, const em::hasher_params& hasher_params)
    : m_key_width(key_width),
      m_rc5_parameter_parts(NUMBER_OF_RC5_PARTS, em::hash_bv_t(0, key_width / 2)),
      m_long_crc_div_flipped(flip_bv(hasher_params.long_crc_div)),
      m_long_crc_init(hasher_params.long_crc_init),
      m_short_crc_div_flipped(flip_bv(hasher_params.short_crc_div)),
      m_short_crc_init(hasher_params.short_crc_init),
      m_fast_long_crc_init(calc_fast_crc_init(flip_bv(hasher_params.long_crc_div), hasher_params.long_crc_init, key_width)),
      m_fast_short_crc_init(calc_fast_crc_init(flip_bv(hasher_params.short_crc_div), hasher_params.short_crc_init, key_width / 2))
{
    size_t rc5_part_width = key_width / 2;
    const auto& rc5_parameter(hasher_params.rc5_parameter);
    for (size_t part_index = 0; part_index < NUMBER_OF_RC5_PARTS; part_index++) {
        size_t lsb = part_index * rc5_part_width;
        const auto& rc5_part(rc5_parameter.bits(lsb + rc5_part_width - 1, lsb));

        m_rc5_parameter_parts[part_index].set_bits(rc5_part_width - 1, 0, rc5_part);
    }

    em::hash_bv_t fast_long_crc_div(calc_fast_crc_div(flip_bv(hasher_params.long_crc_div), key_width));
    for (size_t div_offset = 0; div_offset < key_width + 1; div_offset++) {
        if (fast_long_crc_div.bit(div_offset)) {
            m_fast_long_crc_div_indices.push_back(div_offset);
        }
    }

    em::hash_bv_t fast_short_crc_div(calc_fast_crc_div(flip_bv(hasher_params.short_crc_div), key_width / 2));
    for (size_t div_offset = 0; div_offset < key_width / 2 + 1; div_offset++) {
        if (fast_short_crc_div.bit(div_offset)) {
            m_fast_short_crc_div_indices.push_back(div_offset);
        }
    }
}

em::key_t
em_hasher::encrypt(const em::key_t& key_to_encrypt) const
{
    // RC5 single round, with CRC modifications

    size_t half_key_width = m_key_width / 2;
    em::hash_bv_t a(0, half_key_width);
    em::hash_bv_t b(0, half_key_width);

    a.set_bits(half_key_width - 1, 0, key_to_encrypt);
    b.set_bits(half_key_width - 1, 0, key_to_encrypt.bits(m_key_width - 1, half_key_width));

    a = add_bvs(a, m_rc5_parameter_parts[0]);
    b = add_bvs(b, m_rc5_parameter_parts[1]);

    size_t a_rot_value = calc_short_crc(b);
    a ^= b;
    a = rotl_bv(a, a_rot_value);
    a = add_bvs(a, m_rc5_parameter_parts[2]);

    size_t b_rot_value = calc_short_crc(a);
    b ^= a;
    b = rotl_bv(b, b_rot_value);
    b = add_bvs(b, m_rc5_parameter_parts[3]);

    em::hash_bv_t reconstructed_key = ((b << half_key_width) | a);
    reconstructed_key = calc_equal_width_crc(reconstructed_key);

    em::key_t result(0, m_key_width);
    result.set_bits(m_key_width - 1, 0, reconstructed_key);

    return result;
}

em::key_t
em_hasher::decrypt(const em::key_t& key_to_decrypt) const
{
    // Exact reversing of encryption

    em::hash_bv_t key_to_process(0, m_key_width);
    key_to_process.set_bits(m_key_width - 1, 0, key_to_decrypt);

    key_to_process = calc_reverse_equal_width_crc(key_to_process);

    size_t half_key_width = m_key_width / 2;
    em::hash_bv_t a(key_to_process.bits(half_key_width - 1, 0));
    em::hash_bv_t b(key_to_process.bits(m_key_width - 1, half_key_width));

    size_t b_rot_value = calc_short_crc(a);
    b = sub_bvs(b, m_rc5_parameter_parts[3]);
    b = rotr_bv(b, b_rot_value);
    b ^= a;

    size_t a_rot_value = calc_short_crc(b);
    a = sub_bvs(a, m_rc5_parameter_parts[2]);
    a = rotr_bv(a, a_rot_value);
    a ^= b;

    b = sub_bvs(b, m_rc5_parameter_parts[1]);
    a = sub_bvs(a, m_rc5_parameter_parts[0]);

    em::hash_bv_t reconstructed_key = ((b << half_key_width) | a);

    em::key_t result(0, m_key_width);
    result.set_bits(m_key_width - 1, 0, reconstructed_key);

    return result;
}

em::hash_bv_t
em_hasher::calc_equal_width_crc(const em::hash_bv_t& bv) const
{
    em::hash_bv_t crc_res = calc_fib_crc_fast(bv, m_fast_long_crc_div_indices, m_fast_long_crc_init);

    return crc_res;
}

em::hash_bv_t
em_hasher::calc_reverse_equal_width_crc(const em::hash_bv_t& bv) const
{
    em::hash_bv_t rev_crc_res = calc_fib_rev_crc_fast(bv, m_long_crc_div_flipped, m_long_crc_init);

    return rev_crc_res;
}

size_t
em_hasher::calc_short_crc(const em::hash_bv_t& bv) const
{
    em::hash_bv_t crc_res = calc_fib_crc_fast(bv, m_fast_short_crc_div_indices, m_fast_short_crc_init);
    crc_res = crc_res.bits_from_msb(0, m_short_crc_init.get_width());

    return crc_res.get_value();
}

em::hash_bv_t
em_hasher::calc_fib_crc_simple(const em::hash_bv_t& bv, const em::hash_bv_t& div, const em::hash_bv_t& init) const
{
    size_t bv_width = bv.get_width();
    size_t result_width = init.get_width();

    // Result starts as the initial vector, taps are the bits to XOR with incoming bv bits.
    em::hash_bv_t result = init;
    em::hash_bv_t taps = div.bits_from_msb(1, result_width);

    // The bits are inserted one by one, and XORed with result's relevant bits according to taps.
    // On each cycle result is shifted left by 1, and the LSB is set by XORing next bv bit and relevant result bits.
    for (size_t i = 0; i < bv_width; i++) {
        em::hash_bv_t relevant_bits = result & taps;
        em::hash_bv_t next_bit = bv.bits(i, i);

        // Calculation of next bit.
        size_t number_of_relevant_bits = relevant_bits.get_width();
        for (size_t j = 0; j < number_of_relevant_bits; j++) {
            next_bit ^= relevant_bits.bits(j, j);
        }

        // Shifting right by 1, setting MSB to be calculated next bit.
        size_t last_bit = result_width - 1;
        result = result.bits_from_msb(0, last_bit);
        result.set_bits(last_bit, last_bit, next_bit);
    }

    return result;
}

em::hash_bv_t
em_hasher::calc_fib_rev_crc_simple(const em::hash_bv_t& bv, const em::hash_bv_t& div, const em::hash_bv_t& init) const
{
    size_t bv_width = bv.get_width();
    size_t result_width = init.get_width();

    // Result is calculated bit by bit, taps are the bits to XOR with incoming bv bits.
    // Temp will store the previous stage for next bit calculation.
    em::hash_bv_t result(0, result_width);
    em::hash_bv_t temp(bv);
    em::hash_bv_t taps = div.bits_from_msb(1, result_width);

    // On each cycle temp is shifted right by 1, and the MSB is set to be the next initial vector bit.
    // The next result bit is calculated by XORing saved bit and relevant temp bits.
    for (size_t i = 0; i < bv_width; i++) {
        em::hash_bv_t next_bit = temp.bits_from_msb(0, 1);

        // Previous stage.
        em::hash_bv_t prev_bit = init.bits_from_msb(i, 1);
        temp = temp.bits_from_msb(1, result_width - 1);
        temp = (temp << 1) | prev_bit;

        em::hash_bv_t relevant_bits = temp & taps;

        // Calculation of next bit.
        size_t number_of_relevant_bits = relevant_bits.get_width();
        for (size_t j = 0; j < number_of_relevant_bits; j++) {
            next_bit ^= relevant_bits.bits(j, j);
        }

        // Next bit is the next result bit.
        result.set_bits_from_msb(i, 1, next_bit);
    }

    return result;
}

em::hash_bv_t
em_hasher::rotr_bv(const em::hash_bv_t& bv, size_t value) const
{
    size_t bv_width = bv.get_width();
    value = value % bv_width;
    if (value == 0) {
        return bv;
    }

    size_t rem_value = bv_width - value;

    em::hash_bv_t result;
    result.resize(bv_width);
    result.set_bits_from_msb(0, value, bv);
    result.set_bits_from_msb(value, rem_value, bv.bits_from_msb(0, rem_value));

    return result;
}

em::hash_bv_t
em_hasher::rotl_bv(const em::hash_bv_t& bv, size_t value) const
{
    size_t bv_width = bv.get_width();
    value = value % bv_width;
    size_t right_rotate_value = bv_width - value;

    em::hash_bv_t result = rotr_bv(bv, right_rotate_value);

    return result;
}

em::hash_bv_t
em_hasher::add_bvs(const em::hash_bv_t& bv1, const em::hash_bv_t& bv2) const
{
    size_t width = bv1.get_width();
    size_t width_in_bytes = bv1.get_width_in_bytes();
    em::hash_bv_t result(0, width);

    const uint8_t* bv1_ba = bv1.byte_array();
    const uint8_t* bv2_ba = bv2.byte_array();
    uint8_t* result_ba = result.byte_array();

    bool carry = 0;
    for (size_t bi = 0; bi < width_in_bytes; bi++) {
        result_ba[bi] = bv1_ba[bi] + bv2_ba[bi] + carry;
        carry = (result_ba[bi] < bv1_ba[bi]);
    }

    return result.bits(width - 1, 0);
}

em::hash_bv_t
em_hasher::sub_bvs(const em::hash_bv_t& bv1, const em::hash_bv_t& bv2) const
{
    size_t width = bv1.get_width();
    size_t width_in_bytes = bv1.get_width_in_bytes();
    em::hash_bv_t result(0, width);

    const uint8_t* bv1_ba = bv1.byte_array();
    const uint8_t* bv2_ba = bv2.byte_array();
    uint8_t* result_ba = result.byte_array();

    bool borrow = 0;
    for (size_t bi = 0; bi < width_in_bytes; bi++) {
        result_ba[bi] = bv1_ba[bi] - bv2_ba[bi] - borrow;
        borrow = (result_ba[bi] > bv1_ba[bi]);
    }

    return result.bits(width - 1, 0);
}

em::hash_bv_t
em_hasher::flip_bv(const em::hash_bv_t& bv) const
{
    size_t bv_width = bv.get_width();
    em::hash_bv_t flipped_bv(0, bv_width);

    for (size_t bit_pos = 0; bit_pos < bv_width; bit_pos++) {
        flipped_bv.set_bits(bit_pos, bit_pos, bv.bits_from_msb(bit_pos, 1));
    }

    return flipped_bv;
}

em::hash_bv_t
em_hasher::calc_fast_crc_div(const em::hash_bv_t& div, size_t bv_width) const
{
    size_t div_width = div.get_width();
    em::hash_bv_t ext_div(div);

    size_t extension = bv_width + 1 - div_width;
    if (extension != 0) {
        ext_div = ext_div << extension;
    }

    em::hash_bv_t zero_init_value(0, bv_width);
    em::hash_bv_t bv_one_in_lsb(1, bv_width);
    em::hash_bv_t fast_long_div = calc_fib_crc_simple(bv_one_in_lsb, ext_div, zero_init_value);

    return fast_long_div;
}

em::hash_bv_t
em_hasher::calc_fast_crc_init(const em::hash_bv_t& div, const em::hash_bv_t& init, size_t bv_width) const
{
    size_t div_width = div.get_width();
    em::hash_bv_t ext_div(div);
    em::hash_bv_t ext_init(init);

    size_t extension = bv_width + 1 - div_width;
    if (extension != 0) {
        ext_div = ext_div << extension;
        ext_init = ext_init << extension;
    }

    em::hash_bv_t zero_value(0, bv_width);
    em::hash_bv_t fast_long_init = calc_fib_crc_simple(zero_value, ext_div, ext_init);

    return fast_long_init;
}

em::hash_bv_t
em_hasher::calc_fib_crc_fast(const em::hash_bv_t& bv, const vector<size_t>& fast_div_indices, const em::hash_bv_t& fast_init) const
{
    em::hash_bv_t result(fast_init);
    for (size_t bv_offset : fast_div_indices) {
        result.xor_with_other_shifted_left(bv, bv_offset);
    }

    return result;
}

em::hash_bv_t
em_hasher::calc_fib_rev_crc_fast(const em::hash_bv_t& bv, const em::hash_bv_t& div, const em::hash_bv_t& init) const
{
    size_t bv_width = bv.get_width();
    em::hash_bv_t result;

    for (size_t bv_offset = 0; bv_offset < bv_width + 1; bv_offset++) {
        if (div.bit_from_msb(bv_offset)) {
            em::hash_bv_t temp;
            temp.set_bits(bv_width - 1, bv_offset, bv);
            if (bv_offset != 0) {
                temp.set_bits(bv_offset - 1, 0, init.bits_from_msb(0, bv_offset));
            }

            result ^= temp;
        }
    }

    return result;
}

} // namespace silicon_one
