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

#ifndef __LEABA_EM_HASHER_H__
#define __LEABA_EM_HASHER_H__

#include <memory>

#include "common/bit_vector.h"
#include "hw_tables/em_common.h"
#include "hw_tables/hw_tables_fwd.h"

/// @file

namespace silicon_one
{

/*

EM hashing algorithm:

   * The algorithm is based on the cryptographic algorithm RC5.
     The RC5 algorithm takes a key, breaks it to two equal width parts,
     and repeatdly mix them and additional RC5 parameter (constant given at construction) up with multiple bit operations,
     eventually join these parts to a hashed key with the width of the original key.

   * In our algorithm we perform only a single round, with a two modifications:
       1. In an RC5 round, one of the operations is rotation of a part by the value of the other part.
          This is HW expensive opertaion, thus we replace the rotation value by a CRC calculation of the other part.
          This CRC takes a half key width value and returns a ceil(log2(half key width)) width value.
       2. At the end of the round, another CRC is imposed on the reassembled key.
          This CRC takes a key width value and returns a key width value.

*/

/// @brief EM hasher.
///
/// A class implementing the EM hashing algorithms.
/// Supports encrypting and decrypting of given length bit vectors.
class em_hasher
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Construct an EM hasher.
    ///
    /// @param[in]      key_width               Width of key to encrypt/decrypt.
    /// @param[in]      hasher_params           Parameters required for CRC and RC5 calculation.
    em_hasher(size_t key_width, const em::hasher_params& hasher_params);

    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    em_hasher() = default;

    /// @name API-s
    /// @{

    /// @brief Encrypt a given key.
    ///
    /// @param[in]      key_to_encrypt          Key to encrypt.
    ///
    /// @return Encrypted key.
    em::key_t encrypt(const em::key_t& key_to_encrypt) const;

    /// @brief Decrypt a given key.
    ///
    /// @param[in]      key_to_decrypt          Key to decrypt.
    ///
    /// @return Encrypted key.
    em::key_t decrypt(const em::key_t& key_to_decrypt) const;

    /// @}

private:
    enum { NUMBER_OF_RC5_PARTS = 4 };

    /// @brief Calculate CRC of given bit vector, from its width to the same width.
    ///
    /// @param[in]      bv                      Bit vector to calculate CRC of.
    ///
    /// @return Bit vector representing CRC result.
    em::hash_bv_t calc_equal_width_crc(const em::hash_bv_t& bv) const;

    /// @brief Calculate reverse CRC of given bit vector, from its width to the same width.
    ///
    /// @param[in]      bv                      Bit vector to calculate reverse CRC of.
    ///
    /// @return Bit vector representing reverse CRC result.
    em::hash_bv_t calc_reverse_equal_width_crc(const em::hash_bv_t& bv) const;

    /// @brief Calculate CRC of given bit vector, from its width to number of bits needed to represent its width.
    ///
    /// @param[in]      bv                      Bit vector to calculate short CRC of.
    ///
    /// @return Bit vector representing CRC result.
    size_t calc_short_crc(const em::hash_bv_t& bv) const;

    /// @brief Calculate CRC of a given bit vector according to CRC parameters.
    ///
    /// @param[in]      bv                      Bit vector to calculate CRC of.
    /// @param[in]      div                     CRC polynomial divisor.
    /// @param[in]      init                    Initial vector.
    ///
    /// @return Bit vector representing CRC result.
    em::hash_bv_t calc_fib_crc_simple(const em::hash_bv_t& bv, const em::hash_bv_t& div, const em::hash_bv_t& init) const;

    /// @brief Calculate reverse CRC of a given bit vector according to CRC parameters.
    ///
    /// @param[in]      bv                      Bit vector to calculate reverse CRC of.
    /// @param[in]      div                     CRC polynomial divisor.
    /// @param[in]      init                    Initial vector.
    ///
    /// @return Bit vector representing reverse CRC result.
    em::hash_bv_t calc_fib_rev_crc_simple(const em::hash_bv_t& bv, const em::hash_bv_t& div, const em::hash_bv_t& init) const;

    /// @brief Rotate bit vector left by a given value. Value should be in range [0,bit vector width).
    ///
    /// @param[in]      bv                      Bit vector to rotate.
    /// @param[in]      value                   Given value to rotate bit vector by.
    ///
    /// @return Bit vector represents rotation result.
    em::hash_bv_t rotl_bv(const em::hash_bv_t& bv, size_t value) const;

    /// @brief Rotate bit vector right by a given value. Value should be in range [0,bit vector width).
    ///
    /// @param[in]      bv                      Bit vector to rotate.
    /// @param[in]      value                   Given value to rotate bit vector by.
    ///
    /// @return Bit vector represents rotation result.
    em::hash_bv_t rotr_bv(const em::hash_bv_t& bv, size_t value) const;

    /// @brief Add two equal width bit vectors, result trimmed to be their original width wide.
    ///
    /// @param[in]      bv1                     First bit vector to sum.
    /// @param[in]      bv2                     Second bit vector to sum.
    ///
    /// @return Bit vector represents trimmed sum of two bit vectors.
    em::hash_bv_t add_bvs(const em::hash_bv_t& bv1, const em::hash_bv_t& bv2) const;

    /// @brief Subtract two equal width bit vectors, result is moduloed to be their original width.
    ///
    /// @param[in]      bv1                     Bit vector to subtract from.
    /// @param[in]      bv2                     Bit vector to subtract.
    ///
    /// @return Bit vector represents moduloed difference of two bit vectors.
    em::hash_bv_t sub_bvs(const em::hash_bv_t& bv1, const em::hash_bv_t& bv2) const;

    /// @brief Flip order of bits in bit vector.
    ///
    /// @param[in]      bv                      Bit vector to reverse bits order.
    ///
    /// @return Flipped bit vector.
    em::hash_bv_t flip_bv(const em::hash_bv_t& bv) const;

    /// @brief Calculate divisor for fast CRC calculation.
    ///
    /// @param[in]      div                     Divisor to calculate fast divisor from.
    /// @param[in]      bv_width                Width of bit vector to calculate fast divisor for.
    ///
    /// @return Divisor for fast CRC calculation.
    em::hash_bv_t calc_fast_crc_div(const em::hash_bv_t& div, size_t bv_width) const;

    /// @brief Calculate initial value for fast CRC calculation.
    ///
    /// @param[in]      div                     Divisor to calculate fast initial value from.
    /// @param[in]      init                    Initial value to valvulate fast initial value from.
    /// @param[in]      bv_width                Width of bit vector to calculate fast initial value for.
    ///
    /// @return Initial value for fast CRC calculation.
    em::hash_bv_t calc_fast_crc_init(const em::hash_bv_t& div, const em::hash_bv_t& init, size_t bv_width) const;

    /// @brief Fast CRC calculation.
    ///
    /// @param[in]      bv                      Bit vector to calculate fast CRC of.
    /// @param[in]      fast_div_indices        Fast CRC polynomial divisor indices.
    /// @param[in]      fast_init               Fast initial vector.
    ///
    /// @return Bit vector representing CRC result.
    em::hash_bv_t calc_fib_crc_fast(const em::hash_bv_t& bv,
                                    const std::vector<size_t>& fast_div_indices,
                                    const em::hash_bv_t& fast_init) const;

    /// @brief Fast reverse CRC calculation.
    ///
    /// @param[in]      bv                      Bit vector to calculate fast reverse CRC of.
    /// @param[in]      div                     Original CRC polynomial divisor.
    /// @param[in]      init                    Original initial vector.
    ///
    /// @return Bit vector representing reverse CRC result.
    em::hash_bv_t calc_fib_rev_crc_fast(const em::hash_bv_t& bv, const em::hash_bv_t& div, const em::hash_bv_t& init) const;

    // Members
    size_t m_key_width;                               ///< Supported key width.
    std::vector<em::hash_bv_t> m_rc5_parameter_parts; ///< RC5 expanded parameter, stored as 4 parts.

    // Flipped: bits stored in reversed order for calculation simplicity
    const em::hash_bv_t m_long_crc_div_flipped;  ///< Divisor of equal width CRC (flipped).
    const em::hash_bv_t m_long_crc_init;         ///< Initial vector of equal width CRC.
    const em::hash_bv_t m_short_crc_div_flipped; ///< Divisor of short CRC (flipped).
    const em::hash_bv_t m_short_crc_init;        ///< Initial vector of short CRC.

    // Members for speeding up long CRC calculation
    std::vector<size_t> m_fast_long_crc_div_indices;  ///< Indices of long fast CRC divisor.
    const em::hash_bv_t m_fast_long_crc_init;         ///< Long fast CRC initial value.
    std::vector<size_t> m_fast_short_crc_div_indices; ///< Indices of short fast CRC divisor.
    const em::hash_bv_t m_fast_short_crc_init;        ///< short fast CRC initial value.
};

using em_hasher_scptr = std::shared_ptr<const em_hasher>;

} // namespace silicon_one

#endif
