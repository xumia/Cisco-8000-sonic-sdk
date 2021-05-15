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

#ifndef __LEABA_EM_BANK_H__
#define __LEABA_EM_BANK_H__

#include "common/bit_vector.h"
#include "common/la_status.h"

#include "lld/lld_fwd.h"

#include "hw_tables/em_common.h"
#include "hw_tables/em_hasher.h"

namespace silicon_one
{

/// @brief Exact match entry data.
struct em_bank_entry_data {
    bool valid;               ///< Whether entry is valid.
    bit_vector key;           ///< Decrypted key.
    bit_vector payload;       ///< Payload.
    size_t key_width;         ///< Current entry key width.
    bit_vector encrypted_key; ///< Encrypted key, including hash and verifier.
    size_t hash_value;        ///< Current entry hash value (line number).
};

/// @brief EM bank wrapper.
///
/// Piggybacks an existing HW EM bank, enabling caller to decipher values in it.
class em_bank
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief C'tor.
    ///
    /// @param[in]  ldevice         Low level device.
    /// @param[in]  bank_idx        Bank index within the core.
    /// @param[in]  verifier        Verifier memory.
    /// @param[in]  config_reg      Per-bank configuration register.
    /// @param[in]  rc5_start_pos   Start position of RC5 seed in per-bank configuration register.
    /// @param[in]  key_widths      List of possible key widths for given EM. Largest key is the first.
    /// @param[in]  data_width      Width of key and payload.
    em_bank(const ll_device_sptr& ldevice,
            size_t bank_idx,
            const lld_memory_scptr& verifier,
            const lld_register_scptr& config_reg,
            size_t rc5_start_pos,
            const std::vector<size_t>& key_widths,
            size_t data_width);

    /// @brief EM bank destructor.
    ~em_bank() = default;

    /// @brief Check if the entry is valid.
    ///
    /// @param[in]  entry_idx        Entry index.
    ///
    /// @retval     whether entry is valid.
    bool is_valid(size_t entry_idx) const;

    /// @brief Decript and return entry content.
    ///
    /// @param[in]  entry_idx        Entry index.
    ///
    /// @retval     entry content.
    em_bank_entry_data get_entry(size_t entry_idx) const;

    /// @brief Return number of entries in the bank (full and empty).
    ///
    /// @retval     number of entries.
    size_t get_size() const;

    /// @brief Encrypt key according to given width.
    ///
    /// @param[in]  key             Key.
    /// @param[in]  key_width       Key width in bits.
    ///
    /// @retval     encrypted key.
    bit_vector encrypt(const bit_vector& key, size_t key_width) const;

    /// @brief Decrypt key according to given width.
    ///
    /// @param[in]  key             Encrypted key.
    /// @param[in]  key_width       Key width in bits.
    ///
    /// @retval     decrypted key.
    bit_vector decrypt(const bit_vector& key, size_t key_width) const;

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    em_bank() = default;

    /// @brief init flow.
    void init();

    /// @brief Decript key based on encrypted key and key width.
    void decrypt_key(em_bank_entry_data& data) const;

    /// @brief Return hasher according to key width.
    em_hasher_scptr get_hasher(size_t key_width) const;

private:
    ll_device_sptr m_ll_device;  ///< Low level device.
    lld_memory_scptr m_verifier; ///< Verifier memory containing bank data.
    bit_vector m_rc5;            ///< RC5 seed.

    std::vector<size_t> m_key_widths; ///< List of key widths, starting with primary key (largest).
    size_t m_data_width;              ///< Combined width of key and payload.
    size_t m_bank_idx;                ///< Bank index in EM core.

    std::vector<em_hasher_scptr> m_hashers; ///< Hasher per key width.

    size_t m_bank_addr_width;      ///< Width in bits needed to represent any line in the bank memory.
    size_t m_key_size_field_width; ///< Width of the key size field in bank memory line.
};

} // namespace silicon_one

#endif // __LEABA_EM_BANK_H__
