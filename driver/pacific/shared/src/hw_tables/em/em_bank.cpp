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

#include "hw_tables/em_bank.h"
#include "hw_tables/em_hasher.h"

#include "common/logger.h"

#include "lld/ll_device.h"
#include "lld/lld_memory.h"
#include "lld/lld_register.h"

#include "crc_divisors.h"

namespace silicon_one
{

em_bank::em_bank(const ll_device_sptr& ldevice,
                 size_t bank_idx,
                 const lld_memory_scptr& verifier,
                 const lld_register_scptr& per_bank_config,
                 size_t rc5_start_pos,
                 const std::vector<size_t>& key_widths,
                 size_t data_width)
    : m_ll_device(ldevice), m_verifier(verifier), m_key_widths(key_widths), m_data_width(data_width), m_bank_idx(bank_idx)
{
    dassert_crit(!m_key_widths.empty());
    size_t prim_key_width = key_widths[0];

    bit_vector cfg_reg_val;
    m_ll_device->read_register(per_bank_config, cfg_reg_val);
    m_rc5 = cfg_reg_val.bits(prim_key_width * 2 + rc5_start_pos - 1, rc5_start_pos);

    init();
}

void
em_bank::init()
{
    m_rc5.resize(m_key_widths[0] * 2);

    const lld_memory_desc_t* desc = m_verifier->get_desc();
    size_t bank_size = desc->entries;

    m_bank_addr_width = bit_utils::bits_to_represent(bank_size - 1);
    m_key_size_field_width = bit_utils::bits_to_represent(m_key_widths.size());

    for (size_t key_width : m_key_widths) {

        // Prepare crc divisors
        em::hasher_params hasher_params;

        hasher_params.long_crc_div = get_long_non_primitive_crc_divisor(key_width);
        hasher_params.short_crc_div = get_short_crc_divisor(key_width);

        if (!hasher_params.long_crc_div.get_width() || !hasher_params.short_crc_div.get_width()) {
            log_err(TABLES, "%s: could not find CRC divisors for length: %zd", __func__, key_width);
        }

        hasher_params.long_crc_init = em::hash_bv_t(0, hasher_params.long_crc_div.get_width() - 1);
        hasher_params.short_crc_init = em::hash_bv_t(0, hasher_params.short_crc_div.get_width() - 1);
        hasher_params.short_crc_init.negate();

        hasher_params.rc5_parameter = m_rc5;

        m_hashers.push_back(std::make_shared<em_hasher>(key_width, hasher_params));
    }
}

bool
em_bank::is_valid(size_t entry_idx) const
{
    bit_vector val;
    la_status status = m_ll_device->read_memory(*m_verifier, entry_idx, val);
    if (status != LA_STATUS_SUCCESS) {
        return false;
    }

    size_t lsb = m_data_width - m_bank_addr_width - 1;
    size_t key_size_width = val.bits(lsb + m_key_size_field_width, lsb).get_value();
    return (key_size_width != 0);
}

em_bank_entry_data
em_bank::get_entry(size_t entry_idx) const
{
    em_bank_entry_data ret;
    ret.hash_value = entry_idx;
    ret.key_width = 0;
    ret.valid = false;

    bit_vector val;
    la_status status = m_ll_device->read_memory(*m_verifier, entry_idx, val);
    if (status != LA_STATUS_SUCCESS) {
        return ret;
    }

    size_t key_width_lsb = m_data_width - m_bank_addr_width;
    size_t key_size_width = val.bits(key_width_lsb + m_key_size_field_width - 1, key_width_lsb).get_value();

    // key_size_width is starting from 1 (0 is invalid option), therefore, it can be equal to size.
    if (key_size_width == 0 || key_size_width > m_key_widths.size()) {
        return ret;
    }

    bool is_double_entry = false;
    ret.valid = true;
    ret.key_width = m_key_widths[key_size_width - 1];
    if (ret.key_width > m_data_width) {
        // Double entry - decript according to the previous key width
        is_double_entry = true;
        ret.key_width = m_key_widths[key_size_width];
    }

    size_t key_lsb = m_data_width - ret.key_width;
    ret.payload = val.bits(key_lsb - 1, 0);
    ret.encrypted_key = val.bits(key_width_lsb - 1, key_lsb);

    if (is_double_entry && (m_bank_idx % 2) == 1) {
        // there is no encryption in the second bank of the double entry
        ret.key = ret.encrypted_key;
    } else {
        size_t verifier_width = ret.encrypted_key.get_width();
        ret.encrypted_key.resize(ret.key_width);
        ret.encrypted_key.set_bits(ret.key_width - 1, verifier_width, entry_idx);

        decrypt_key(ret);
    }

    if (is_double_entry) {
        // Revert to the real key width
        ret.key_width = m_key_widths[key_size_width - 1];
    }

    return ret;
}

bit_vector
em_bank::encrypt(const bit_vector& key, size_t key_width) const
{
    em_hasher_scptr hasher = get_hasher(key_width);
    if (!hasher) {
        return bit_vector();
    }

    em::key_t in_key(key);
    in_key.resize(key_width);
    em::key_t out_key = hasher->encrypt(in_key);

    return out_key;
}

bit_vector
em_bank::decrypt(const bit_vector& key, size_t key_width) const
{
    em_hasher_scptr hasher = get_hasher(key_width);
    if (!hasher) {
        return bit_vector();
    }

    em::key_t in_key(key);
    in_key.resize(key_width);
    em::key_t out_key = hasher->decrypt(in_key);

    return out_key;
}

void
em_bank::decrypt_key(em_bank_entry_data& data) const
{
    data.key = decrypt(data.encrypted_key, data.key_width);
}

em_hasher_scptr
em_bank::get_hasher(size_t key_width) const
{
    em_hasher_scptr hasher = nullptr;
    for (size_t key_idx = 0; key_idx < m_key_widths.size(); ++key_idx) {
        if (m_key_widths[key_idx] == key_width) {
            hasher = m_hashers[key_idx];
            break;
        }
    }

    return hasher;
}

size_t
em_bank::get_size() const
{
    const lld_memory_desc_t* desc = m_verifier->get_desc();
    return desc->entries;
}

} // namespace silicon_one
