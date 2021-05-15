// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "mc_fe_links_bmp_sram_base.h"

#include "lld/ll_device.h"

#include "common/gen_utils.h"

namespace silicon_one
{

enum {
    MC_GROUP_ID_LENGTH = 16,
    MC_FE_LINKS_LOGICAL_SIZE = 1 << 16, // 64K

    // MC links bitmap in FE is stored in db that is union of two memeories.
    MC_FE_LINKS_BMP_PART_1_LENGTH = 91,      // the length of the links bitmap in the first part (without ECC).
    MC_FE_LINKS_BMP_ECC_PART_1_LENGTH = 8,   // the length of the ECC of the first part.
    MC_FE_LINKS_BMP_PART_2_LENGTH = 91,      // the length of the links bitmap in the second part (without ECC).
    MC_FE_LINKS_BMP_PART_2_USED_LENGTH = 18, // from the 91 bits above we use only 18 bits, other bits are unused.
    MC_FE_LINKS_BMP_ECC_PART_2_LENGTH = 8,   // the length of the ECC of the second part.
};

mc_fe_links_bmp_sram_base::mc_fe_links_bmp_sram_base(const ll_device_sptr& ll_device) : m_ll_device(ll_device)
{
}

size_t
mc_fe_links_bmp_sram_base::max_size() const
{
    return MC_FE_LINKS_LOGICAL_SIZE;
}

la_status
mc_fe_links_bmp_sram_base::write(size_t line, const bit_vector& value)
{
    size_t gid = line;
    const bit_vector& links_bitmap = value;

    // Shared DB num = MCID[0]
    uint64_t shared_db_num = bit_utils::get_bit(gid, 0);

    // shared_db_verifier_mem_num = 2 * MCID[15]
    uint64_t shared_db_verifier_mem_num = 2 * bit_utils::get_bit(gid, MC_GROUP_ID_LENGTH - 1);

    // gid[14:1] is the m_address in table which we write to.
    uint64_t address = bit_utils::get_bits(gid, MC_GROUP_ID_LENGTH - 2, 1);

    // links bitmap is divided into two parts each contains 91 bits, however, in part 2 only 18 bits are used.
    // each part should have ECC suffix of 8 bits.
    bit_vector128_t entry1(0, MC_FE_LINKS_BMP_PART_1_LENGTH + MC_FE_LINKS_BMP_ECC_PART_1_LENGTH);
    bit_vector128_t entry2(0, MC_FE_LINKS_BMP_PART_2_LENGTH + MC_FE_LINKS_BMP_ECC_PART_2_LENGTH);
    entry1.set_bits(MC_FE_LINKS_BMP_PART_1_LENGTH - 1, 0, links_bitmap.bits(MC_FE_LINKS_BMP_PART_1_LENGTH - 1, 0));
    entry2.set_bits(
        MC_FE_LINKS_BMP_PART_2_USED_LENGTH - 1,
        0,
        links_bitmap.bits(MC_FE_LINKS_BMP_PART_2_USED_LENGTH + MC_FE_LINKS_BMP_PART_1_LENGTH - 1, MC_FE_LINKS_BMP_PART_1_LENGTH));
    add_ecc_to_entry(entry1, MC_FE_LINKS_BMP_PART_1_LENGTH);
    add_ecc_to_entry(entry2, MC_FE_LINKS_BMP_PART_2_LENGTH);

    // rx_pdr_mc_db[Shared DB num].shared_db_verifier[m_shared_db_verifier_mem_num] in m_address m_gid[14:1] = {Ecc(entry1), entry1}
    lld_memory_sptr first_mem = get_rx_pdr_mc_db_memory(shared_db_num, shared_db_verifier_mem_num);
    la_status status = m_ll_device->write_memory(first_mem, address, entry1);
    return_on_error(status);

    // rx_pdr_mc_db[Shared DB num].shared_db_verifier[m_shared_db_verifier_mem_num + 1] in m_address m_gid[14:1] = {Ecc(entry2),
    // entry2}
    lld_memory_sptr second_mem = get_rx_pdr_mc_db_memory(shared_db_num, shared_db_verifier_mem_num + 1);
    status = m_ll_device->write_memory(second_mem, address, entry2);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

// TODO: Code duplication with em_core.cpp - this function was copied from there.
void
mc_fe_links_bmp_sram_base::add_ecc_to_entry(bit_vector128_t& entry, size_t ecc_lsb) const
{
    size_t entry_width = entry.get_width();
    size_t ecc_msb = entry_width - 1;
    size_t ecc_width = entry_width - ecc_lsb;

    // Create mixed data and zeros vector, according to what we see in HW
    size_t pos = 2;
    bit_vector128_t mixed_data;
    // These bit slices are hardcoded for performance according to what HW does
    struct {
        size_t bit_pos;
        size_t width;
    } entry_bit_slices[] = {{0, 1}, {1, 3}, {4, 7}, {11, 15}, {26, 31}, {57, 34}};
    for (size_t i = 0; i < array_size(entry_bit_slices); i++) {
        mixed_data.set_bits(pos + entry_bit_slices[i].width,
                            pos + 1,
                            entry.bits(entry_bit_slices[i].bit_pos + entry_bit_slices[i].width - 1, entry_bit_slices[i].bit_pos));
        pos *= 2;
    }

    // Run parity
    size_t mixed_data_width = mixed_data.get_width();
    for (size_t ecc_idx = 0, ecc_pos = ecc_lsb; ecc_idx < ecc_width - 1; ++ecc_idx, ++ecc_pos) {
        size_t addr_pos = (1 << ecc_idx);
        bool ecc_val = entry.bit(ecc_pos);
        bool ecc_calc_val = ecc_val;
        for (size_t data_idx = 1; data_idx < mixed_data_width; ++data_idx) {
            if (data_idx & addr_pos) {
                bool data_val = mixed_data.bit(data_idx);
                ecc_calc_val = ecc_calc_val ^ data_val;
            }
        }
        entry.set_bit(ecc_pos, ecc_calc_val);
    }

    // Run parity for MSB
    bool ecc_msb_val = (entry.count_ones() % 2) == 1;
    entry.set_bit(ecc_msb, ecc_msb_val);
}
}
