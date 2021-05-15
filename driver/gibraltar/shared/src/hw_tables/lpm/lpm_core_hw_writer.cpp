// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "lpm_core_hw_writer.h"
#include "lld/ll_device.h"

#include "common/logger.h"

namespace silicon_one
{

lpm_core_hw_writer::lpm_core_hw_writer(const ll_device_sptr& ldevice,
                                       lpm_core_id_t core_id,
                                       uint8_t num_tcam_banksets,
                                       size_t num_cells_per_bankset,
                                       size_t tcam_bank_size)
    : m_ll_device(ldevice),
      m_core_id(core_id),
      m_tcam_num_banksets(num_tcam_banksets),
      m_num_cells_per_bankset(num_cells_per_bankset),
      m_tcam_bank_size(tcam_bank_size)
{
    if (!m_ll_device) {
        // This is an empty object to mimic HW writes.
        // It should not be initialized and will not be used.
        return;
    }
}

lpm_core_hw_writer::~lpm_core_hw_writer()
{
}

const ll_device_sptr&
lpm_core_hw_writer::get_ll_device() const
{
    return m_ll_device;
}

lpm_key_t
lpm_core_hw_writer::encode_prefix(const lpm_key_t& key, size_t root_width, size_t output_width) const
{
    lpm_key_t encoded_prefix(0, output_width);

    dassert_crit(root_width <= key.get_width());

    size_t prefix_width = std::min(key.get_width() - root_width, output_width - 1);
    if (prefix_width > 0) {
        lpm_key_t prefix(key.bits_from_msb(root_width, prefix_width));
        encoded_prefix.set_bits_from_msb(0 /*offset*/, prefix_width, prefix);
    }

    size_t shift = output_width - 1 - prefix_width;
    encoded_prefix.set_bit(shift, true);

    return encoded_prefix;
}

bit_vector
lpm_core_hw_writer::decode_prefix(const bit_vector& prefix) const
{
    dassert_crit(!prefix.is_zero());

    bit_vector ret(prefix);
    const size_t width = prefix.get_width();

    // shift, till you see 1 (including)
    for (size_t pos = 0; pos < width; pos++) {
        if (ret.bit(pos)) {
            ret = ret >> (pos + 1);
            return ret;
        }
    }

    dassert_crit(false);
    return bit_vector();
}

size_t
lpm_core_hw_writer::tcam_location_to_row(const tcam_cell_location& location) const
{
    size_t row = location.bankset * m_num_cells_per_bankset + location.bank * m_tcam_bank_size + location.cell;
    return row;
}

tcam_cell_location
lpm_core_hw_writer::tcam_row_to_location(size_t row) const
{
    uint8_t bankset = row / m_num_cells_per_bankset;
    uint32_t row_in_bankset = row % m_num_cells_per_bankset;

    uint8_t bank = row_in_bankset / m_tcam_bank_size;
    uint32_t row_in_bank = row_in_bankset % m_tcam_bank_size;

    tcam_cell_location location = {.bankset = bankset, .bank = bank, .cell = row_in_bank};
    return location;
}

bool
lpm_core_hw_writer::verify_no_overrides(const uint64_t* data_ptr, size_t msb, size_t lsb) const
{
    if (msb < lsb) {
        return true;
    }

    uint64_t data = 0;
    size_t current_lsb = lsb;
    size_t bits_to_compare = msb - lsb + 1;

    while (bits_to_compare > 0) {
        size_t iteration_bits_to_compare = std::min(bits_to_compare, (size_t)bit_utils::BITS_IN_UINT64);
        size_t current_msb = current_lsb + iteration_bits_to_compare - 1;
        bit_utils::get_bits(data_ptr, current_msb, current_lsb, &data);
        bool is_free = (data == 0);
        if (!is_free) {
            return false;
        }

        bits_to_compare -= iteration_bits_to_compare;
        current_lsb += iteration_bits_to_compare;
    }

    return true;
}

la_status
lpm_core_hw_writer::calculate_bucket_location_in_hbm(size_t hw_index,
                                                     size_t repl_idx,
                                                     hbm_physical_location& out_hbm_location) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

} // namespace silicon_one
