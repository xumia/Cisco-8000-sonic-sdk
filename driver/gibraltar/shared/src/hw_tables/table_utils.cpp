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

#include "table_utils.h"
#include "common/defines.h"
#include "common/logger.h"
#include "hw_tables/em_hasher.h"

#include "lld/ll_device.h"

#include "em/crc_divisors.h"

namespace silicon_one
{

namespace table_utils
{

la_status
write_physical_sram(const ll_device_sptr& ldevice, const physical_sram& sram, size_t line, size_t offset, const bit_vector& value)
{
    line = sram.start_line + line;

    for (const lld_memory_scptr& mem : sram.memories) {
        size_t lsb = offset + sram.offset;
        size_t msb = lsb + value.get_width() - 1;
        la_status status = ldevice->read_modify_write_memory(*mem, line, msb, lsb, value);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
read_physical_sram(const ll_device_sptr& ldevice, const physical_sram& sram, size_t line, bit_vector& out_val)
{
    line = sram.start_line + line;

    // Read representative memory value.
    const lld_memory_scptr& mem = sram.memories[0];
    bit_vector mem_val;
    la_status status = ldevice->read_memory(*mem, line, mem_val);
    return_on_error(status);

    out_val = mem_val.bits(sram.offset + sram.width - 1 /*msb*/, sram.offset /*lsb*/);
    return LA_STATUS_SUCCESS;
}

la_status
write_sram_section(const ll_device_sptr& ldevice,
                   const std::vector<physical_sram>& section,
                   size_t line,
                   size_t offset,
                   const bit_vector& value)
{
    int sram_offset = (int)offset;

    size_t lsb = 0;
    for (const physical_sram& sram : section) {
        int sram_width = (int)sram.width - sram_offset;
        if (sram_width > 0) {
            int bits_to_copy = std::min(value.get_width() - lsb, sram_width - lsb);
            dassert_crit(bits_to_copy > 0);

            size_t msb = lsb + bits_to_copy - 1;
            bit_vector sram_value = value.bits(msb, lsb);
            la_status status = write_physical_sram(ldevice, sram, line, sram_offset, sram_value);
            return_on_error(status);

            lsb += bits_to_copy;
            sram_offset = std::max(0, sram_offset - bits_to_copy);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
write_sram_section_with_multiple_mem(const ll_device_sptr& ldevice,
                                     const std::vector<physical_sram>& section,
                                     size_t line,
                                     size_t offset,
                                     const bit_vector& value)
{
    int sram_offset = (int)offset;

    size_t lsb = 0;
    for (const physical_sram& sram : section) {
        size_t msb = lsb + sram.width - 1;
        bit_vector sram_value = value.bits(msb, lsb);
        la_status status = write_physical_sram(ldevice, sram, line, sram_offset, sram_value);
        return_on_error(status);
        lsb = msb + 1;
    }

    return LA_STATUS_SUCCESS;
}

la_status
read_sram_section(const ll_device_sptr& ldevice, const std::vector<physical_sram>& section, size_t line, bit_vector& out_val)
{
    size_t lsb = 0;
    for (const physical_sram& sram : section) {
        size_t msb = lsb + sram.width - 1;

        bit_vector sram_val;
        la_status status = read_physical_sram(ldevice, sram, line, sram_val);
        return_on_error(status);

        out_val.set_bits(msb, lsb, sram_val);

        lsb = msb + 1;
    }

    return LA_STATUS_SUCCESS;
}

la_status
write_physical_tcam(const ll_device_sptr& ldevice,
                    const physical_tcam& tcam,
                    size_t line,
                    const bit_vector& key,
                    const bit_vector& mask)
{
    line = tcam.start_line + line;

    for (const lld_memory_scptr& mem : tcam.memories) {
        la_status status = ldevice->write_tcam(*mem, line, key, mask);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
read_physical_tcam(const ll_device_sptr& ldevice,
                   const physical_tcam& tcam,
                   size_t line,
                   bit_vector& out_key,
                   bit_vector& out_mask,
                   bool& out_valid)
{
    line = tcam.start_line + line;

    // representative
    const lld_memory_scptr& mem = tcam.memories[0];
    la_status status = ldevice->read_tcam(*mem, line, out_key, out_mask, out_valid);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
write_tcam_section(const ll_device_sptr& ldevice,
                   const std::vector<physical_tcam>& section,
                   size_t line,
                   const bit_vector& key,
                   const bit_vector& mask)
{
    size_t lsb = 0;
    for (const physical_tcam& tcam : section) {
        size_t msb = lsb + tcam.width - 1;

        bit_vector tcam_key = key.bits(msb, lsb);
        bit_vector tcam_mask = mask.bits(msb, lsb);
        la_status status = write_physical_tcam(ldevice, tcam, line, tcam_key, tcam_mask);
        return_on_error(status);

        lsb = msb + 1;
    }

    return LA_STATUS_SUCCESS;
}

la_status
read_tcam_section(const ll_device_sptr& ldevice,
                  const std::vector<physical_tcam>& section,
                  size_t line,
                  bit_vector& out_key,
                  bit_vector& out_mask,
                  bool& out_valid)
{
    size_t lsb = 0;
    for (const physical_tcam& tcam : section) {
        size_t msb = lsb + tcam.width - 1;

        bit_vector tcam_key;
        bit_vector tcam_mask;
        la_status status = read_physical_tcam(ldevice, tcam, line, tcam_key, tcam_mask, out_valid);
        return_on_error(status);

        out_key.set_bits(msb, lsb, tcam_key);
        out_mask.set_bits(msb, lsb, tcam_mask);

        lsb = msb + 1;
    }

    return LA_STATUS_SUCCESS;
}

la_status
write_register_array_sram(const ll_device_sptr& ldevice,
                          const register_array& sram,
                          size_t reg_idx,
                          size_t entry_offset,
                          const bit_vector& value)
{
    size_t lsb = sram.offset + entry_offset;
    size_t msb = lsb + value.get_width() - 1;

    for (const lld_register_scptr& reg : sram.memories[reg_idx]) {
        la_status status = ldevice->read_modify_write_register(*reg, msb, lsb, value);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
write_sram_section(const ll_device_sptr& ldevice, const std::vector<register_array>& srams, size_t line, const bit_vector& value)
{
    size_t lsb = 0;

    for (const register_array& sram : srams) {
        dassert_crit(sram.width % sram.entries_per_line == 0);
        size_t entry_width = sram.width / sram.entries_per_line;
        size_t entry_offset = (line % sram.entries_per_line) * entry_width;

        int bits_to_copy = std::min(value.get_width() - lsb, entry_width);
        dassert_crit(bits_to_copy > 0);

        size_t msb = lsb + bits_to_copy - 1;
        bit_vector sram_value = value.bits(msb, lsb);
        size_t reg_idx = line / sram.entries_per_line;

        la_status status = write_register_array_sram(ldevice, sram, reg_idx, entry_offset, sram_value);
        return_on_error(status);

        lsb += bits_to_copy;
    }

    return LA_STATUS_SUCCESS;
}

} // namespace table_utils

} // namespace silicon_one
