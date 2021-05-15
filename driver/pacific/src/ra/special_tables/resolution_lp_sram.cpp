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

#include "resolution_lp_sram.h"

#include "common/defines.h"
#include "lld/ll_device.h"
#include "lld/pacific_tree.h"

namespace silicon_one
{
//**************************************
// resolution_lp_config
//**************************************

resolution_lp_config::resolution_lp_config(const std::vector<lld_memory_scptr>& config_mems,
                                           const entry_widths& widths,
                                           size_t base_width,
                                           size_t mask_width)
    : m_config_mems(config_mems), m_widths(widths), m_base_width(base_width), m_mask_width(mask_width)
{
}

void
resolution_lp_config::add_table(size_t table_id,
                                size_t hw_key_prefix,
                                size_t hw_key_prefix_width,
                                size_t base,
                                size_t mask,
                                size_t shift)
{
    table_record_sptr rec = std::make_shared<table_record>();

    rec->base = base;
    rec->mask = mask;
    rec->shift = shift;
    rec->hw_key_prefix = hw_key_prefix;
    rec->hw_key_prefix_width = hw_key_prefix_width;
    rec->table_id = table_id;

    m_tables.push_back(rec);
}

const resolution_lp_config::table_record_wcptr
resolution_lp_config::get_table_record(size_t table_id) const
{
    for (const auto& rec : m_tables) {
        if (rec->table_id == table_id) {
            return rec;
        }
    }

    return nullptr;
}

la_status
resolution_lp_config::configure_hw(const ll_device_sptr& ldevice) const
{
    // In opposite to base and mask, shift field is always 2 bits.
    static const size_t shift_width = 2;
    static const size_t MAX_PREFIX_WIDTH = 5;

    size_t mem_width = shift_width + m_base_width + m_mask_width;

    // if prefix width for a specific table is less than max prefix width, the configuration
    // should be written to every permutation of LSB

    for (table_record_scptr rec : m_tables) {
        dassert_crit(rec->hw_key_prefix_width <= MAX_PREFIX_WIDTH);

        size_t missing_lsb = MAX_PREFIX_WIDTH - rec->hw_key_prefix_width;
        size_t lsb_permutations_num = 1 << missing_lsb;
        for (size_t lsb_permutation = 0; lsb_permutation < lsb_permutations_num; ++lsb_permutation) {
            size_t config_line = (rec->hw_key_prefix << missing_lsb) | lsb_permutation;
            bit_vector config_val(0, mem_width);
            size_t shift_msb = shift_width - 1;
            size_t base_msb = shift_width + m_base_width - 1;
            size_t mask_msb = mem_width - 1;
            config_val.set_bits(shift_msb, 0, rec->shift);
            config_val.set_bits(base_msb, shift_msb + 1, rec->base);
            config_val.set_bits(mask_msb, base_msb + 1, rec->mask);

            for (const lld_memory_scptr& config_mem : m_config_mems) {
                la_status ret = ldevice->write_memory(*config_mem, config_line, config_val);
                return_on_error(ret);
            }
        }
    }
    return LA_STATUS_SUCCESS;
}

const resolution_lp_config::entry_widths&
resolution_lp_config::get_widths() const
{
    return m_widths;
}

//**************************************
// resolution_lp_sram
//**************************************

resolution_lp_sram::resolution_lp_sram(const ll_device_sptr& ldevice,
                                       const std::vector<lld_memory_scptr>& srams,
                                       const config_t* config,
                                       size_t table_id)
    : m_ll_device(ldevice), m_srams(srams), m_table_id(table_id), m_config(*config)
{
    dassert_crit(m_srams.size());

    // representative
    m_size = m_srams[0]->get_desc()->entries;
}

size_t
resolution_lp_sram::get_offset_encoding(const config_t::table_record_wcptr& rec, size_t line) const
{
    dassert_crit(rec);

    size_t shift_max_val = 1 << rec->shift;
    // offset encoding in line num
    size_t offset_enc = line % shift_max_val;

    return offset_enc;
}

size_t
resolution_lp_sram::get_sram_line(const config_t::table_record_wcptr& rec, size_t line) const
{
    dassert_crit(rec);

    size_t mask = rec->mask;
    // shift the mask
    mask = mask << config_t::MASK_SHIFT;
    // turn on all shifted bits
    mask |= (1 << config_t::MASK_SHIFT) - 1;

    size_t ret = line;
    ret &= mask;
    ret >>= rec->shift;
    ret += rec->base * config_t::BASE_ADDRESS_GRANULARITY;

    return ret;
}

la_status
resolution_lp_sram::write_to_sram(size_t sram_line, const bit_vector& value)
{
    for (const lld_memory_scptr& sram : m_srams) {
        la_status ret = m_ll_device->write_memory(*sram, sram_line, value);
        return_on_error(ret);
    }

    return LA_STATUS_SUCCESS;
}

la_status
resolution_lp_sram::write_protected_entry(size_t sram_line, const bit_vector& value)
{
    const resolution_lp_config::entry_widths& widths(m_config.get_widths());

    if (value.get_width() != config_t::ENTRY_WIDTH_ENCODING_NUM_BITS + widths.protected_width) {
        return LA_STATUS_EINVAL;
    }

    bit_vector in_val(value.bits_from_msb(config_t::ENTRY_WIDTH_ENCODING_NUM_BITS /*offset*/, widths.protected_width /*width*/));
    in_val.resize(widths.sram_width);
    in_val.set_bits_from_msb(0 /*offset*/, 1 /*width*/, 1 /*protected encoding*/);

    return write_to_sram(sram_line, in_val);
}

la_status
resolution_lp_sram::write_partial_entry(size_t width_encoding,
                                        size_t record_width,
                                        size_t sram_line,
                                        size_t offset,
                                        const bit_vector& value)
{
    const resolution_lp_config::entry_widths& widths(m_config.get_widths());

    if (value.get_width() < config_t::ENTRY_WIDTH_ENCODING_NUM_BITS + record_width) {
        return LA_STATUS_EINVAL;
    }

    // read from representative
    bit_vector in_val;
    m_ll_device->read_memory(*(m_srams[0]), sram_line, in_val);
    in_val.resize(widths.sram_width);

    in_val.set_bits_from_msb(0 /*offset*/, 2 /*width*/, width_encoding);

    bit_vector record = value.bits_from_msb(config_t::ENTRY_WIDTH_ENCODING_NUM_BITS /*offset*/, record_width);
    in_val.set_bits(offset + record_width - 1, offset, record);

    return write_to_sram(sram_line, in_val);
}

la_status
resolution_lp_sram::write(size_t line, const bit_vector& value)
{
    const resolution_lp_config::entry_widths& widths(m_config.get_widths());

    config_t::table_record_wcptr rec = m_config.get_table_record(m_table_id);

    if (!rec) {
        return LA_STATUS_ENOTINITIALIZED;
    }

    size_t sram_line = get_sram_line(rec, line);

    if (sram_line >= m_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    size_t offset_enc = get_offset_encoding(rec, line);
    size_t width_enc = value.bits_from_msb(0 /*offset*/, config_t::ENTRY_WIDTH_ENCODING_NUM_BITS).get_value();

    switch (width_enc) {
    case config_t::ENTRY_WIDTH_ENCODING_PROTECTED:
        if (offset_enc != 0) {
            return LA_STATUS_EINVAL;
        }

        return write_protected_entry(sram_line, value);

    case config_t::ENTRY_WIDTH_ENCODING_WIDE:
        // MSB of the offset encoding should be 0
        if ((offset_enc >> 1) != 0) {
            return LA_STATUS_EINVAL;
        }

        return write_partial_entry(
            0x00 /*wide entry encoding*/, widths.wide_width, sram_line, offset_enc * widths.wide_width, value);

    case config_t::ENTRY_WIDTH_ENCODING_NARROW:

        return write_partial_entry(
            0x01 /*narrow entry encoding*/, widths.narrow_width, sram_line, offset_enc * widths.narrow_width, value);

    default:
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

size_t
resolution_lp_sram::max_size() const
{
    return m_size;
}

} // namespace silicon_one
