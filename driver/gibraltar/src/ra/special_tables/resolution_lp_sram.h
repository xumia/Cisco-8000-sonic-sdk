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

#ifndef __RESOLUTION_LP_SRAM_H__
#define __RESOLUTION_LP_SRAM_H__

#include "lld/ll_device.h"
#include "lld/lld_fwd.h"

#include "hw_tables/logical_sram.h"
#include "hw_tables/physical_locations.h"

namespace silicon_one
{

class lld_memory;

/// @brief Static configuration of native_l2_and_l3_lp.
///
/// TODO: for now, the configuration is hard coded set to the default option.
class resolution_lp_config
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    enum {
        ENTRY_WIDTH_ENCODING_NUM_BITS = 2, ///< Number of MSB bits, where width option is encoded.
        MASK_SHIFT = 12,                   ///< Initial bit of key mask.
        BASE_ADDRESS_GRANULARITY = 1024,   ///< Granulariy of base address offset.
    };

    // TODO - this should be syncronized with NPL
    enum entry_width_encoding_e {
        ENTRY_WIDTH_ENCODING_NARROW,
        ENTRY_WIDTH_ENCODING_PROTECTED,
        ENTRY_WIDTH_ENCODING_WIDE,
    };

public:
    /// @brief Entry widths
    struct entry_widths {
        size_t sram_width;
        size_t protected_width;
        size_t wide_width;
        size_t narrow_width;
    };

    struct table_record {
        size_t table_id;            ///< Table ID
        size_t hw_key_prefix;       ///< HW key prefix
        size_t hw_key_prefix_width; ///< HW key prefix width in bits.
        size_t base;                ///< Table start line in 1k granularity
        size_t mask;                ///< Key mask, for the bits [17:12]
        size_t shift;               ///< Number of LSB bits to define record offset within memory line.
    };

    using table_record_sptr = std::shared_ptr<table_record>;
    using table_record_scptr = std::shared_ptr<const table_record>;
    using table_record_wptr = weak_ptr_unsafe<table_record>;
    using table_record_wcptr = weak_ptr_unsafe<const table_record>;

    resolution_lp_config() = default; // For serialization purposes only.

    /// @brief C'tor
    ///
    /// @param[in]  config_mems         List of configuration memory instances.
    /// @param[in]  widths              List of entry widths.
    /// @param[in]  base_width          Width of base field.
    /// @param[in]  mask_widh           Width of mask field.
    resolution_lp_config(const std::vector<lld_memory_scptr>& config_mems,
                         const entry_widths& widths,
                         size_t base_width,
                         size_t mask_width);

    /// @brief Return table data given table ID.
    ///
    /// @param[in]  table_id             NPL table ID.
    ///
    /// @retval     table data.
    const table_record_wcptr get_table_record(size_t table_id) const;

    /// @brief Write Database configuration to the device.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    ///
    /// @retval     status code.
    la_status configure_hw(const ll_device_sptr& ldevice) const;

    /// @brief Add NPL table to the database.
    ///
    /// @param[in]  table_id                NPL table ID.
    /// @param[in]  hw_key_prefix           Logical Table ID, which is added as a prefix to the key.
    /// @param[in]  hw_key_prefix_width     Width in bits of Logical Table ID.
    /// @param[in]  base                    Start line of the table within the database in 1k granularity.
    /// @param[in]  mask                    Key mask, for the bits [17:12] for tables with narrower than 18 bits keys.
    /// @param[in]  shift                   Number of key LSB, to represent entry type and not address.
    void add_table(size_t table_id, size_t hw_key_prefix, size_t hw_key_prefix_width, size_t base, size_t mask, size_t shift);

    /// @brief Return entry widths.
    ///
    /// @retval entry widhts.
    const entry_widths& get_widths() const;

private:
    std::vector<lld_memory_scptr> m_config_mems;
    entry_widths m_widths;
    std::vector<table_record_sptr> m_tables;
    size_t m_base_width;
    size_t m_mask_width;
};

/// @brief Sram Interface implementation.
///
/// Implementing Native L2 and L3 LP database, which is special due to following reasons:
/// 1. It hosts four tables (l2_lp, l3_lp, nh and ce_ptr),  which divide the database according to pre-defined configuration.
/// 2. Database can store records in 3 sizes. The size of the inserted record is determined by payload encoding.
/// 3. There is a configuration table, which stores, per table type (prefix):
///     - BASE - start line, in 1k granularity. Example, BASE = 2 means that table starts at line 2k.
///     - SHIFT - number of LSB bits in a key, to define record offset in line (up to 2 bits).
///     - MASK - mask on a key MSB, to define max key size (up to 6 bits).
///
/// Key Structure
/// ====================
/// 0. HW key width is 20 bits, where 2-5 MSB are allocated to table prefix (prefixes are Haffman coded).
/// 1. Table key width is up to 18 bits (depends on the prefix size).
/// 2. 6 MSB can be masked by configuration table, enabling keys 12-18 bits.
/// 3. Up to 2 LSB bits encode offset of the entry in memory line (for entries 1/2 line and 1/4 line)
///     Number of bits in offset encoding is defined by SHIFT field in configuration registers.
///     - wide entry - LSB defines offset (0 or 1). If SHIFT = 2, LSB+1 is "don't care" bit.
///     - narrow entry - 2 LSB define offset (0, 1, 2, 3).
/// 4. Line to write record is determined by following formula ((key & {MASK,0xFFF}) >> SHIFT) + BASE*1k.
///
/// Value Structure
/// ====================
/// 1. MSB defines whether the line is protected.
///     1 - line contains protected record, whole line wide
///     0 - line contains wide (1/2 line) or narrow (1/4 line) records
/// 2. MSB-1 defines whether the line contains wide or narrow records
///     0 - wide records (1/2 line)
///     1 - narrow records (1/4 line)
///
class resolution_lp_sram : public logical_sram
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    typedef resolution_lp_config config_t;

    /// @brief C'tor
    ///
    /// @param[in]  ldevice             Pointer to low level device.
    /// @param[in]  srams               native_l2_and_l2_lp sram.
    /// @param[in]  config              native_l2_and_l2_lp config.
    /// @param[in]  table_id            Table identifier (prefix) within the database.
    resolution_lp_sram(const ll_device_sptr& ldevice,
                       const std::vector<lld_memory_scptr>& srams,
                       const config_t* config,
                       size_t table_id);

    /// Logical SRAM API
    virtual la_status write(size_t line, const bit_vector& value);
    virtual size_t max_size() const;

private:
    resolution_lp_sram() = default; // For serialization purposes only.

    // Line encoding helpers
    size_t get_offset_encoding(const config_t::table_record_wcptr& rec, size_t line) const;
    size_t get_sram_line(const config_t::table_record_wcptr& rec, size_t line) const;

    // HW writing helpers
    la_status write_to_sram(size_t sram_line, const bit_vector& value);
    la_status write_protected_entry(size_t sram_line, const bit_vector& value);
    la_status write_partial_entry(size_t width_encoding,
                                  size_t record_width,
                                  size_t sram_line,
                                  size_t offset,
                                  const bit_vector& value);

private:
    // Pointer to low level device.
    ll_device_sptr m_ll_device;

    // native_l2_and_l2_lp sram replications.
    std::vector<lld_memory_scptr> m_srams;

    // Table ID.
    size_t m_table_id;

    // Database config
    config_t m_config;

    // SRAM size (lines)
    size_t m_size;
};

} // namespace silicon_one

#endif // __RESOLUTION_LP_SRAM_H__
