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

#ifndef __PHYSICAL_LOCATIONS_H__
#define __PHYSICAL_LOCATIONS_H__

#include "lld/lld_memory.h"
#include "lld/lld_register.h"

namespace silicon_one
{

/// @brief Physical Exact Match.
///
/// Exact Match structure, including SRAM banks, cofiguration registers and overflow CAM.
/// All memory and register arrays are itemized.
/// Physical location cannot contain HW replications since it's assigned 1:1
/// to the logical EM core.
///
/// Exact Match Core Structure
/// ====================
/// Each Exact Match Core is constructed from LBR template and have the same structure and naming.
/// The relevant components are as following:
///
/// - EM Configuration Register (register per EM). Name: <ExactMatchName>_PER_EM_REG
///   Register layout:
///   0                   16 or 32               + 1                + 16
///   +--------------------+---------------------+---------------------+
///   | key_width_config   | auto bubble         | bubble_threshold    |
///   +--------------------+---------------------+---------------------+
///     - <key_width_config> field contains 16 1-bit or 2-bit values, depends on number of different key widths, the current EM
///     supports. Each field holds the value for a single logical table, means that single EM can host up to 16 logical tables
///
/// - Bank Configuration Register array (register per bank). Name: <ExactMatchName>_PER_BANK_REG
///   Register layout:
///   0               1                   + 2*key_width          + 1
///   +---------------+---------------------+---------------------+
///   | active_bank   | RC5 hash key        | primitive_crc       |
///   +---------------+---------------------+---------------------+
///
/// - SRAM bank list to store the values. All banks have the same width and size. Name: <ExactMatchName>_VERIFIER
///
/// - Overflow CAM. Name: <ExactMatchName>_PER_BANK_REG
///   CAM layout:
///   0               key_width         + value_width            + 1
///   +---------------+---------------------+---------------------+
///   | key           | payload             | valid               |
///   +---------------+---------------------+---------------------+
struct physical_em {

    /// @brief Single bank.
    struct bank {
        lld_register_scptr config_reg; ///< Bank configuration register.
        lld_memory_scptr memory;       ///< Bank SRAM.
        bit_vector rc5;                ///< RC5 parameter for current bank.
        bool is_active;                ///< Whether the bank is active.
    };

    size_t data_width;                           ///< Data Width: Key + Payload,
    size_t ecc_width;                            ///< ECC width.
    size_t bank_size;                            ///< Number of entries per bank.
    size_t cam_size;                             ///< Number of entries in cam.
    size_t bank_width;                           ///< Bank width in bits.
    bool skip_ecc_calc;                          ///< Skip ECC calculation (calculated by HW)
    std::vector<lld_register_scptr> config_regs; ///< EM configuration register replications.
    std::vector<bank> banks;                     ///< Memory banks.
    std::vector<size_t> key_widths;              ///< Key widths, supported by EM.
    using em_line_config_t = std::vector<std::pair<size_t, size_t> >;
    em_line_config_t line_cfg;          ///< (Key width, payload width) pairs supported by EM
    std::vector<lld_memory_scptr> cams; ///< Sections of the overflow CAM.
};

/// @brief Register array SRAM.
///
/// Registers, implementing memory region while each register is treated as a single memory line.
/// For replicated registers, this contains all replications.
struct register_array {
    typedef std::vector<lld_register_scptr> memory_line_t;
    size_t entries_per_line;             ///< Number of data entries stored per register.
    size_t offset;                       ///< Address offset in bits.
    size_t width;                        ///< Width in bits.
    size_t size;                         ///< Number of fields in the resource.
    std::vector<memory_line_t> memories; ///< Physical replications.
};

/// @brief Register array SRAM section.
///
/// aggregation of multiple #register_array-s to create a wider SRAM.
/// Aggregated #register_array-s need to have matching number of lines.
struct register_array_section {
    size_t entries_per_line;           ///< Number of data entries stored per register.
    size_t width;                      ///< Width in bits.
    size_t size;                       ///< Total number of fields in the resource.
    std::vector<register_array> srams; ///< Physical replications.
};

/// @brief Physical SRAM.
///
/// Sub-region inside SRAM memory.
/// For replicated SRAM-s, this contains all replications.
struct physical_sram {
    size_t start_line;                      ///< Start memory line.
    size_t offset;                          ///< Address offset in bits.
    size_t width;                           ///< Width in bits.
    std::vector<lld_memory_scptr> memories; ///< Physical replications of SRAM instance.
};

/// @brief SRAM section.
///
/// Horizontal aggregation of multiple #physical_sram-s to create a wider SRAM.
/// Aggregated #physical_sram-s need to have matching number of lines.
struct sram_section {
    size_t size;                      ///< Number of lines in the range.
    size_t entries_per_line;          ///< Number of data entries stored per SRAM line.
    std::vector<physical_sram> srams; ///< Ordered list of partial SRAM lines.
    bool is_valid;                    ///< Valid indicator. This section should not be accessed if invalid.
};

///@brief Physical TCAM.
///
/// Sub-region inside TRAM memory.
/// For replicated TRAM-s, this contains all replications.
struct physical_tcam {
    size_t start_line;                      ///< Start memory line.
    size_t width;                           ///< Width in bits.
    std::vector<lld_memory_scptr> memories; ///< Physical replications of SRAM instance.
};

/// @brief TCAM section.
///
/// Horizontal aggregation of multiple #physical_sram-s and #physical_tcam-s to create ternary line.
/// Aggregated memories need to have matching number of lines.
struct tcam_section {
    size_t size;                      ///< Number of lines in the range.
    std::vector<physical_tcam> tcams; ///< Ordered list of partial TCAM lines.
    std::vector<physical_sram> srams; ///< Ordered list of partial SRAM lines.
};

} // namespace silicon_one

#endif // __PHYSICAL_LOCATIONS_H__
