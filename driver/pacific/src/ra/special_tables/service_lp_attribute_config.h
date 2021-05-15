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

#ifndef __SERVICE_LP_ATTRIBUTE_CONFIG_H__
#define __SERVICE_LP_ATTRIBUTE_CONFIG_H__

#include "common/la_status.h"
#include "lld/lld_fwd.h"

#include <vector>

namespace silicon_one
{

class ll_device;
class lld_register;

/// @brief Static configuration of service_lp_attribute database.
///
/// Structure of the database
/// ====================
/// The database consists of 4 SRAM cores. The size of the cores is 16K, 32k, 32k, 16k.
/// The cores are assigned to slice-pairs, according to a pre-defined configuration, which is set via configuration register.
/// Each core has 2 ports, while each port is assigned to a different slice, within the same slice-pair.
///
/// The database allows creating logical SRAM of up to 64k entries (16 bits key).
/// Two MSB [15-14] are an encoding of the core ID + 16k offset within 32k cores, translated from the configuration register.
/// The input configuration must ensure that table lines (key) create continuum of SRAM entries.
///
class service_lp_attribute_config
{
public:
    static const size_t IDX_NOVAL = 0xff;

    enum {
        NUM_CORES = 4,            ///< Number of SRAM cores.
        PORTS_PER_CORE = 2,       ///< Ports per SRAM core.
        NUM_CONFIG_REGS = 6,      ///< Number of config registers in array.
        SECTION_SIZE = (1 << 14), ///< Section size: 16k
    };

public:
    /// @brief Write Database configuration to the device.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    ///
    /// @retval     status code.
    la_status configure_hw(const ll_device_sptr& ldevice) const;

    /// @brief Returns SRAM core index for the provided slice pair and section index.
    ///
    /// @param[in]  slice_pair_idx      Slice pair index (0-2)
    /// @param[in]  idx                 Index of 16k section in SRAM collection (0-3).
    ///                                 If the SRAM core is 32k, two subsequent indices return the same core index.
    ///                                 Each slice can be assigned to up to 4 different sections (total 64k).
    ///
    /// @retval     core index (0-3) or IDX_NOVAL if section index is out-of range.
    size_t get_sram_core_idx(size_t slice_pair_idx, size_t idx) const;

    /// @brief Returns section start line for a given sram core and section index.
    ///
    /// @param[in]  sram_core_idx       Sram core index (0-3).
    /// @param[in]  section_idx         Index of 16k section in SRAM collection (0-3).
    ///
    /// @retval    start line within the SRAM core.
    size_t get_section_start_line(size_t sram_core_idx, size_t section_idx) const;

private:
    /// @brief Return SRAM core size.
    size_t get_core_size(size_t core_idx) const;

    /// @brief Return port index (two ports per SRAM core) which is assigned to the slice/section.
    size_t get_sram_core_port_idx(size_t slice_idx, size_t idx) const;
};

} // namespace silicon_one

#endif // __SERVICE_LP_ATTRIBUTE_CONFIG_H__
