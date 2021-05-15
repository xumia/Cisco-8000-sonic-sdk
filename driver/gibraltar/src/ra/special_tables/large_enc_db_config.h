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

#ifndef __LARGE_ENC_DB_CONFIG_H__
#define __LARGE_ENC_DB_CONFIG_H__

#include "common/la_status.h"

#include "lld/lld_fwd.h"

#include <vector>

namespace silicon_one
{

/// @brief Static configuration of large_enc_db.
///
/// Structure of the database
/// ====================
/// The database is constructed from 4 EM cores.
/// Each core has two ports.
/// Bank sizes:
///     cores 0,3           4k entries.
///     cores 1,2           8k entries.
/// The ports are assigned to different slices, but same slice-pair, based on pre-set configuration.
/// It happens, that a slice is assigned to more than one core, constructing one large logical EM from the union of
/// banks. This poses a problem in insertion of the new records: the insertion algorithm should consider all banks, as equal.
/// Having naive insertion will create undesired over-utilization on the first banks in the list (simple insertion->relocating->CAM)
/// before attempting to insert to the second banks.
///
/// Note: since the database is sharing resources between slices in a slice-pair,
/// each table, defined on the database, must be defined per-slice-pair.
///
class large_enc_db_config
{
public:
    enum {
        NUM_EM_CORES = 4,                          ///< Number of EM cores.
        PORTS_PER_CORE = 2,                        ///< Ports per EM core.
        NUM_PORTS = NUM_EM_CORES * PORTS_PER_CORE, ///< Number ports.
        NUM_CONFIG_REGS = NUM_PORTS,               ///< Number of configuration registers to set EM core <-> slice relations.
        NUM_CONFIG_REG_ACCESSES = 6,               ///< Number of accesses that might be encoded
                                                   ///< in configuration register (max slice number).
    };

public:
    /// @brief Write Database configuration to the device.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    ///
    /// @retval     status code.
    la_status configure_hw(const ll_device_sptr& ldevice) const;

    /// @brief Return list of EM cores, assigned for the given slice pair.
    ///
    /// @param[in]  slice_pair_idx      Slice pair index.
    ///
    /// @retval     List of Large Encapsulation DB core indices (0-3).
    std::vector<size_t> get_em_cores(size_t slice_pair_idx) const;
};

} // namespace silicon_one

#endif // __LARGE_ENC_DB_CONFIG_H__
