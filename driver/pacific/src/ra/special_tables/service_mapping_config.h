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

#ifndef __SERVICE_MAPPING_CONFIG_H__
#define __SERVICE_MAPPING_CONFIG_H__

#include "lld/ll_device.h"
#include "lld/lld_fwd.h"

#include "hw_tables/physical_locations.h"

namespace silicon_one
{

class em_hasher;

/// @brief Static configuration of databases service_mapping0 and sevice_mapping1.
///
/// Structure
/// ====================
/// The database is instantantiated for two keys service_mapping0 and service_mapping1.
/// There are 8 EM cores in each instantiation. A slice is assigned to one core for key0 and one core for key1, allowing two
/// accesses per cycle.
///
/// Each instantiation is sharing acccess to the banks for the same core id,
/// i.e. core0 in service_mapping0 is sharing banks with core0 in service_mapping1.
/// "Shared banks" means that only one of the cores is having access to the bank, according to a pre-set configuration.
/// This is done by assigning inverse values into per_bank register's active_bank bitfield.
///
/// All banks have the same size (4k lines), but the number of banks per set varies per core:
/// Bank number:
///     cores 0,3,4,7     4 banks (small cores).
///     cores 1,2,5,6     8 banks (large cores).
///
///
/// Example:
/// - EM core0[0] is assigned to banks 0-1
///     - per-bank registers 0, 1 -> active_bank = 1
///     - per-bank registers 2, 3 -> active_bank = 0
/// - EM core0[1] is assigned to banks 2-3
///     - per-bank registers 4, 5 -> active_bank = 0
///     - per-bank registers 6, 7 -> active_bank = 1
///
///  --------- EM core0[0] --------------- CAM0[0]
///     |       |
///     0       1       2       3
///     |       |
///    bank0   bank1   bank2   bank3
///                     |       |
///     4       5       6       7
///                     |       |
///  --------- EM core0[1] --------------- CAM0[1]

class service_mapping_config
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    enum {
        NUM_PORTS = 2,                              ///< Number of ports/accesses per slice (service_mapping0 or service_mapping1).
        NUM_EM_CORES = 8,                           ///< Number of EM cores per each port.
        NUM_SMALL_EM_CORE_BANKS = 4,                ///< Number of banks in small em core (0,3,4,7).
        NUM_LARGE_EM_CORE_BANKS = 8,                ///< Number of banks in large em core (1,2,5,6).
        NUM_CONFIG_REGS = NUM_EM_CORES * NUM_PORTS, ///< Number of configuration registers to set EM core <-> slice/port relations.
        NUM_CONFIG_REG_ACCESSES = 12                ///< Number of accesses that might be encoded
                                                    ///< in configuration register (slice number (6) X port per slice (2))
    };

public:
    service_mapping_config(); // For serialization purposes only.

    /// @brief Write Database configuration to the device.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    ///
    /// @retval     status code.
    la_status configure_hw(const ll_device_sptr& ldevice) const;

    /// @brief Return list of EM cores, assigned for the given slice (for both.
    ///
    /// @param[in]  slice_idx           Slice index.
    ///
    /// @retval     List of Large Encapsulation DB core indices (0-3).
    std::vector<size_t> get_em_cores(size_t slice_idx) const;

    /// @brief Return bitset of active EM banks for given core and key ID
    ///
    /// @param[in]  em_core             EM core index (0-7).
    /// @param[in]  port_idx            Port ID (0-1) for service_mapping0 or service_mapping1
    ///
    /// @retval     Bitset of available banks. Bitset width is the number of banks
    ///             bit i=1 means bank i is active; i=0 means bank is not active.
    bit_vector get_active_banks(size_t em_core, size_t port_idx) const;

public:
    // Initialize active banks for EM cores/keys
    void init_active_banks();

private:
    // Bitset of active banks for port0 assingment.
    // For port1 active banks are inversed.
    bit_vector m_active_banks[NUM_EM_CORES];
};

} // namespace silicon_one

#endif // __SERVICE_MAPPING_CONFIG_H__
