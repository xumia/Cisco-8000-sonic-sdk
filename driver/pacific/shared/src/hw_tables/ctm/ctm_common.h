// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __CTM_COMMON_H__
#define __CTM_COMMON_H__

#include "common/allocator_wrapper.h"
#include "common/gen_utils.h"
#include <stddef.h>

namespace silicon_one
{

namespace ctm
{
static constexpr size_t IDX_INVAL = (size_t)-1;       ///< Invalid index.
static constexpr size_t MEM_IDX_INVAL = (size_t)-1;   ///< Invalid memory index.
static constexpr size_t CHANNEL_INVAL = (size_t)-1;   ///< Invalid channel index.
static constexpr size_t INTERFACE_INVAL = (size_t)-1; ///< Invalid interface index.
static constexpr size_t FREE_THRESHOLD
    = 5; ///< Threshold for the minumum free space left in group before trying to make more space.

enum {
    NUM_MEMS_PER_SUBRING = 12,                              ///< Number of TCAM/SRAM memories per subring per CDB core.
    NUM_RINGS = 8,                                          ///< Number of CDB TCAM rings.
    NUM_INTERFACES = 30,                                    ///< Total number of CTM interfaces.
    NUM_CHANNELS_PER_CORE = 5,                              ///< Number of key/result channels per core.
    NUM_INTERFACES_PER_SLICE = 5,                           ///< Number of interfaces per slice.
    NUM_SLICES = NUM_INTERFACES / NUM_INTERFACES_PER_SLICE, ///
    BANK_SIZE = 512,                                        ///< Size of ring bank.
    NUM_TCAMS_PER_SRAM = 2,                                 ///< TCAM size is 512, SRAM size is 1024. It's
                                                            ///< possible to map 2 TCAMs to the same SRAM
    TCAM_WIDTH_LPM = 40,                                    ///< Width of single bank of LPM TCAM,
    TCAM_WIDTH_ACL = 160,                                   ///< Width of single bank of ACL TCAM,
    SRAM_WIDTH = 32,                                        ///< Width of single bank of Associated SRAM,
};

enum ctm_dbm_res_chan_e {
    RES_CHAN_DBM0
    = NUM_RINGS * NUM_CHANNELS_PER_CORE, ///< HW defined numbers of DBM mergers (AKA priority decoders). Do not change.
    RES_CHAN_DBM1,
    RES_CHAN_DBM2,
    RES_CHAN_DBM3,
    NUM_DB_MERGERS = 4, ///< Number of Database mergers
};

/// @brief Tcam key size encoding.
/// The encoding match configuration register values.
enum key_size_e {
    KEY_SIZE_40b = 0,
    KEY_SIZE_80b = 1,
    KEY_SIZE_160b = 2,
    KEY_SIZE_320b = 3,
    KEY_SIZE_LAST = KEY_SIZE_320b,
    KEY_SIZE_INVALID,
};

/// @brief Ring slice interface encoding.
/// The encoding match HW definitions.
enum interface_e {
    INTERFACE_TERM = 0,
    INTERFACE_FWD0 = 1,
    INTERFACE_FWD1 = 2,
    INTERFACE_TX0 = 3,
    INTERFACE_TX1 = 4,
};

enum class num_srams { ONE_SRAM, TWO_SRAMS, NUM_SRAMS_INVAL };

struct group_desc {
    enum group_ifs_e {
        GROUP_IFS_TERM = 0,   // Encoding match HW definitions
        GROUP_IFS_FW0_NARROW, // Encoding match HW definitions
        GROUP_IFS_FW1_NARROW, // Encoding match HW definitions
        GROUP_IFS_TX0_NARROW, // Encoding match HW definitions
        GROUP_IFS_TX1_NARROW, // Encoding match HW definitions
        GROUP_IFS_FW_WIDE,
        GROUP_IFS_TX_WIDE,
        NUMBER_OF_GROUPS_IFS,
    };
    group_desc() : slice_idx(IDX_INVAL), interface(NUMBER_OF_GROUPS_IFS)
    {
    }
    group_desc(size_t _slice_id, group_ifs_e _interface) : slice_idx(_slice_id), interface(_interface)
    {
    }
    bool operator==(const group_desc& ref) const
    {
        return std::tie(slice_idx, interface) == std::tie(ref.slice_idx, ref.interface);
    }
    bool operator!=(const group_desc& ref) const
    {
        return std::tie(slice_idx, interface) != std::tie(ref.slice_idx, ref.interface);
    }

    bool operator<(const group_desc& ref) const
    {
        return std::tie(slice_idx, interface) < std::tie(ref.slice_idx, ref.interface);
    }

    bool is_wide() const
    {
        bool status = false;

        if (interface == GROUP_IFS_FW_WIDE || interface == GROUP_IFS_TX_WIDE) {
            status = true;
        }

        return status;
    }

    bool is_valid() const
    {
        return slice_idx != IDX_INVAL;
    }

    size_t slice_idx;
    group_ifs_e interface;
};

struct table_desc {
    table_desc() : slice_id(0), table_id(0)
    {
    }
    table_desc(size_t _slice_id, size_t _table_id) : slice_id(_slice_id), table_id(_table_id)
    {
    }
    bool operator==(const table_desc& ref) const
    {
        return std::tie(slice_id, table_id) == std::tie(ref.slice_id, ref.table_id);
    }

    bool operator<(const table_desc& ref) const
    {
        return std::tie(slice_id, table_id) < std::tie(ref.slice_id, ref.table_id);
    }

    size_t slice_id;
    size_t table_id;
};

/// @brief ifs slice data descriptor to map between slice interface (in) to key channel.
struct slice_interface_input_desc {
    size_t slice_id;        ///< Assigned slice (0-5)
    size_t input_interface; ///< Assigned input slice interface (0-4)
};

/// @brief ifs slice data descriptor to map between result channel to slice interface (out).
struct slice_interface_out_desc {
    size_t cdb_core_idx;   ///< CDB ring index (0-7)
    size_t result_channel; ///< SRAM result channel (0-4)
};

}; // namespace ctm

}; // namespace silicon_one

#endif // __CTM_COMMON_H__
