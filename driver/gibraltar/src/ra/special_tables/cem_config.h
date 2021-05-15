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

#ifndef __CEM_CONFIG_H__
#define __CEM_CONFIG_H__

#include "common/bit_vector.h"
#include "common/la_status.h"
#include "hw_tables/cem.h"

#include "lld/lld_register.h"

#include <vector>

namespace silicon_one
{

class ll_device;

/// @brief Static configuration of Central Exact Match.
///
/// The following configurations are done:
/// 1. CEM tables are registered into EM database (key size option).
/// 2. Updated core-group mapping - for now all groups go to core0.
/// 3. Bubble is set to 200 cycles, auto-bubble on.
/// 4. Active banks are set to 0xff00 means that 8 LSB banks are assigned to LPM.
/// 5. RC5 seed is set.

class cem_config
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    struct table_record;
    CEREAL_SUPPORT_PRIVATE_CLASS(table_record)

public:
    enum {
        CEM_KEY_WIDTH_OPT_46 = 2,  ///< Small key width option, payload width = 64
        CEM_KEY_WIDTH_OPT_78 = 1,  ///< Medium key width option, payload width = 32
        CEM_KEY_WIDTH_OPT_142 = 0, ///< Large key width option, consuming 2 banks, payload width = 64
    };

    enum {
        EM_NEW_MAX_AGE = 7,                   ///< Max age for new record from owner device
        EM_NO_AGING_AGE = EM_NEW_MAX_AGE - 1, ///< No-aging value static records coming from CPU
        EM_REFRESH_AGE = EM_NEW_MAX_AGE - 2   ///< Refresh age - next value after MAX_AGE
    };

    // C'tor
    cem_config(const ll_device_sptr& ldevice);

    /// @brief Write Database configuration to the device.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    ///
    /// @retval     status code.
    la_status configure_hw(const ll_device_sptr& ldevice) const;

    /// @brief Add NPL table to the database.
    ///
    /// @param[in]  table_id                NPL table ID.
    /// @param[in]  logical_id              Logical Table ID.
    /// @param[in]  logical_id_width        Width in bits of Logical Table ID.
    /// @param[in]  cem_key_width_option    Key width option for CEM.
    void add_table(size_t table_id, size_t logical_id, size_t logical_id_width, size_t key_width_option);

    /// @brief Return active banks.
    ///
    /// @retval     bit_vector representing which banks out of 16 are allocated to CEM.
    bit_vector get_active_banks() const;

private:
    cem_config() : m_cem_parameters{}
    {
    }

    template <class CDB_CORE>
    la_status write_cdb_core_config(const ll_device_sptr& ldevice, const CDB_CORE& core, const bit_vector& key_width_reg) const;

    la_status set_rc5_seed(const ll_device_sptr& ldevice, const lld_register_array_sptr& em_hash_reg) const;

    cem::cem_parameters empty_params()
    {
        const cem::cem_parameters params
            = {.num_banks = 0, .num_even_banks = 0, .banks_configuration = 0, .cem_arc_cpu_register_start_addr = 0};
        return params;
    }

private:
    struct table_record {
        size_t table_id;         ///< Table ID
        size_t logical_id;       ///< Logical Table ID.
        size_t logical_id_width; ///< Logical Table ID width.
        size_t key_width_option; ///< Key width option. In CEM it depends on key width and payload width.
    };

    std::vector<table_record> m_tables;

    const cem::cem_parameters m_cem_parameters;
};

} // namespace silicon_one

#endif // __CEM_CONFIG_H__
