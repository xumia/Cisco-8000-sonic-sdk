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

#ifndef __RA_TABLE_INIT_HELPER_H__
#define __RA_TABLE_INIT_HELPER_H__

#include "common/defines.h"
#include "em_utils.h"
#include "hw_tables/hw_tables_fwd.h"
#include "hw_tables/lpm_types.h"
#include "lld/pacific_mem_structs.h"
#include "ra_translator_creator.h"

namespace silicon_one
{

namespace ra
{

/// @file Implementations of NPL Table initialization functional objects.
/// Implemented by partial template specializations per table type and particular implementations for special tables.
///

/// @brief General template class for table initialization per table type (direct, em, ternary or lpm).
/// This implementation should be never used, since it's overriden by partial specializations below.
///
template <class _Table, table_type_e _Type>
class table_init_helper
{
public:
    la_status init_table(_Table& table, ra_translator_creator& creator, const std::vector<size_t>& indices)
    {
        return LA_STATUS_SUCCESS;
    }
};

/// @brief Direct Table initialization functional object.
///
template <class _Table>
class table_init_helper<_Table, TABLE_TYPE_DIRECT>
{
public:
    la_status init_table(_Table& table, ra_translator_creator& creator, const std::vector<size_t>& indices)
    {
        typedef typename _Table::trait_type _Trait;
        typename _Table::table_translator_sptr_vec_t translator_vec;

        microcode_parser& parser = creator.get_microcode_parser();
        microcode_parser::translator_desc_vec_t desc_vec = parser.get_translator_descriptors(_Trait::get_table_name());

        // There are 2 types of tables without translator:
        // 1. Tables that the compiler statically didn't map.
        //    These tables will get empty translator.
        //
        // 2. Tables that are allocated for specific context, while their slice's context is dynamically configured to be different
        // context.
        //    These tables won't get any translator and we SDK never write to them.
        if (desc_vec.size() == 0) {
            log_warning(RA, "No placement found for ternary table %s", _Trait::get_table_name().c_str());
            translator_vec.push_back(std::make_shared<ra_empty_direct_translator<_Trait> >());
        }

        for (const microcode_parser::npl_table_translator_desc& desc : desc_vec) {
            std::unique_ptr<logical_sram> lsram = nullptr;

            std::vector<size_t> filtered_indices;
            la_status status = creator.filter_indices_by_npl_context(desc, indices, filtered_indices);
            return_on_error(status);

            if (filtered_indices.empty()) {
                continue;
            }

            if (desc.database_id == DATABASE_NATIVE_LP_SRAM) {
                // Native L2 and L3 LP, NH and CE_PTR
                lsram = creator.create_resolution_lp_sram(
                    desc, filtered_indices, resource_manager::RESOLUTION_LP_DB_NATIVE, _Trait::table_id);

            } else if (desc.database_id == DATABASE_PATH_LP_SRAM) {
                // Path LP
                lsram = creator.create_resolution_lp_sram(
                    desc, filtered_indices, resource_manager::RESOLUTION_LP_DB_PATH, _Trait::table_id);

            } else if (desc.database_id == DATABASE_MAC_SERVICE_LP_SRAM) {
                // Service LP attributes
                lsram = creator.create_service_lp_attribute_sram(desc, filtered_indices);

            } else {
                // Default case

                if (desc.translation_id == TRANSLATION_TYPE_EXACT) {
                    lsram = creator.create_memory_sram(desc, false /*no multival*/, filtered_indices);

                } else if (desc.translation_id == TRANSLATION_TYPE_MULTIVAL_SRAM) {
                    lsram = creator.create_memory_sram(desc, true /*multival*/, filtered_indices);

                } else if (desc.translation_id == TRANSLATION_TYPE_REG_SRAM) {
                    lsram = creator.create_register_array_sram(desc, false /*multival*/, filtered_indices);

                } else if (desc.translation_id == TRANSLATION_TYPE_MULTIVAL_REG) {
                    lsram = creator.create_register_array_sram(desc, true /*multival*/, filtered_indices);
                }
            }

            if (!lsram) {
                continue;
            }

            // Due to bug in entry_translators, only 0 replication returns results.
            size_t replication_idx = (desc.block_id > DATABASE_BLOCK_LAST_INTERNAL) ? 0 : desc.replication_idx;
            typename _Table::table_translator_sptr_t tr = std::make_shared<ra_direct_translator<_Trait> >(
                creator.get_ll_device(), desc.context_id, replication_idx, std::move(lsram));

            translator_vec.push_back(tr);
        }

        table.initialize(translator_vec);
        return LA_STATUS_SUCCESS;
    }
};

/// @brief Exact Match Table initialization functional object.
///
template <class _Table>
class table_init_helper<_Table, TABLE_TYPE_EM>
{
public:
    la_status init_table(_Table& table, ra_translator_creator& creator, const std::vector<size_t>& indices)
    {
        typedef typename _Table::trait_type _Trait;
        typename _Table::table_translator_sptr_vec_t translator_vec;

        bool has_network_slice = creator.has_network_slice();
        if (!has_network_slice) {
            table.initialize(translator_vec);
            return LA_STATUS_SUCCESS;
        }

        microcode_parser& parser = creator.get_microcode_parser();
        microcode_parser::translator_desc_vec_t desc_vec = parser.get_translator_descriptors(_Trait::get_table_name());

        // There are 2 types of tables without translator:
        // 1. Tables that the compiler statically didn't map.
        //    These tables will get empty translator.
        //
        // 2. Tables that are allocated for specific context, while their slice's context is dynamically configured to be different
        // context.
        //    These tables won't get any translator and we SDK never write to them.
        if (desc_vec.size() == 0) {
            log_warning(RA, "No placement found for em table %s", _Trait::get_table_name().c_str());
            translator_vec.push_back(std::make_shared<ra_empty_direct_translator<_Trait> >());
        }

        for (const microcode_parser::npl_table_translator_desc& desc : desc_vec) {
            logical_em_sptr em(nullptr);

            std::vector<size_t> filtered_indices;
            la_status status = creator.filter_indices_by_npl_context(desc, indices, filtered_indices);
            return_on_error(status);

            if (filtered_indices.empty()) {
                continue;
            }

            switch (desc.database_id) {
            case DATABASE_CENTRAL_EM:
                // CEM tables
                em = creator.create_cem_em(desc, filtered_indices);
                break;
            case DATABASE_TM_MC_EM:
                em = creator.create_mc_emdb_em(desc, filtered_indices);
                break;
            default:
                em = creator.create_em(desc, filtered_indices);
                break;
            }

            if (!em) {
                continue;
            }

            // Due to bug in entry_translators, only 0 replication returns results.
            size_t replication_idx = (desc.block_id > DATABASE_BLOCK_LAST_INTERNAL) ? 0 : desc.replication_idx;
            size_t em_key_width = em_utils::get_key_width(desc.database_id, desc.key_width, desc.payload_width);
            size_t em_payload_width = em_utils::get_payload_width(desc.database_id, desc.key_width, desc.payload_width);

            typename _Table::table_translator_sptr_t tr
                = std::make_shared<ra_em_translator<_Trait> >(creator.get_ll_device(),
                                                              desc.context_id,
                                                              replication_idx,
                                                              em,
                                                              em_key_width,
                                                              em_payload_width,
                                                              desc.application_specific_fields_width);
            translator_vec.push_back(tr);
        }

        table.initialize(translator_vec);
        return LA_STATUS_SUCCESS;
    }
};

/// @brief Ternary Table initialization functional object.
///
template <class _Table>
class table_init_helper<_Table, TABLE_TYPE_TERNARY>
{
public:
    la_status init_table(_Table& table, ra_translator_creator& creator, const std::vector<size_t>& indices)
    {
        typedef typename _Table::trait_type _Trait;
        typename _Table::table_translator_sptr_vec_t translator_vec;

        microcode_parser& parser = creator.get_microcode_parser();
        microcode_parser::translator_desc_vec_t desc_vec = parser.get_translator_descriptors(_Trait::get_table_name());

        // There are 2 types of tables without translator:
        // 1. Tables that the compiler statically didn't map.
        //    These tables will get empty translator.
        //
        // 2. Tables that are allocated for specific context, while their slice's context is dynamically configured to be different
        // context.
        //    These tables won't get any translator and we SDK never write to them.
        if (desc_vec.size() == 0) {
            log_warning(RA, "No placement found for ternary table %s", _Trait::get_table_name().c_str());
            translator_vec.push_back(std::make_shared<ra_empty_ternary_translator<_Trait> >());
        }

        for (const microcode_parser::npl_table_translator_desc& desc : desc_vec) {
            logical_tcam_sptr ltcam = nullptr;
            bool has_default_value = desc.has_default_value;

            std::vector<size_t> filtered_indices;
            la_status status = creator.filter_indices_by_npl_context(desc, indices, filtered_indices);
            return_on_error(status);

            if (filtered_indices.empty()) {
                continue;
            }

            if (desc.database_id == DATABASE_CENTRAL_TCAM) {
                if (!filtered_indices.empty()) {
                    ltcam = creator.create_ctm_tcam(_Trait::table_id, desc, filtered_indices);
                }
                if (!ltcam) {
                    // CTM - still unmapped
                    translator_vec.push_back(std::make_shared<ra_empty_ternary_translator<_Trait> >());
                } else {
                    // Central TCAM needs to add default value for each ctm tcam in order to resolve db merger hw issue
                    has_default_value = true;
                }
            } else {

                // Default case
                ltcam = creator.create_memory_tcam(desc, filtered_indices);
            }

            if (!ltcam) {
                continue;
            }

            // Due to bug in entry_translators, only 0 replication returns results.
            size_t replication_idx = (desc.block_id > DATABASE_BLOCK_LAST_INTERNAL) ? 0 : desc.replication_idx;
            typename _Table::table_translator_sptr_t tr
                = std::make_shared<ra_ternary_translator<_Trait> >(creator.get_ll_device(),
                                                                   desc.context_id,
                                                                   replication_idx,
                                                                   has_default_value,
                                                                   ltcam,
                                                                   creator.get_udk_translator_info(_Trait::table_id));

            translator_vec.push_back(tr);
        }

        table.initialize(translator_vec);
        return LA_STATUS_SUCCESS;
    }
};

/// @brief LPM initialization functional objects.
///
template <>
class table_init_helper<npl_ipv4_lpm_table_t, TABLE_TYPE_LPM>
{
public:
    static const size_t PREFIX_LEN = 11; // 11 bits for vrf ID
    static const lpm_ip_protocol_e IP_PROTOCOL = lpm_ip_protocol_e::IPV4;

    la_status init_table(npl_ipv4_lpm_table_t& table, ra_translator_creator& creator, const std::vector<size_t>& indices)
    {
        typename npl_ipv4_lpm_table_t::table_translator_sptr_vec_t translator_vec;

        // All LPM tables are global
        dassert_crit(indices.size() == 1);

        std::unique_ptr<lpm_db> db = creator.create_lpm_table(PREFIX_LEN, IP_PROTOCOL);
        dassert_crit(db);
        translator_vec.push_back(std::make_shared<ra_lpm_translator<npl_ipv4_lpm_table_t::trait_type> >(std::move(db)));
        table.initialize(translator_vec);

        return LA_STATUS_SUCCESS;
    }
};

template <>
class table_init_helper<npl_ipv6_lpm_table_t, TABLE_TYPE_LPM>
{
public:
    static const size_t PREFIX_LEN = 11; // 11 bits for vrf ID
    static const lpm_ip_protocol_e IP_PROTOCOL = lpm_ip_protocol_e::IPV6;

    la_status init_table(npl_ipv6_lpm_table_t& table, ra_translator_creator& creator, const std::vector<size_t>& indices)
    {
        typename npl_ipv6_lpm_table_t::table_translator_sptr_vec_t translator_vec;

        // All LPM tables are global
        dassert_crit(indices.size() == 1);

        std::unique_ptr<lpm_db> db = creator.create_lpm_table(PREFIX_LEN, IP_PROTOCOL);
        dassert_crit(db);
        translator_vec.push_back(std::make_shared<ra_lpm_translator<npl_ipv6_lpm_table_t::trait_type> >(std::move(db)));
        table.initialize(translator_vec);

        return LA_STATUS_SUCCESS;
    }
};

template <>
class table_init_helper<npl_ipv4_og_pcl_lpm_table_t, TABLE_TYPE_LPM>
{
public:
    static const size_t PREFIX_LEN = 11; // 11 bits for vrf ID
    static const lpm_ip_protocol_e IP_PROTOCOL = lpm_ip_protocol_e::IPV4;

    la_status init_table(npl_ipv4_og_pcl_lpm_table_t& table, ra_translator_creator& creator, const std::vector<size_t>& indices)
    {
        typename npl_ipv4_og_pcl_lpm_table_t::table_translator_sptr_vec_t translator_vec;

        // All LPM tables are global
        dassert_crit(indices.size() == 1);

        std::unique_ptr<lpm_db> db = creator.create_lpm_table(PREFIX_LEN, IP_PROTOCOL);
        dassert_crit(db);
        translator_vec.push_back(std::make_shared<ra_lpm_translator<npl_ipv4_og_pcl_lpm_table_t::trait_type> >(std::move(db)));
        table.initialize(translator_vec);

        return LA_STATUS_SUCCESS;
    }
};

template <>
class table_init_helper<npl_ipv6_og_pcl_lpm_table_t, TABLE_TYPE_LPM>
{
public:
    static const size_t PREFIX_LEN = 11; // 11 bits for vrf ID
    static const lpm_ip_protocol_e IP_PROTOCOL = lpm_ip_protocol_e::IPV6;

    la_status init_table(npl_ipv6_og_pcl_lpm_table_t& table, ra_translator_creator& creator, const std::vector<size_t>& indices)
    {
        typename npl_ipv6_og_pcl_lpm_table_t::table_translator_sptr_vec_t translator_vec;

        // All LPM tables are global
        dassert_crit(indices.size() == 1);

        std::unique_ptr<lpm_db> db = creator.create_lpm_table(PREFIX_LEN, IP_PROTOCOL);
        dassert_crit(db);
        translator_vec.push_back(std::make_shared<ra_lpm_translator<npl_ipv6_og_pcl_lpm_table_t::trait_type> >(std::move(db)));
        table.initialize(translator_vec);

        return LA_STATUS_SUCCESS;
    }
};

// Partial specializations
///////////////////////////////////

// EMPTY
//////////////////////////////////////////////////////////////
/*
template <>
class table_init_helper<npl_scaled_acl_key_type_select_compound_table_t, TABLE_TYPE_DIRECT>
{
public:
    la_status init_table(npl_scaled_acl_key_type_select_compound_table_t& table,
                           ra_translator_creator& creator,
                           const std::vector<size_t>& indices)
    {
        typedef npl_scaled_acl_key_type_select_compound_table_t _Table;
        typedef typename _Table::trait_type _Trait;
        typename _Table::table_translator_sptr_vec_t translator_vec;
        translator_vec.push_back(new ra_empty_direct_translator<_Trait>());
        table.initialize(translator_vec);
        return LA_STATUS_SUCCESS;
    }
};
*/
// Trap table
//////////////////////////////////////////////////////////////
template <class TABLE>
la_status
init_trap_table(TABLE& table, ra_translator_creator& creator, const std::vector<size_t>& indices, bool is_reversed)
{
    typedef TABLE _Table;
    typedef typename _Table::trait_type _Trait;
    typename _Table::table_translator_sptr_vec_t translator_vec;

    if ((indices.size() != (engine_block_mapper::ASIC_MAX_SLICES_PER_DEVICE_NUM + 1))
        && (indices.size() != engine_block_mapper::ASIC_MAX_SLICES_PER_DEVICE_NUM)) {
        // Trap/snoop tables should be initialized for all slices plus the npu host
        return LA_STATUS_ENOTINITIALIZED;
    }

    microcode_parser& parser = creator.get_microcode_parser();
    microcode_parser::translator_desc_vec_t desc_vec = parser.get_translator_descriptors(_Trait::get_table_name());

    for (const microcode_parser::npl_table_translator_desc& desc : desc_vec) {

        std::vector<size_t> filtered_indices;
        la_status status = creator.filter_indices_by_npl_context(desc, indices, filtered_indices);
        return_on_error(status);

        if (filtered_indices.empty()) {
            continue;
        }

        trap_tcam_sptr ttcam = creator.create_trap_tcam(desc, filtered_indices);
        if (!ttcam) {
            return LA_STATUS_ENOTINITIALIZED;
        }

        typename _Table::table_translator_sptr_t tr = std::make_shared<ra_trap_ternary_translator<_Trait> >(
            creator.get_ll_device(), desc.context_id, desc.replication_idx, ttcam, is_reversed);

        translator_vec.push_back(tr);
    }

    table.initialize(translator_vec);
    return LA_STATUS_SUCCESS;
}

template <>
class table_init_helper<npl_redirect_table_t, TABLE_TYPE_TERNARY>
{
public:
    la_status init_table(npl_redirect_table_t& table, ra_translator_creator& creator, const std::vector<size_t>& indices)
    {
        return init_trap_table(table, creator, indices, true /*is_reversed*/);
    }
};

template <>
class table_init_helper<npl_snoop_table_t, TABLE_TYPE_TERNARY>
{
public:
    la_status init_table(npl_snoop_table_t& table, ra_translator_creator& creator, const std::vector<size_t>& indices)
    {
        return init_trap_table(table, creator, indices, false /*is_reversed*/);
    }
};

// Loopback tables
//////////////////////////////////////////////////////////////

template <class _Table>
la_status
init_loopback_table(_Table& table, ra_translator_creator& creator, const std::vector<size_t>& indices)
{
    typedef typename _Table::trait_type _Trait;
    typename _Table::table_translator_sptr_vec_t translator_vec;

    for (auto index : indices) {
        std::unique_ptr<logical_sram> sram = creator.create_loopback_table(_Trait::table_id, index);
        typename _Table::table_translator_sptr_t tr = std::make_shared<ra_direct_translator<_Trait> >(
            creator.get_ll_device(), NPL_NONE_CONTEXT, 0 /*replication_idx*/, std::move(sram));
        translator_vec.push_back(tr);
    }

    dassert_crit(translator_vec.size());

    table.initialize(translator_vec);
    return LA_STATUS_SUCCESS;
}

template <>
class table_init_helper<npl_pma_loopback_table_t, TABLE_TYPE_DIRECT>
{
public:
    la_status init_table(npl_pma_loopback_table_t& table, ra_translator_creator& creator, const std::vector<size_t>& indices)
    {
        return init_loopback_table<npl_pma_loopback_table_t>(table, creator, indices);
    }
};

template <>
class table_init_helper<npl_mii_loopback_table_t, TABLE_TYPE_DIRECT>
{
public:
    la_status init_table(npl_mii_loopback_table_t& table, ra_translator_creator& creator, const std::vector<size_t>& indices)
    {
        return init_loopback_table<npl_mii_loopback_table_t>(table, creator, indices);
    }
};

// Specializations for some tables.
///////////////////////////////////

template <>
class table_init_helper<npl_ifgb_tc_lut_table_t, TABLE_TYPE_DIRECT>
{
public:
    la_status init_table(npl_ifgb_tc_lut_table_t& table, ra_translator_creator& creator, const std::vector<size_t>& indices);

private:
    enum {
        PHYSICAL_TABLE_KEY_WIDTH = 6,
        SERDES_PAIR_KEY_PART_WIDTH = 4,
        IFG_KEY_PART_WIDTH = 1,
        FULL_KEY_WIDTH = PHYSICAL_TABLE_KEY_WIDTH + SERDES_PAIR_KEY_PART_WIDTH + IFG_KEY_PART_WIDTH,
        PHYSICAL_TABLE_PAYLOAD_WIDTH = ifgb_tc_lut_mem_memory::SIZE_IN_BITS_WO_ECC,
    };
};

template <>
class table_init_helper<npl_rx_meter_rate_limiter_shaper_configuration_table_t, TABLE_TYPE_DIRECT>
{
public:
    la_status init_table(npl_rx_meter_rate_limiter_shaper_configuration_table_t& table,
                         ra_translator_creator& creator,
                         const std::vector<size_t>& indices);

private:
    enum {
        PORT_PACKET_INDEX_KEY_PART_WIDTH = 7,
        G_IFG_INDEX_KEY_PART_WIDTH = 4,
        FULL_KEY_WIDTH = PORT_PACKET_INDEX_KEY_PART_WIDTH + G_IFG_INDEX_KEY_PART_WIDTH,
        PHYSICAL_TABLE_PAYLOAD_WIDTH = rx_meter_rate_limiter_shaper_configuration_table_memory::SIZE_IN_BITS_WO_ECC,
    };
};
// Factory-dispatcher for template partial specializations
///////////////////////////////////

template <class _Table>
la_status
init_table(_Table& table, translator_creator& creator, const std::vector<size_t>& indices)
{
    table_init_helper<_Table, _Table::trait_type::table_type> helper;
    ra_translator_creator& ra_creator = static_cast<ra_translator_creator&>(creator);

    la_status ret = helper.init_table(table, ra_creator, indices);

    return ret;
}

}; // namespace ra

} // namespace silicon_one

#endif // __RA_TABLE_INIT_HELPER_H__
