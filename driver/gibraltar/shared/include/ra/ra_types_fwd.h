// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __RA_TYPES_FWD__
#define __RA_TYPES_FWD__

#include <memory>

#include "common/cereal_utils.h"
#include "common/weak_ptr_unsafe.h"

namespace silicon_one
{

class lpm_config;
using lpm_config_sptr = std::shared_ptr<lpm_config>;
using lpm_config_scptr = std::shared_ptr<const lpm_config>;
using lpm_config_wptr = weak_ptr_unsafe<lpm_config>;
using lpm_config_wcptr = weak_ptr_unsafe<const lpm_config>;

class cem_config;
using cem_config_sptr = std::shared_ptr<cem_config>;
using cem_config_scptr = std::shared_ptr<const cem_config>;
using cem_config_wptr = weak_ptr_unsafe<cem_config>;
using cem_config_wcptr = weak_ptr_unsafe<const cem_config>;

class ctm_tcam_line_mgr;
using ctm_tcam_line_mgr_sptr = std::shared_ptr<ctm_tcam_line_mgr>;
using ctm_tcam_line_mgr_scptr = std::shared_ptr<const ctm_tcam_line_mgr>;
using ctm_tcam_line_mgr_wptr = weak_ptr_unsafe<ctm_tcam_line_mgr>;
using ctm_tcam_line_mgr_wcptr = weak_ptr_unsafe<const ctm_tcam_line_mgr>;

class large_enc_db_config;
using large_enc_db_config_sptr = std::shared_ptr<large_enc_db_config>;
using large_enc_db_config_scptr = std::shared_ptr<const large_enc_db_config>;
using large_enc_db_config_wptr = weak_ptr_unsafe<large_enc_db_config>;
using large_enc_db_config_wcptr = weak_ptr_unsafe<const large_enc_db_config>;

class loopback_table_sram;
using loopback_table_sram_sptr = std::shared_ptr<loopback_table_sram>;
using loopback_table_sram_scptr = std::shared_ptr<const loopback_table_sram>;
using loopback_table_sram_wptr = weak_ptr_unsafe<loopback_table_sram>;
using loopback_table_sram_wcptr = weak_ptr_unsafe<const loopback_table_sram>;

class resolution_lp_sram;
using resolution_lp_sram_sptr = std::shared_ptr<loopback_table_sram>;
using resolution_lp_sram_scptr = std::shared_ptr<const resolution_lp_sram>;
using resolution_lp_sram_wptr = weak_ptr_unsafe<resolution_lp_sram>;
using resolution_lp_sram_wcptr = weak_ptr_unsafe<const resolution_lp_sram>;

class resolution_lp_config;
using resolution_lp_config_sptr = std::shared_ptr<resolution_lp_config>;
using resolution_lp_config_scptr = std::shared_ptr<const resolution_lp_config>;
using resolution_lp_config_wptr = weak_ptr_unsafe<resolution_lp_config>;
using resolution_lp_config_wcptr = weak_ptr_unsafe<const resolution_lp_config>;

class mc_fe_links_bmp_sram_base;
using mc_fe_links_bmp_sram_base_sptr = std::shared_ptr<mc_fe_links_bmp_sram_base>;
using mc_fe_links_bmp_sram_base_scptr = std::shared_ptr<const mc_fe_links_bmp_sram_base>;
using mc_fe_links_bmp_sram_base_wptr = weak_ptr_unsafe<mc_fe_links_bmp_sram_base>;
using mc_fe_links_bmp_sram_base_wcptr = weak_ptr_unsafe<const mc_fe_links_bmp_sram_base>;

class mc_fe_links_bmp_sram;
using mc_fe_links_bmp_sram_sptr = std::shared_ptr<mc_fe_links_bmp_sram>;
using mc_fe_links_bmp_sram_scptr = std::shared_ptr<const mc_fe_links_bmp_sram>;
using mc_fe_links_bmp_sram_wptr = weak_ptr_unsafe<mc_fe_links_bmp_sram>;
using mc_fe_links_bmp_sram_wcptr = weak_ptr_unsafe<const mc_fe_links_bmp_sram>;

class trap_tcam;
using trap_tcam_sptr = std::shared_ptr<trap_tcam>;
using trap_tcam_scptr = std::shared_ptr<const trap_tcam>;
using trap_tcam_wptr = weak_ptr_unsafe<trap_tcam>;
using trap_tcam_wcptr = weak_ptr_unsafe<const trap_tcam>;

class mc_emdb;
using mc_emdb_sptr = std::shared_ptr<mc_emdb>;
using mc_emdb_scptr = std::shared_ptr<const mc_emdb>;
using mc_emdb_wptr = weak_ptr_unsafe<mc_emdb>;
using mc_emdb_wcptr = weak_ptr_unsafe<const mc_emdb>;

class lpm_db;
using lpm_db_sptr = std::shared_ptr<lpm_db>;
using lpm_db_scptr = std::shared_ptr<const lpm_db>;
using lpm_db_wptr = weak_ptr_unsafe<lpm_db>;
using lpm_db_wcptr = weak_ptr_unsafe<const lpm_db>;

class service_mapping_config;
using service_mapping_config_sptr = std::shared_ptr<service_mapping_config>;
using service_mapping_config_scptr = std::shared_ptr<const service_mapping_config>;
using service_mapping_config_wptr = weak_ptr_unsafe<service_mapping_config>;
using service_mapping_config_wcptr = weak_ptr_unsafe<const service_mapping_config>;

class cem_em;
using cem_em_sptr = std::shared_ptr<cem_em>;
using cem_em_scptr = std::shared_ptr<const cem_em>;
using cem_em_wptr = weak_ptr_unsafe<cem_em>;
using cem_em_wcptr = weak_ptr_unsafe<const cem_em>;

class microcode_parser;
using microcode_parser_sptr = std::shared_ptr<microcode_parser>;
using microcode_parser_scptr = std::shared_ptr<const microcode_parser>;
using microcode_parser_wptr = weak_ptr_unsafe<microcode_parser>;
using microcode_parser_wcptr = weak_ptr_unsafe<const microcode_parser>;

class engine_block_mapper;
using engine_block_mapper_sptr = std::shared_ptr<engine_block_mapper>;
using engine_block_mapper_scptr = std::shared_ptr<const engine_block_mapper>;
using engine_block_mapper_wptr = weak_ptr_unsafe<engine_block_mapper>;
using engine_block_mapper_wcptr = weak_ptr_unsafe<const engine_block_mapper>;

class service_lp_attribute_config;
using service_lp_attribute_config_sptr = std::shared_ptr<service_lp_attribute_config>;
using service_lp_attribute_config_scptr = std::shared_ptr<const service_lp_attribute_config>;
using service_lp_attribute_config_wptr = weak_ptr_unsafe<service_lp_attribute_config>;
using service_lp_attribute_config_wcptr = weak_ptr_unsafe<const service_lp_attribute_config>;

class resource_manager;
using resource_manager_sptr = std::shared_ptr<resource_manager>;
using resource_manager_scptr = std::shared_ptr<const resource_manager>;
using resource_manager_wptr = weak_ptr_unsafe<resource_manager>;
using resource_manager_wcptr = weak_ptr_unsafe<const resource_manager>;

class ra_translator_creator;
using ra_translator_creator_sptr = std::shared_ptr<ra_translator_creator>;
using ra_translator_creator_scptr = std::shared_ptr<const ra_translator_creator>;
using ra_translator_creator_wptr = weak_ptr_unsafe<ra_translator_creator>;
using ra_translator_creator_wcptr = weak_ptr_unsafe<const ra_translator_creator>;

class ctm_config;
using ctm_config_sptr = std::shared_ptr<ctm_config>;
using ctm_config_scptr = std::shared_ptr<const ctm_config>;
using ctm_config_wptr = weak_ptr_unsafe<ctm_config>;
using ctm_config_wcptr = weak_ptr_unsafe<const ctm_config>;

class ctm_mgr;
using ctm_mgr_sptr = std::shared_ptr<ctm_mgr>;
using ctm_mgr_scptr = std::shared_ptr<const ctm_mgr>;
using ctm_mgr_wptr = weak_ptr_unsafe<ctm_mgr>;
using ctm_mgr_wcptr = weak_ptr_unsafe<const ctm_mgr>;

class ctm_tcam;
using ctm_tcam_sptr = std::shared_ptr<ctm_tcam>;
using ctm_tcam_scptr = std::shared_ptr<const ctm_tcam>;
using ctm_tcam_wptr = weak_ptr_unsafe<ctm_tcam>;
using ctm_tcam_wcptr = weak_ptr_unsafe<const ctm_tcam>;

class ra_ternary_table_mapping;
using ra_ternary_table_mapping_sptr = std::shared_ptr<ra_ternary_table_mapping>;

template <class _Trait>
class ra_direct_translator;
template <class _Trait>
using ra_direct_translator_sptr = std::shared_ptr<ra_direct_translator<_Trait> >;
template <class _Trait>
using ra_direct_translator_scptr = std::shared_ptr<const ra_direct_translator<_Trait> >;
template <class _Trait>
using ra_direct_translator_wptr = weak_ptr_unsafe<ra_direct_translator<_Trait> >;
template <class _Trait>
using ra_direct_translator_wcptr = weak_ptr_unsafe<const ra_direct_translator<_Trait> >;

template <class _Trait>
class ra_ternary_translator;
template <class _Trait>
using ra_ternary_translator_sptr = std::shared_ptr<ra_ternary_translator<_Trait> >;
template <class _Trait>
using ra_ternary_translator_scptr = std::shared_ptr<const ra_ternary_translator<_Trait> >;
template <class _Trait>
using ra_ternary_translator_wptr = weak_ptr_unsafe<ra_ternary_translator<_Trait> >;
template <class _Trait>
using ra_ternary_translator_wcptr = weak_ptr_unsafe<const ra_ternary_translator<_Trait> >;

template <class _Trait>
class ra_trap_ternary_translator;
template <class _Trait>
using ra_trap_ternary_translator_sptr = std::shared_ptr<ra_trap_ternary_translator<_Trait> >;
template <class _Trait>
using ra_trap_ternary_translator_scptr = std::shared_ptr<const ra_trap_ternary_translator<_Trait> >;
template <class _Trait>
using ra_trap_ternary_translator_wptr = weak_ptr_unsafe<ra_trap_ternary_translator<_Trait> >;
template <class _Trait>
using ra_trap_ternary_translator_wcptr = weak_ptr_unsafe<const ra_trap_ternary_translator<_Trait> >;

template <class _Trait>
class ra_lpm_translator;
template <class _Trait>
using ra_lpm_translator_sptr = std::shared_ptr<ra_lpm_translator<_Trait> >;
template <class _Trait>
using ra_lpm_translator_scptr = std::shared_ptr<const ra_lpm_translator<_Trait> >;
template <class _Trait>
using ra_lpm_translator_wptr = weak_ptr_unsafe<ra_lpm_translator<_Trait> >;
template <class _Trait>
using ra_lpm_translator_wcptr = weak_ptr_unsafe<const ra_lpm_translator<_Trait> >;

template <class _Trait>
class ra_em_translator;
template <class _Trait>
using ra_em_translator_sptr = std::shared_ptr<ra_em_translator<_Trait> >;
template <class _Trait>
using ra_em_translator_scptr = std::shared_ptr<const ra_em_translator<_Trait> >;
template <class _Trait>
using ra_em_translator_wptr = weak_ptr_unsafe<ra_em_translator<_Trait> >;
template <class _Trait>
using ra_em_translator_wcptr = weak_ptr_unsafe<const ra_em_translator<_Trait> >;

template <class _Trait>
class ra_empty_direct_translator;
template <class _Trait>
using ra_empty_direct_translator_sptr = std::shared_ptr<ra_empty_direct_translator<_Trait> >;
template <class _Trait>
using ra_empty_direct_translator_scptr = std::shared_ptr<const ra_empty_direct_translator<_Trait> >;
template <class _Trait>
using ra_empty_direct_translator_wptr = weak_ptr_unsafe<ra_empty_direct_translator<_Trait> >;
template <class _Trait>
using ra_empty_direct_translator_wcptr = weak_ptr_unsafe<const ra_empty_direct_translator<_Trait> >;

template <class _Trait>
class ra_empty_lpm_translator;
template <class _Trait>
using ra_empty_lpm_translator_sptr = std::shared_ptr<ra_empty_lpm_translator<_Trait> >;
template <class _Trait>
using ra_empty_lpm_translator_scptr = std::shared_ptr<const ra_empty_lpm_translator<_Trait> >;
template <class _Trait>
using ra_empty_lpm_translator_wptr = weak_ptr_unsafe<ra_empty_lpm_translator<_Trait> >;
template <class _Trait>
using ra_empty_lpm_translator_wcptr = weak_ptr_unsafe<const ra_empty_lpm_translator<_Trait> >;

template <class _Trait>
class ra_empty_ternary_translator;
template <class _Trait>
using ra_empty_ternary_translator_sptr = std::shared_ptr<ra_empty_ternary_translator<_Trait> >;
template <class _Trait>
using ra_empty_ternary_translator_scptr = std::shared_ptr<const ra_empty_ternary_translator<_Trait> >;
template <class _Trait>
using ra_empty_ternary_translator_wptr = weak_ptr_unsafe<ra_empty_ternary_translator<_Trait> >;
template <class _Trait>
using ra_empty_ternary_translator_wcptr = weak_ptr_unsafe<const ra_empty_ternary_translator<_Trait> >;
}

#endif
