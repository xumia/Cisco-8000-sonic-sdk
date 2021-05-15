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

#ifndef __HW_TABLES_FWD_H__
#define __HW_TABLES_FWD_H__

#include "common/cereal_utils.h"
#include "common/weak_ptr_unsafe.h"

#include <memory>

namespace silicon_one
{

// Smart pointer definitions
class logical_lpm;
using logical_lpm_sptr = std::shared_ptr<logical_lpm>;
using logical_lpm_scptr = std::shared_ptr<const logical_lpm>;
using logical_lpm_wptr = weak_ptr_unsafe<logical_lpm>;
using logical_lpm_wcptr = weak_ptr_unsafe<const logical_lpm>;

class lpm_core;
using lpm_core_sptr = std::shared_ptr<lpm_core>;
using lpm_core_scptr = std::shared_ptr<const lpm_core>;
using lpm_core_wptr = weak_ptr_unsafe<lpm_core>;
using lpm_core_wcptr = weak_ptr_unsafe<const lpm_core>;

class bucketing_tree;
using bucketing_tree_sptr = std::shared_ptr<bucketing_tree>;
using bucketing_tree_scptr = std::shared_ptr<const bucketing_tree>;
using bucketing_tree_wptr = weak_ptr_unsafe<bucketing_tree>;
using bucketing_tree_wcptr = weak_ptr_unsafe<const bucketing_tree>;

class cem;
using cem_sptr = std::shared_ptr<cem>;
using cem_scptr = std::shared_ptr<const cem>;
using cem_wptr = weak_ptr_unsafe<cem>;
using cem_wcptr = weak_ptr_unsafe<const cem>;

class logical_em;
using logical_em_sptr = std::shared_ptr<logical_em>;
using logical_em_scptr = std::shared_ptr<const logical_em>;
using logical_em_wptr = weak_ptr_unsafe<logical_em>;
using logical_em_wcptr = weak_ptr_unsafe<const logical_em>;

class ctm_config;
using ctm_config_sptr = std::shared_ptr<ctm_config>;
using ctm_config_scptr = std::shared_ptr<const ctm_config>;
using ctm_config_wptr = weak_ptr_unsafe<ctm_config>;
using ctm_config_wcptr = weak_ptr_unsafe<const ctm_config>;

class em_core;
using em_core_sptr = std::shared_ptr<em_core>;
using em_core_scptr = std::shared_ptr<const em_core>;
using em_core_wptr = weak_ptr_unsafe<em_core>;
using em_core_wcptr = weak_ptr_unsafe<const em_core>;

class lpm_hw_writer_consistency_checker;
using lpm_hw_writer_consistency_checker_sptr = std::shared_ptr<lpm_hw_writer_consistency_checker>;
using lpm_hw_writer_consistency_checker_scptr = std::shared_ptr<const lpm_hw_writer_consistency_checker>;
using lpm_hw_writer_consistency_checker_wptr = weak_ptr_unsafe<lpm_hw_writer_consistency_checker>;
using lpm_hw_writer_consistency_checker_wcptr = weak_ptr_unsafe<const lpm_hw_writer_consistency_checker>;
}

#endif
