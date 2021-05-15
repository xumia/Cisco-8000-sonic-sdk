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

#ifndef __LLD_LLD_FWD_H__
#define __LLD_LLD_FWD_H__

#include <memory>

#include "common/cereal_utils.h"
#include "common/weak_ptr_unsafe.h"

namespace silicon_one
{

class ll_device;
using ll_device_sptr = std::shared_ptr<ll_device>;
using ll_device_wptr = weak_ptr_unsafe<ll_device>;

class lld_block;
using lld_block_sptr = std::shared_ptr<lld_block>;
using lld_block_wptr = weak_ptr_unsafe<lld_block>;
using lld_block_scptr = std::shared_ptr<const lld_block>;
using lld_block_wcptr = weak_ptr_unsafe<const lld_block>;

class lld_memory;
using lld_memory_sptr = std::shared_ptr<lld_memory>;
using lld_memory_scptr = std::shared_ptr<const lld_memory>;

class lld_memory_array_container;
using lld_memory_array_sptr = std::shared_ptr<lld_memory_array_container>;
using lld_memory_array_scptr = std::shared_ptr<const lld_memory_array_container>;

class lld_register;
using lld_register_sptr = std::shared_ptr<lld_register>;
using lld_register_scptr = std::shared_ptr<const lld_register>;

class lld_register_array_container;
using lld_register_array_sptr = std::shared_ptr<lld_register_array_container>;
using lld_register_array_scptr = std::shared_ptr<const lld_register_array_container>;

class lld_storage;
using lld_storage_sptr = std::shared_ptr<lld_storage>;
using lld_storage_scptr = std::shared_ptr<const lld_storage>;

class pacific_tree;
using pacific_tree_scptr = std::shared_ptr<const pacific_tree>;
using pacific_tree_wcptr = weak_ptr_unsafe<const pacific_tree>;

class gibraltar_tree;
using gibraltar_tree_scptr = std::shared_ptr<const gibraltar_tree>;
using gibraltar_tree_wcptr = weak_ptr_unsafe<const gibraltar_tree>;

class asic4_tree;
using asic4_tree_scptr = std::shared_ptr<const asic4_tree>;
using asic4_tree_wcptr = weak_ptr_unsafe<const asic4_tree>;

class asic3_tree;
using asic3_tree_scptr = std::shared_ptr<const asic3_tree>;
using asic3_tree_wcptr = weak_ptr_unsafe<const asic3_tree>;

class asic5_tree;
using asic5_tree_scptr = std::shared_ptr<const asic5_tree>;
using asic5_tree_wcptr = weak_ptr_unsafe<const asic5_tree>;

class interrupt_tree;
using interrupt_tree_sptr = std::shared_ptr<interrupt_tree>;
using interrupt_tree_scptr = std::shared_ptr<const interrupt_tree>;
using interrupt_tree_wptr = weak_ptr_unsafe<interrupt_tree>;

class ll_device_context;
using ll_device_context_sptr = std::shared_ptr<ll_device_context>;

class d2d_iface;
using d2d_iface_sptr = std::shared_ptr<d2d_iface>;
};

#endif
