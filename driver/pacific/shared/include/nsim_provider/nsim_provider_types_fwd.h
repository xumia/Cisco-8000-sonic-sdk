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

#ifndef __NSIM_PROVIDER_TYPES_H__
#define __NSIM_PROVIDER_TYPES_H__

#include <memory>

#include "common/cereal_utils.h"
#include "common/weak_ptr_unsafe.h"

namespace silicon_one
{
class nsim_provider;
using nsim_provider_sptr = std::shared_ptr<nsim_provider>;
using nsim_provider_scptr = std::shared_ptr<const nsim_provider>;
using nsim_provider_wptr = weak_ptr_unsafe<nsim_provider>;
using nsim_provider_wcptr = weak_ptr_unsafe<const nsim_provider>;

class device_simulator_server;
using device_simulator_server_sptr = std::shared_ptr<device_simulator_server>;
using device_simulator_server_scptr = std::shared_ptr<const device_simulator_server>;
using device_simulator_server_wptr = weak_ptr_unsafe<device_simulator_server>;
using device_simulator_server_wcptr = weak_ptr_unsafe<const device_simulator_server>;

class nsim_translator_command;
using nsim_translator_command_sptr = std::shared_ptr<nsim_translator_command>;
using nsim_translator_command_scptr = std::shared_ptr<const nsim_translator_command>;
using nsim_translator_command_wptr = weak_ptr_unsafe<nsim_translator_command>;
using nsim_translator_command_wcptr = weak_ptr_unsafe<const nsim_translator_command>;

class nsim_translator_creator;
using nsim_translator_creator_sptr = std::shared_ptr<nsim_translator_creator>;
using nsim_translator_creator_scptr = std::shared_ptr<const nsim_translator_creator>;
using nsim_translator_creator_wptr = weak_ptr_unsafe<nsim_translator_creator>;
using nsim_translator_creator_wcptr = weak_ptr_unsafe<const nsim_translator_creator>;

template <class _Trait>
class nsim_translator;
template <class _Trait>
using nsim_translator_sptr = std::shared_ptr<nsim_translator<_Trait> >;
template <class _Trait>
using nsim_translator_scptr = std::shared_ptr<const nsim_translator<_Trait> >;
template <class _Trait>
using nsim_translator_wptr = weak_ptr_unsafe<nsim_translator<_Trait> >;
template <class _Trait>
using nsim_translator_wcptr = weak_ptr_unsafe<const nsim_translator<_Trait> >;

template <class _Trait>
class nsim_lpm_translator;
template <class _Trait>
using nsim_lpm_translator_sptr = std::shared_ptr<nsim_lpm_translator<_Trait> >;
template <class _Trait>
using nsim_lpm_translator_scptr = std::shared_ptr<const nsim_lpm_translator<_Trait> >;
template <class _Trait>
using nsim_lpm_translator_wptr = weak_ptr_unsafe<nsim_lpm_translator<_Trait> >;
template <class _Trait>
using nsim_lpm_translator_wcptr = weak_ptr_unsafe<const nsim_lpm_translator<_Trait> >;

template <class _Trait>
class nsim_ternary_translator;
template <class _Trait>
using nsim_ternary_translator_sptr = std::shared_ptr<nsim_ternary_translator<_Trait> >;
template <class _Trait>
using nsim_ternary_translator_scptr = std::shared_ptr<const nsim_ternary_translator<_Trait> >;
template <class _Trait>
using nsim_ternary_translator_wptr = weak_ptr_unsafe<nsim_ternary_translator<_Trait> >;
template <class _Trait>
using nsim_ternary_translator_wcptr = weak_ptr_unsafe<const nsim_ternary_translator<_Trait> >;
}
#endif
