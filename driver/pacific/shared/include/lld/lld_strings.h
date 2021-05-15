// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LLD_STRINGS_H__
#define __LLD_STRINGS_H__

#include "lld/interrupt_types.h"
#include "lld/lld_init_expression.h"
#include "lld/lld_memory.h"

/// @file
/// @brief LLD structs/enums to strings definitions.

namespace silicon_one
{

/// @brief Return lld_memory_type_e as string.
std::string to_string(lld_memory_type_e memory_type);

/// @brief Return lld_memory_subtype_e as string.
std::string to_string(lld_memory_subtype_e memory_subtype);

/// @brief Return lld_memory_protection_e as string.
std::string to_string(lld_memory_protection_e memory_protection);

/// @brief Return interrupt_type_e as string.
std::string to_string(interrupt_type_e interrupt_type);

/// @brief Return init_stage_e as string.
std::string to_string(init_stage_e init_stage);

/// @brief Return init_mode_e as string.
std::string to_string(init_expression_slice_mode_e init_mode);

} // namespace silicon_one

#endif /* __LLD_STRINGS_H__ */
