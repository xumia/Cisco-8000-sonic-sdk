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

#ifndef __NPLAPI_FWD_H__
#define __NPLAPI_FWD_H__

#include "common/weak_ptr_unsafe.h"
#include <memory>

struct udk_translation_info;
using udk_translation_info_sptr = std::shared_ptr<udk_translation_info>;
using udk_translation_info_scptr = std::shared_ptr<const udk_translation_info>;

namespace silicon_one
{

class translator_creator;
using translator_creator_sptr = std::shared_ptr<translator_creator>;
using translator_creator_scptr = std::shared_ptr<const translator_creator>;
using translator_creator_wptr = weak_ptr_unsafe<translator_creator>;
using translator_creator_wcptr = weak_ptr_unsafe<const translator_creator>;
}

#endif
