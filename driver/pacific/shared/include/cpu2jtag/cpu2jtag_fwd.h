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

#ifndef __HLD_CPU2JTAG_FWD_H__
#define __HLD_CPU2JTAG_FWD_H__

#include "common/cereal_utils.h"
#include "common/weak_ptr_unsafe.h"

// Smart pointer definitions
namespace silicon_one
{

class cpu2jtag;
using cpu2jtag_sptr = std::shared_ptr<cpu2jtag>;
using cpu2jtag_scptr = std::shared_ptr<const cpu2jtag>;
using cpu2jtag_wptr = weak_ptr_unsafe<cpu2jtag>;
using cpu2jtag_wcptr = weak_ptr_unsafe<const cpu2jtag>;
}

#endif
