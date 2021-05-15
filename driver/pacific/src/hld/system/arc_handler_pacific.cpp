// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "arc_handler_pacific.h"
#include "lld/ll_device.h"
#include "lld/pacific_tree.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

arc_handler_pacific::arc_handler_pacific(const la_device_impl_wptr& device) : arc_handler_base(device)
{
}

arc_handler_pacific::~arc_handler_pacific()
{
}

lld_memory_sptr
arc_handler_pacific::get_mem_ptr()
{
    return m_device->m_pacific_tree->sbif->css_mem_even;
}
}
