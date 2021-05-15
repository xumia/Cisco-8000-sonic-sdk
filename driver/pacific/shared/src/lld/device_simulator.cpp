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

#include "lld/device_simulator.h"

namespace silicon_one
{

void
device_simulator::set_pacific_tree(const pacific_tree* pt)
{
    m_pacific_tree = pt;
}

void
device_simulator::set_gibraltar_tree(const gibraltar_tree* gt)
{
    m_gibraltar_tree = gt;
}

void
device_simulator::set_asic3_tree(const asic3_tree* grt)
{
    m_asic3_tree = grt;
}

void
device_simulator::set_asic4_tree(const asic4_tree* pd)
{
    m_asic4_tree = pd;
}

void
device_simulator::set_asic5_tree(const asic5_tree* ar)
{
    m_asic5_tree = ar;
}

la_status
device_simulator::add_property(std::string key, std::string value)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

} // namespace silicon_one
