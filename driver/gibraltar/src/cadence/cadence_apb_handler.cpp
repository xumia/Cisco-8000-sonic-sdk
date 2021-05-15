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

#include "cadence_apb_handler.h"

namespace silicon_one
{

cadence_apb_handler::cadence_apb_handler(apb* apb_pcie) : m_apb_pcie(apb_pcie)
{
    dassert_crit(apb_pcie->get_interface_type() == apb_interface_type_e::PCIE);
}

int
cadence_apb_handler::read(int address, int& out_val)
{
    bit_vector bv(0, 32);
    la_status rc = m_apb_pcie->read((uint32_t)apb::pcie_apb_select_e::PHY, address, bv);
    if (rc) {
        return -1;
    }

    out_val = (uint32_t)bv.get_value();
    return 0;
}

int
cadence_apb_handler::write(int address, int in_val)
{
    bit_vector bv(in_val, 32);
    la_status rc = m_apb_pcie->write((uint32_t)apb::pcie_apb_select_e::PHY, address, bv);

    return rc ? (int)rc.value() : 0;
}
}
